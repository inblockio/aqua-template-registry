//! Write-path concurrency tests (backlog item R7).
//!
//! `Registry::submit` (src/registry.rs) verifies a submitted tree's
//! cryptography OUTSIDE the write lock, then takes the write lock and runs
//! `check_trust`, the sequence-number assignment, the durable store append,
//! and the index update (`apply`) all INSIDE it, as one critical section.
//! That section is exactly the window a race would need to exploit to get
//! two submissions accepted for the same name, hash, or vendor claim. These
//! tests drive real concurrent submissions at that window, several rounds
//! each, and check that exactly one side of every race wins, that the loser
//! gets a well-formed conflict error with the right HTTP status, and that
//! the store stays internally consistent (and re-openable) afterward.
//!
//! Every submission that can race here is a real signed Aqua tree, built
//! through `aqua-rs-sdk-core`, the same way tests/e2e.rs builds them. The
//! only thing under test is what happens when two already-built,
//! already-signed submissions are handed to the registry at the same time.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use aqua_template_registry::error::RegistryError;
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::Registry;

// ---------------------------------------------------------------------------
// helpers (mirrors the local-TempDir pattern in tests/e2e.rs; deliberately
// not shared through tests/common, so this file stays self-contained)
// ---------------------------------------------------------------------------

/// A unique temporary directory that removes itself on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aqua-template-registry-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A distinct 0x-prefixed 32-byte hash for a given `n`, so many rounds and
/// many tasks within a round never accidentally collide on one hash.
fn hash_of(n: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    format!("0x{}", hex::encode(bytes))
}

fn template_reg(vendor: &str, name: &str, hash: &str) -> TemplateRegistration {
    TemplateRegistration {
        vendor: vendor.into(),
        name: name.into(),
        template_hash: hash.into(),
        supersedes: None,
        display_name: None,
        description: None,
        daemon_trigger: None,
        file_dependency: None,
    }
}

/// Register a vendor namespace, sequentially and outside of any race, and
/// return the registry receipt's tree tip.
async fn claim(reg: &Registry, key: &PublisherKey, vendor: &str) -> String {
    let tree = publisher::vendor_registration(reg.aquafier(), key, vendor, None)
        .await
        .expect("build vendor registration");
    let body = publisher::to_json(&tree).expect("serialize");
    reg.submit_vendor(&body)
        .await
        .expect("submit vendor")
        .tree_tip
}

/// Rounds to run each race for. Five is the minimum asked for. Running more
/// than one round matters because which side of a race wins is genuinely
/// nondeterministic, and a bug that only shows up when the "wrong" side wins
/// could otherwise pass on a lucky single run.
const ROUNDS: u32 = 5;

// ---------------------------------------------------------------------------
// 1. Two submissions racing the same template hash.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_the_same_template_hash_admits_exactly_one() {
    // Pins the core write-path invariant: check_trust's DuplicateTemplate
    // check reads index.templates, and apply writes it, both inside the one
    // write-lock critical section that submit holds from check_trust through
    // apply. If that lock did not fully serialize submissions, two tasks
    // could both observe "not present yet" and both get accepted, leaving
    // two feed entries that claim the same template hash. multi_thread with
    // worker_threads greater than one is required here: on the current
    // thread flavor the two tasks would just take turns at await points on
    // one OS thread and never actually contend for the RwLock from two
    // threads at once, so the test would prove nothing about real
    // concurrency.
    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-hash-{round}"));
        let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
        let key = PublisherKey::generate().expect("generate key");

        let vendor = format!("racehash{round}");
        claim(&registry, &key, &vendor).await;

        let name = "widget";
        let hash = hash_of(1_000 + round as u64);

        // Build both signed trees up front: the race is over submit_template,
        // not over tree construction.
        let tree_a = publisher::template_registration(
            registry.aquafier(),
            &key,
            template_reg(&vendor, name, &hash),
        )
        .await
        .expect("build tree a");
        let tree_b = publisher::template_registration(
            registry.aquafier(),
            &key,
            template_reg(&vendor, name, &hash),
        )
        .await
        .expect("build tree b");
        let body_a = publisher::to_json(&tree_a).expect("serialize a");
        let body_b = publisher::to_json(&tree_b).expect("serialize b");

        let r1 = registry.clone();
        let r2 = registry.clone();
        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { r1.submit_template(&body_a).await }),
            tokio::spawn(async move { r2.submit_template(&body_b).await }),
        );
        // Count outcomes explicitly. Which task wins is genuinely
        // nondeterministic and this test must not depend on it.
        let results = vec![res_a.expect("task a joined"), res_b.expect("task b joined")];

        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(
            ok_count, 1,
            "round {round}: exactly one racing submission must be accepted"
        );
        assert_eq!(
            err_count, 1,
            "round {round}: exactly one racing submission must be refused"
        );

        let err = results
            .into_iter()
            .find(|r| r.is_err())
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DuplicateTemplate(_)),
            "round {round}: got {err:?}"
        );
        assert_eq!(
            err.status(),
            409,
            "round {round}: DuplicateTemplate must report a 409"
        );

        let stats = registry.stats();
        assert_eq!(
            stats.templates, 1,
            "round {round}: exactly one template hash stuck"
        );
        assert_eq!(
            stats.head_seq, 2,
            "round {round}: 1 vendor claim plus 1 accepted template; the loser never consumes a seq"
        );

        let resolved = registry.resolve(&vendor, name).expect("resolve");
        assert_eq!(resolved.template_hash, hash, "round {round}");

        assert_eq!(
            registry.publisher_templates(key.did()).len(),
            1,
            "round {round}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Two submissions racing the same alias name.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_the_same_alias_name_admits_exactly_one() {
    // Same invariant as the template race above, but exercised through
    // submit_alias's own DuplicateAlias check, which reads and writes
    // index.aliases rather than index.templates. Worth its own test because
    // the template and alias branches of check_trust/apply touch different
    // maps: a bug isolated to one would not necessarily show up in the other.
    // multi_thread + worker_threads for the same reason as test 1: real
    // cross-thread contention on the RwLock, not cooperative interleaving.
    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-alias-{round}"));
        let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
        let key = PublisherKey::generate().expect("generate key");

        let vendor = format!("racealias{round}");
        claim(&registry, &key, &vendor).await;

        let alias_name = "shortcut";
        let target = hash_of(2_000 + round as u64);

        // Built up front for the same reason as test 1: the race is over
        // submit_alias, not over tree construction. The target hash need not
        // resolve to a registered template; check_trust's alias branch never
        // checks that.
        let tree_a =
            publisher::alias_registration(registry.aquafier(), &key, &vendor, alias_name, &target)
                .await
                .expect("build alias a");
        let tree_b =
            publisher::alias_registration(registry.aquafier(), &key, &vendor, alias_name, &target)
                .await
                .expect("build alias b");
        let body_a = publisher::to_json(&tree_a).expect("serialize a");
        let body_b = publisher::to_json(&tree_b).expect("serialize b");

        let r1 = registry.clone();
        let r2 = registry.clone();
        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { r1.submit_alias(&body_a).await }),
            tokio::spawn(async move { r2.submit_alias(&body_b).await }),
        );
        let results = vec![res_a.expect("task a joined"), res_b.expect("task b joined")];

        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "round {round}: exactly one racing alias submission must be accepted"
        );
        assert_eq!(
            results.iter().filter(|r| r.is_err()).count(),
            1,
            "round {round}: exactly one racing alias submission must be refused"
        );

        let err = results
            .into_iter()
            .find(|r| r.is_err())
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::DuplicateAlias(_)),
            "round {round}: got {err:?}"
        );
        assert_eq!(
            err.status(),
            409,
            "round {round}: DuplicateAlias must report a 409"
        );

        assert_eq!(
            registry.stats().aliases,
            1,
            "round {round}: exactly one alias stuck"
        );

        let resolved = registry
            .resolve(&vendor, alias_name)
            .expect("resolve alias");
        assert_eq!(resolved.template_hash, target, "round {round}");
    }
}

// ---------------------------------------------------------------------------
// 3. Two different keys racing to claim the same vendor name.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_two_vendor_claims_for_one_name_admits_exactly_one() {
    // Vendor names are first-come-first-served (check_trust's Rule 2). Two
    // different keys racing the same name must not both land. Because
    // check_trust and apply share the one write-lock critical section, the
    // loser's check_trust always runs against an index that already has the
    // winner's record (never a stale or empty index.vendors entry), so the
    // loser's VendorNameTaken always names the DID that actually won, not
    // some earlier or default value.
    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-vendor-{round}"));
        let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
        let alice = PublisherKey::generate().expect("generate alice");
        let mallory = PublisherKey::generate().expect("generate mallory");

        let vendor = format!("contested{round}");

        // Built up front: the race is over submit_vendor, not over tree
        // construction. Both are legitimately self-certifying (each names its
        // own signer as vendor_did), so the only rule left to decide this is
        // "first come, first served".
        let tree_a = publisher::vendor_registration(registry.aquafier(), &alice, &vendor, None)
            .await
            .expect("build alice's claim");
        let tree_b = publisher::vendor_registration(registry.aquafier(), &mallory, &vendor, None)
            .await
            .expect("build mallory's claim");
        let body_a = publisher::to_json(&tree_a).expect("serialize a");
        let body_b = publisher::to_json(&tree_b).expect("serialize b");

        let r1 = registry.clone();
        let r2 = registry.clone();
        let (res_a, res_b) = tokio::join!(
            tokio::spawn(async move { r1.submit_vendor(&body_a).await }),
            tokio::spawn(async move { r2.submit_vendor(&body_b).await }),
        );
        let results = vec![res_a.expect("task a joined"), res_b.expect("task b joined")];

        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "round {round}: exactly one of the two vendor claims must be accepted"
        );
        assert_eq!(
            results.iter().filter(|r| r.is_err()).count(),
            1,
            "round {round}: exactly one of the two vendor claims must be refused"
        );

        // Which key won is genuinely nondeterministic. Read back whichever
        // DID actually landed, without assuming which one that is.
        let winner_did = results
            .iter()
            .find_map(|r| r.as_ref().ok().map(|receipt| receipt.publisher_did.clone()))
            .expect("one submission was accepted");
        assert!(
            winner_did == alice.did() || winner_did == mallory.did(),
            "round {round}: winner must be one of the two racers"
        );

        let err = results
            .into_iter()
            .find(|r| r.is_err())
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::VendorNameTaken { .. }),
            "round {round}: got {err:?}"
        );
        assert_eq!(
            err.status(),
            403,
            "round {round}: VendorNameTaken must report a 403"
        );

        // The surviving record agrees with the winner's own receipt, and
        // there is exactly one vendor namespace on the books.
        let record = registry.vendor(&vendor).expect("vendor record");
        assert_eq!(record.vendor_did, winner_did, "round {round}");
        assert_eq!(registry.stats().vendors, 1, "round {round}");
    }
}

// ---------------------------------------------------------------------------
// 4. A template and an alias racing for the same qualified name.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_a_template_and_an_alias_for_the_same_name_admits_exactly_one() {
    // A qualified name can be a template or an alias, never both. Reasoning
    // through check_trust for the two possible lock-acquisition orders:
    //
    //   * The template applies first. It inserts the qualified name into
    //     by_qualified. The alias's check_trust then finds index.aliases
    //     still empty for this name (DuplicateAlias cannot fire; nobody else
    //     ever registers this exact alias in this round), but
    //     index.by_qualified.contains_key(qualified) is now true, so the
    //     alias loses with NameCollision.
    //   * The alias applies first. It inserts the qualified name into
    //     aliases. The template's check_trust then finds index.templates
    //     still missing this hash (DuplicateTemplate cannot fire; the hash
    //     is fresh this round), but index.aliases.contains_key(qualified) is
    //     now true, so the template loses with NameCollision.
    //
    // Both orderings produce the SAME variant on the loser: NameCollision.
    // DuplicateTemplate and DuplicateAlias guard against a second write of
    // the same kind, and this test only ever submits one of each kind, so
    // neither of those checks can be what actually fires here. That is why
    // this test asserts NameCollision precisely, rather than accepting a set
    // of variants.
    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-collision-{round}"));
        let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
        let key = PublisherKey::generate().expect("generate key");

        let vendor = format!("collide{round}");
        claim(&registry, &key, &vendor).await;

        let name = "thing";
        let hash = hash_of(3_000 + round as u64);

        let template_tree = publisher::template_registration(
            registry.aquafier(),
            &key,
            template_reg(&vendor, name, &hash),
        )
        .await
        .expect("build template");
        let alias_tree =
            publisher::alias_registration(registry.aquafier(), &key, &vendor, name, &hash)
                .await
                .expect("build alias");
        let template_body = publisher::to_json(&template_tree).expect("serialize template");
        let alias_body = publisher::to_json(&alias_tree).expect("serialize alias");

        let r1 = registry.clone();
        let r2 = registry.clone();
        let (res_t, res_a) = tokio::join!(
            tokio::spawn(async move { r1.submit_template(&template_body).await }),
            tokio::spawn(async move { r2.submit_alias(&alias_body).await }),
        );
        let results = vec![
            res_t.expect("template task joined"),
            res_a.expect("alias task joined"),
        ];

        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "round {round}: exactly one of template/alias must win the name"
        );
        assert_eq!(
            results.iter().filter(|r| r.is_err()).count(),
            1,
            "round {round}: exactly one of template/alias must lose"
        );

        let err = results
            .into_iter()
            .find(|r| r.is_err())
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(err, RegistryError::NameCollision(_)),
            "round {round}: got {err:?}"
        );
        assert_eq!(
            err.status(),
            409,
            "round {round}: NameCollision must report a 409"
        );

        // Exactly one of the two indexes ends up holding the name: never
        // both, never neither.
        let stats = registry.stats();
        assert_eq!(
            stats.templates + stats.aliases,
            1,
            "round {round}: exactly one of template/alias index holds the name"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Many disjoint concurrent submissions must all succeed with a dense,
//    ordered sequence.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_feed_stays_dense_and_ordered_under_concurrent_writes() {
    // Sequence numbers are handed out inside the very same write-lock
    // critical section that appends to the store and updates the index:
    // submit's `seq = index.head_seq + 1` through apply's
    // `index.head_seq = seq`. If that were not fully atomic across
    // concurrent submissions, two tasks could compute the same seq (a
    // collision that silently overwrites one entry with another) or leave a
    // gap (an entry that the next replay cannot explain). Either failure
    // would make the on-disk feed look corrupt, which is exactly what
    // apply's own seq check (`if seq != index.head_seq + 1`) exists to catch,
    // both at submit time and at replay time via Registry::open.
    const N: u64 = 8;

    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-dense-{round}"));
        let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
        let key = PublisherKey::generate().expect("generate key");

        let vendor = format!("dense{round}");
        claim(&registry, &key, &vendor).await;
        let base = registry.stats().head_seq; // 1, right after the vendor claim.

        // Distinct names and distinct hashes: nothing here should conflict
        // with anything else, so all N submissions are expected to succeed.
        let mut bodies = Vec::new();
        for i in 0..N {
            let tree = publisher::template_registration(
                registry.aquafier(),
                &key,
                template_reg(
                    &vendor,
                    &format!("item{i}"),
                    &hash_of(4_000 + round as u64 * 100 + i),
                ),
            )
            .await
            .expect("build");
            bodies.push(publisher::to_json(&tree).expect("serialize"));
        }

        let mut handles = Vec::new();
        for body in bodies {
            let r = registry.clone();
            handles.push(tokio::spawn(async move { r.submit_template(&body).await }));
        }

        let mut seqs: Vec<u64> = Vec::new();
        for handle in handles {
            let receipt = handle
                .await
                .expect("task joined")
                .expect("every disjoint submission must be accepted");
            seqs.push(receipt.seq);
        }

        seqs.sort_unstable();
        let expected: Vec<u64> = (base + 1..=base + N).collect();
        assert_eq!(
            seqs, expected,
            "round {round}: seqs must be exactly the contiguous range, with no gaps and no duplicates"
        );

        assert_eq!(
            registry.stats().head_seq,
            base + N,
            "round {round}: head_seq must land on the last handed-out seq"
        );

        let page = registry.feed(key.did(), 0, None);
        let feed_seqs: Vec<u64> = page.entries.iter().map(|e| e.seq).collect();
        assert!(
            feed_seqs.windows(2).all(|w| w[0] < w[1]),
            "round {round}: the feed must be strictly ascending, got {feed_seqs:?}"
        );
        assert_eq!(
            feed_seqs.len(),
            (base + N) as usize,
            "round {round}: the feed must contain the vendor claim plus all N templates"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. A reopened store must agree with what a race left behind.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reopened_store_agrees_with_what_the_race_left_behind() {
    // Registry::open replays the persisted feed through the same apply used
    // at submit time, and turns any replay conflict into CorruptStore rather
    // than silently dropping a registration (see registry.rs's Registry::open
    // doc comment). If a race ever left the on-disk feed inconsistent with
    // what the in-memory index had accepted, for example a store append that
    // landed without the matching index update, or vice versa, reopening
    // would either fail outright or replay into a different head_seq,
    // template count, or resolution than the original run had. So this test
    // is a real end-to-end check on the race's durable side effects, not a
    // formality.
    for round in 0..ROUNDS {
        let dir = TempDir::new(&format!("race-reopen-{round}"));
        let key = PublisherKey::generate().expect("generate key");
        let vendor = format!("reopen{round}");
        let name = "widget";
        let hash = hash_of(5_000 + round as u64);

        let (head_seq_before, templates_before, resolved_before) = {
            let registry = Arc::new(Registry::open(dir.path()).expect("open registry"));
            claim(&registry, &key, &vendor).await;

            let tree_a = publisher::template_registration(
                registry.aquafier(),
                &key,
                template_reg(&vendor, name, &hash),
            )
            .await
            .expect("build a");
            let tree_b = publisher::template_registration(
                registry.aquafier(),
                &key,
                template_reg(&vendor, name, &hash),
            )
            .await
            .expect("build b");
            let body_a = publisher::to_json(&tree_a).expect("serialize a");
            let body_b = publisher::to_json(&tree_b).expect("serialize b");

            let r1 = registry.clone();
            let r2 = registry.clone();
            let (res_a, res_b) = tokio::join!(
                tokio::spawn(async move { r1.submit_template(&body_a).await }),
                tokio::spawn(async move { r2.submit_template(&body_b).await }),
            );
            let results = [res_a.expect("task a joined"), res_b.expect("task b joined")];
            assert_eq!(
                results.iter().filter(|r| r.is_ok()).count(),
                1,
                "round {round}: exactly one racing submission must be accepted before reopening"
            );

            let stats = registry.stats();
            let resolved = registry
                .resolve(&vendor, name)
                .expect("resolve before reopening")
                .template_hash;
            (stats.head_seq, stats.templates, resolved)
            // The Arc<Registry>, and the Store underneath it, drop here.
        };

        // Reopen from the same directory: a fresh in-memory index rebuilt
        // purely by replaying entries/ from disk.
        let reopened =
            Registry::open(dir.path()).expect("reopening must not surface a CorruptStore");
        let stats = reopened.stats();
        assert_eq!(
            stats.head_seq, head_seq_before,
            "round {round}: head_seq must survive a reopen"
        );
        assert_eq!(
            stats.templates, templates_before,
            "round {round}: template count must survive a reopen"
        );
        let resolved_after = reopened
            .resolve(&vendor, name)
            .expect("resolve after reopening")
            .template_hash;
        assert_eq!(
            resolved_after, resolved_before,
            "round {round}: resolution must be identical before and after a reopen"
        );
    }
}
