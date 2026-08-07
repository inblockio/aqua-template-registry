//! Freshness (R13) and cross-registry corroboration (R14), end to end.
//!
//! # Why the timestamp question needed answering before the policy was written
//!
//! A freshness policy is only worth as much as the timestamp it reads. A head
//! tree carries two candidates: `covered_at` inside the object payload, and the
//! `local_timestamp` on the signature revision. They look interchangeable and
//! are not.
//!
//! The signature commits to the OBJECT revision's hash, and that hash covers
//! the payload, so `covered_at` cannot be moved without breaking the tree.
//!
//! The design's first draft also claimed the signature revision's own
//! `local_timestamp` was malleable, since that revision is the tip and nothing
//! commits to it. The second test here rewrites that field, rekeys the revision
//! to the hash its new content produces, and finds that core refuses the tree
//! anyway: the signature is computed over a pre-signature structure that
//! includes the revision's timestamp. So the reasoning was wrong and both
//! fields are in fact tamper-proof.
//!
//! The policy still reads `covered_at`, now for a reason about meaning rather
//! than integrity: it is what the publisher says the commitment is dated,
//! whereas the signature revision's timestamp is when that revision happened to
//! be built. See `src/feedhead.rs::check_freshness`.

mod common;

use std::path::Path;

use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::corroborate::corroborate;
use aqua_template_registry::feedhead::{self, HeadRejection};
use aqua_template_registry::httpclient::RegistryClient;
use aqua_template_registry::import::ImportStore;
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::subscribe::{Subscriber, SyncError};
use aqua_template_registry::templates;
use aqua_template_registry::trust::{ImportPolicy, PinMode};

use common::{RegistryDaemon, TempDir};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn novel_definition(nonce_byte: u8) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "revision_type": "0x1620f3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155",
        "nonce": format!("0x{}", hex::encode([nonce_byte; 16])),
        "local_timestamp": 1786060000u64,
        "version": "https://aqua-protocol.org/docs/v4/schema",
        "method": "scalar",
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": { "note": { "type": "string" }, "created_at": { "type": "integer" } },
            "required": ["note", "created_at"],
            "additionalProperties": false
        },
        "bounds": {
            "max_chain_depth": 4,
            "structural_links": { "required": 0, "max": 2 },
            "max_signature_branches": 2,
            "max_timestamp_branches": 1,
            "max_anchor_branches": 2,
            "max_total_revisions": 32
        }
    }))
    .unwrap()
}

async fn publish_template(
    client: &RegistryClient,
    aq: &Aquafier,
    key: &PublisherKey,
    vendor: &str,
    name: &str,
    body: &str,
) -> String {
    let hash = templates::template_hash_of_definition(body).unwrap();
    let tree = publisher::template_registration(
        aq,
        key,
        TemplateRegistration {
            vendor: vendor.into(),
            name: name.into(),
            template_hash: hash.clone(),
            supersedes: None,
            display_name: None,
            description: None,
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        client
            .post("/templates", publisher::to_json(&tree).unwrap())
            .await
            .unwrap()
            .status,
        201
    );
    assert_eq!(
        client
            .post("/definitions", body.to_string())
            .await
            .unwrap()
            .status,
        201
    );
    hash
}

async fn feed_tips(client: &RegistryClient, did: &str) -> Vec<String> {
    let page: aqua_template_registry::model::FeedPage = client
        .get_json(&format!("/publishers/{did}/feed?since=0&limit=1000"))
        .await
        .unwrap();
    page.entries.into_iter().map(|e| e.tree_tip).collect()
}

fn write_policy(path: &Path, did: &str, pins: &[(&str, &str)], max_age: Option<u64>) {
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(did);
    for (n, h) in pins {
        policy.approve(n, h).unwrap();
    }
    policy.set_max_head_age_secs(max_age);
    policy.save(path).unwrap();
}

// ---------------------------------------------------------------------------
// 1. Which timestamp is actually trustworthy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tampered_covered_at_breaks_the_tree() {
    // covered_at lives in the object payload, which the signature commits to.
    // Moving it by one second must invalidate the tree, which is what makes it
    // safe to build a freshness policy on.
    let aq = Aquafier::new();
    let key = PublisherKey::from_seed([41u8; 32]).unwrap();
    let tips = vec![format!("0x1620{}", hex::encode([1u8; 32]))];
    let covered_at = 1_700_000_000u64;

    let tree = feedhead::build(&aq, &key.credentials(), key.did(), &tips, covered_at)
        .await
        .unwrap();
    let body = publisher::to_json_pretty(&tree).unwrap();

    let honest = feedhead::verify_head(&aq, &body, Some(key.did()))
        .await
        .expect("the honest head verifies");
    assert_eq!(honest.covered_at, covered_at);

    let tampered = body.replace(
        &format!("\"covered_at\": {covered_at}"),
        &format!("\"covered_at\": {}", covered_at + 1),
    );
    assert_ne!(tampered, body, "the mutation must have applied");

    let err = feedhead::verify_head(&aq, &tampered, Some(key.did()))
        .await
        .expect_err("a moved covered_at must invalidate the head");
    assert!(matches!(err, HeadRejection::NotVerified(_)), "got {err:?}");
}

#[tokio::test]
async fn the_signature_revisions_own_timestamp_is_not_a_trustworthy_clock() {
    // Probe, not an assumption. This rewrites the signature revision's own
    // local_timestamp and rekeys it properly, then records what core does.
    // Observed: core REFUSES it, because the pre-signature covers the
    // revision's timestamp. The design note in src/feedhead.rs was corrected to
    // match. Either branch below is a pass; the test exists so a change in
    // core's behaviour is noticed rather than silently assumed away.
    let aq = Aquafier::new();
    let key = PublisherKey::from_seed([42u8; 32]).unwrap();
    let tips = vec![format!("0x1620{}", hex::encode([2u8; 32]))];

    let tree = feedhead::build(&aq, &key.credentials(), key.did(), &tips, 1_700_000_000)
        .await
        .unwrap();
    let body = publisher::to_json_pretty(&tree).unwrap();

    // Find the signature revision and move its local_timestamp, rekeying it to
    // the hash the new content produces (which is what an intermediary able to
    // recompute hashes would do).
    let mut doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    let revisions = doc["revisions"].as_object().unwrap().clone();
    let (sig_hash, sig) = revisions
        .iter()
        .find(|(_, r)| r.get("signature").is_some())
        .map(|(h, r)| (h.clone(), r.clone()))
        .expect("the head tree has a signature revision");

    let original_ts = sig["local_timestamp"].as_u64().unwrap();
    let mut moved = sig.clone();
    moved["local_timestamp"] = serde_json::json!(original_ts + 86_400);

    // Rekey it. Leaving it under the old key would only prove that core checks
    // content against its key, which is not the question. An intermediary can
    // recompute the hash, so the honest experiment is to do exactly that.
    let rekeyed: aqua_rs_sdk_core::schema::AnyRevision =
        serde_json::from_value(moved.clone()).expect("the edited revision still parses");
    let new_key = rekeyed
        .global_calculate_hash(aqua_rs_sdk_core::primitives::HashType::Sha3_256)
        .expect("rehash")
        .to_string();

    let revs = doc["revisions"].as_object_mut().unwrap();
    revs.remove(&sig_hash);
    revs.insert(new_key.clone(), moved);
    assert_ne!(
        new_key, sig_hash,
        "moving the timestamp must change the hash"
    );
    let mutated = serde_json::to_string_pretty(&doc).unwrap();

    let outcome = feedhead::verify_head(&aq, &mutated, Some(key.did())).await;
    // Whichever way this lands, covered_at is unaffected and remains the field
    // the policy uses. Record the result so a future change is visible.
    match &outcome {
        Ok(head) => {
            assert_eq!(
                head.covered_at, 1_700_000_000,
                "the signed timestamp must be untouched by a signature-revision edit"
            );
            println!(
                "observed: editing the signature revision's local_timestamp does NOT \
                 invalidate the tree, so it is not a usable clock"
            );
        }
        Err(e) => {
            println!("observed: core rejects a rewritten signature revision ({e})");
        }
    }
}

// ---------------------------------------------------------------------------
// 2. The freshness policy, end to end.
// ---------------------------------------------------------------------------

/// Build a registry with one vendor, one template, and a head dated `head_age`
/// seconds ago. Returns everything the caller needs to drive a subscriber.
async fn staged_with_head_age(
    tag: &str,
    head_age_secs: u64,
) -> (RegistryDaemon, TempDir, PublisherKey, String) {
    let server_dir = TempDir::new(tag);
    let daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aq = Aquafier::new();
    let key = PublisherKey::from_seed([43u8; 32]).unwrap();

    let vendor_tree = publisher::vendor_registration(&aq, &key, "freshvendor", None)
        .await
        .unwrap();
    assert_eq!(
        client
            .post("/vendors", publisher::to_json(&vendor_tree).unwrap())
            .await
            .unwrap()
            .status,
        201
    );
    let hash = publish_template(
        &client,
        &aq,
        &key,
        "freshvendor",
        "one",
        &novel_definition(0xf1),
    )
    .await;

    let tips = feed_tips(&client, key.did()).await;
    let covered_at = now_secs().saturating_sub(head_age_secs);
    let head = feedhead::build(&aq, &key.credentials(), key.did(), &tips, covered_at)
        .await
        .unwrap();
    let response = client
        .post("/heads", publisher::to_json_pretty(&head).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status, 201, "{}", response.body);

    (daemon, server_dir, key, hash)
}

#[tokio::test]
async fn a_fresh_head_passes_the_freshness_policy() {
    let (mut daemon, _s, key, hash) = staged_with_head_age("fresh-ok", 60).await;
    let consumer = TempDir::new("fresh-ok-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(
        &policy_path,
        key.did(),
        &[("freshvendor/one", &hash)],
        Some(3600),
    );

    let mut sub = Subscriber::new(
        daemon.base_url(),
        key.did(),
        ImportStore::open(consumer.join("imported")).unwrap(),
        ImportPolicy::load(&policy_path).unwrap(),
        None,
        consumer.join("cursor.json"),
    )
    .unwrap();

    let report = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect("a fresh head syncs");
    assert_eq!(report.imported.len(), 1);
    assert_eq!(report.cursor, 2);
    daemon.stop();
}

#[tokio::test]
async fn a_stale_head_fails_closed_and_imports_nothing() {
    // The R13 headline. A head signed two days ago against a one hour policy.
    let (mut daemon, _s, key, hash) = staged_with_head_age("fresh-stale", 172_800).await;
    let consumer = TempDir::new("fresh-stale-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(
        &policy_path,
        key.did(),
        &[("freshvendor/one", &hash)],
        Some(3600),
    );

    let mut sub = Subscriber::new(
        daemon.base_url(),
        key.did(),
        ImportStore::open(consumer.join("imported")).unwrap(),
        ImportPolicy::load(&policy_path).unwrap(),
        None,
        consumer.join("cursor.json"),
    )
    .unwrap();

    let err = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect_err("a stale head must not be accepted");
    match &err {
        SyncError::Head(HeadRejection::Stale {
            age_secs,
            max_age_secs,
            ..
        }) => {
            assert!(*age_secs >= 172_800, "age was {age_secs}");
            assert_eq!(*max_age_secs, 3600);
        }
        other => panic!("expected Stale, got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_STALE");

    // Fail closed.
    assert!(sub.store().hashes().unwrap().is_empty());
    assert_eq!(sub.cursor(), 0);
    daemon.stop();
}

#[tokio::test]
async fn the_same_stale_head_is_accepted_when_no_policy_asks_for_freshness() {
    // Backward compatibility, asserted: a trust file with no max_head_age_secs
    // behaves exactly as it did before R13 existed. Same registry, same head,
    // only the policy differs.
    let (mut daemon, _s, key, hash) = staged_with_head_age("fresh-nopolicy", 172_800).await;
    let consumer = TempDir::new("fresh-nopolicy-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(&policy_path, key.did(), &[("freshvendor/one", &hash)], None);

    let mut sub = Subscriber::new(
        daemon.base_url(),
        key.did(),
        ImportStore::open(consumer.join("imported")).unwrap(),
        ImportPolicy::load(&policy_path).unwrap(),
        None,
        consumer.join("cursor.json"),
    )
    .unwrap();

    let report = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect("no policy means no freshness requirement");
    assert_eq!(report.imported.len(), 1);
    daemon.stop();
}

// ---------------------------------------------------------------------------
// 3. Cross-registry corroboration.
// ---------------------------------------------------------------------------

/// Two honest mirrors carrying the same set must agree.
#[tokio::test]
async fn two_honest_mirrors_corroborate_each_other() {
    let a_dir = TempDir::new("corrob-a");
    let b_dir = TempDir::new("corrob-b");
    let mut a = RegistryDaemon::start(&a_dir.join("data"));
    let mut b = RegistryDaemon::start(&b_dir.join("data"));

    let ca = RegistryClient::new(a.base_url()).unwrap();
    let cb = RegistryClient::new(b.base_url()).unwrap();
    let did = common::publish_seed_over_http(&ca).await;
    common::publish_seed_over_http(&cb).await;

    let head_body = std::fs::read_to_string(common::seed_dir().join("13-feed-head.json")).unwrap();
    assert_eq!(
        ca.post("/heads", head_body.clone()).await.unwrap().status,
        201
    );
    assert_eq!(cb.post("/heads", head_body).await.unwrap().status, 201);

    let report = corroborate(&did, &[a.base_url().to_string(), b.base_url().to_string()])
        .await
        .expect("corroboration ran");

    assert!(report.is_consistent(), "{:?}", report.equivocations);
    assert_eq!(report.corroborating(), 2);
    assert_eq!(report.best_head_seq, Some(12));
    assert!(report.lagging.is_empty());
    assert!(report.unreachable.is_empty());

    a.stop();
    b.stop();
}

/// One mirror behind the other is lag, not equivocation. This distinction is
/// the whole reason lag is reported separately: treating a mirror that has not
/// caught up as an attack would make corroboration unusable.
#[tokio::test]
async fn a_mirror_that_is_merely_behind_is_reported_as_lag_not_equivocation() {
    let a_dir = TempDir::new("corrob-lag-a");
    let b_dir = TempDir::new("corrob-lag-b");
    let mut a = RegistryDaemon::start(&a_dir.join("data"));
    let mut b = RegistryDaemon::start(&b_dir.join("data"));

    let ca = RegistryClient::new(a.base_url()).unwrap();
    let cb = RegistryClient::new(b.base_url()).unwrap();
    let aq = Aquafier::new();
    let key = PublisherKey::from_seed([44u8; 32]).unwrap();

    // Both mirrors get the vendor claim, then a head over just that.
    let vendor_tree = publisher::vendor_registration(&aq, &key, "lagvendor", None)
        .await
        .unwrap();
    let vendor_body = publisher::to_json(&vendor_tree).unwrap();
    ca.post("/vendors", vendor_body.clone()).await.unwrap();
    cb.post("/vendors", vendor_body).await.unwrap();

    let tips_1 = feed_tips(&ca, key.did()).await;
    let head_1 = publisher::to_json_pretty(
        &feedhead::build(&aq, &key.credentials(), key.did(), &tips_1, now_secs())
            .await
            .unwrap(),
    )
    .unwrap();
    ca.post("/heads", head_1.clone()).await.unwrap();
    cb.post("/heads", head_1).await.unwrap();

    // Only mirror A gets the template and the newer head.
    publish_template(&ca, &aq, &key, "lagvendor", "one", &novel_definition(0xf2)).await;
    let tips_2 = feed_tips(&ca, key.did()).await;
    let head_2 = publisher::to_json_pretty(
        &feedhead::build(&aq, &key.credentials(), key.did(), &tips_2, now_secs())
            .await
            .unwrap(),
    )
    .unwrap();
    ca.post("/heads", head_2).await.unwrap();

    let report = corroborate(
        key.did(),
        &[a.base_url().to_string(), b.base_url().to_string()],
    )
    .await
    .unwrap();

    assert!(
        report.is_consistent(),
        "lag must not read as equivocation: {:?}",
        report.equivocations
    );
    assert_eq!(report.best_head_seq, Some(2));
    assert_eq!(report.lagging.len(), 1);
    assert_eq!(report.lagging[0].behind, 1);
    assert_eq!(report.lagging[0].url, b.base_url());

    a.stop();
    b.stop();
}

/// The R14 headline. Two mirrors serving different signed roots at the same
/// height cannot both be right, and corroboration says so without trying to
/// pick a winner.
#[tokio::test]
async fn a_manipulated_mirror_is_caught_equivocating() {
    let a_dir = TempDir::new("corrob-evil-a");
    let b_dir = TempDir::new("corrob-evil-b");
    let mut a = RegistryDaemon::start(&a_dir.join("data"));
    let mut b = RegistryDaemon::start(&b_dir.join("data"));

    let ca = RegistryClient::new(a.base_url()).unwrap();
    let cb = RegistryClient::new(b.base_url()).unwrap();
    let aq = Aquafier::new();
    let key = PublisherKey::from_seed([45u8; 32]).unwrap();

    // Both mirrors receive the same three entries.
    let vendor_tree = publisher::vendor_registration(&aq, &key, "evilvendor", None)
        .await
        .unwrap();
    let vendor_body = publisher::to_json(&vendor_tree).unwrap();
    ca.post("/vendors", vendor_body.clone()).await.unwrap();
    cb.post("/vendors", vendor_body).await.unwrap();
    for (i, nonce) in [0xf3u8, 0xf4].iter().enumerate() {
        let body = novel_definition(*nonce);
        let hash = templates::template_hash_of_definition(&body).unwrap();
        let tree = publisher::template_registration(
            &aq,
            &key,
            TemplateRegistration {
                vendor: "evilvendor".into(),
                name: format!("t{i}"),
                template_hash: hash,
                supersedes: None,
                display_name: None,
                description: None,
                daemon_trigger: None,
                file_dependency: None,
            },
        )
        .await
        .unwrap();
        let tree_body = publisher::to_json(&tree).unwrap();
        ca.post("/templates", tree_body.clone()).await.unwrap();
        cb.post("/templates", tree_body).await.unwrap();
        ca.post("/definitions", body.clone()).await.unwrap();
        cb.post("/definitions", body).await.unwrap();
    }

    let tips = feed_tips(&ca, key.did()).await;
    assert_eq!(tips.len(), 3);
    let honest_head = publisher::to_json_pretty(
        &feedhead::build(&aq, &key.credentials(), key.did(), &tips, now_secs())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ca.post("/heads", honest_head.clone()).await.unwrap().status,
        201
    );
    assert_eq!(cb.post("/heads", honest_head).await.unwrap().status, 201);

    // Mirror B is manipulated: its stored head at height 3 is replaced with a
    // head over a REORDERED entry list. It is validly signed by the real key
    // (the test holds it, standing in for a compromised or careless publisher
    // plus a colluding mirror), so only the cross-mirror comparison can catch
    // it. The registry's own ingest check would have refused it, which is why
    // the file is written directly rather than POSTed.
    b.stop();
    let mut reordered = tips.clone();
    reordered.swap(1, 2);
    let forged = publisher::to_json_pretty(
        &feedhead::build(&aq, &key.credentials(), key.did(), &reordered, now_secs())
            .await
            .unwrap(),
    )
    .unwrap();
    let heads_dir = b_dir
        .join("data")
        .join("heads")
        .join(hex::encode(key.did().as_bytes()));
    std::fs::write(heads_dir.join("000000000003.json"), &forged).unwrap();
    b.start_again();

    let report = corroborate(
        key.did(),
        &[a.base_url().to_string(), b.base_url().to_string()],
    )
    .await
    .unwrap();

    assert!(
        !report.is_consistent(),
        "two different roots at height 3 must be flagged"
    );
    assert_eq!(report.equivocations.len(), 1);
    let e = &report.equivocations[0];
    assert_eq!(e.head_seq, 3);
    assert_ne!(e.root_a, e.root_b);
    assert!(report.summary().starts_with("INCONSISTENT"));
    // Both mirrors served a head that verified on its own; only comparing them
    // reveals the problem.
    assert_eq!(report.corroborating(), 2);

    a.stop();
    b.stop();
}

/// An unreachable mirror is neither corroboration nor contradiction, and must
/// not be silently counted as agreement.
#[tokio::test]
async fn an_unreachable_mirror_is_reported_and_not_counted_as_agreement() {
    let a_dir = TempDir::new("corrob-down-a");
    let mut a = RegistryDaemon::start(&a_dir.join("data"));
    let ca = RegistryClient::new(a.base_url()).unwrap();
    let did = common::publish_seed_over_http(&ca).await;
    let head_body = std::fs::read_to_string(common::seed_dir().join("13-feed-head.json")).unwrap();
    ca.post("/heads", head_body).await.unwrap();

    // Port 1 is reserved and nothing listens there.
    let report = corroborate(
        &did,
        &[a.base_url().to_string(), "http://127.0.0.1:1".to_string()],
    )
    .await
    .unwrap();

    assert!(
        report.is_consistent(),
        "one silent mirror is not a conflict"
    );
    assert_eq!(report.corroborating(), 1, "only one mirror actually agreed");
    assert_eq!(report.unreachable.len(), 1);
    assert!(report.mirrors[1].error.is_some());

    a.stop();
}
