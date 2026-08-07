//! Replay `seed/audit-set-v1` into a fresh registry.
//!
//! The seed set is the registry's first published template set, and it is
//! committed as data rather than regenerated: the signed trees carry nonces and
//! timestamps, so re-running the publisher would produce different bytes with
//! the same meaning. Committing them means these tests exercise the exact bytes
//! a consumer will fetch.
//!
//! What is actually being asserted, in order of how much it would hurt to get
//! wrong:
//!
//! 1. Every one of the twelve registrations still verifies cryptographically
//!    through `aqua-rs-sdk-core`. `Registry::submit_*` refuses anything that
//!    does not, so acceptance is the assertion.
//! 2. Each `template_hash` in the seed equals the hash recomputed from the
//!    matching definition JSON in the same seed. This is the drift guard: a
//!    seed whose registration points at a hash its own definition does not
//!    produce is publishing a name for a type nobody can resolve.
//! 3. Names resolve, the publisher-DID reverse index is complete, and the feed
//!    replays in order.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::model::RegistrationKind;
use aqua_template_registry::{templates, Registry};

/// The eleven audit templates, in the order the seed registers them: the
/// abstract root first, then T1 to T8 in turn order, then the closing types.
const EXPECTED_NAMES: [&str; 11] = [
    "audit_artifact",
    "audit_user_turn_marker",
    "audit_user_prompt",
    "audit_agent_thinking",
    "audit_agent_tool_call",
    "audit_api_response",
    "audit_tool_result",
    "audit_hitl_approval",
    "audit_agent_response",
    "audit_round_anchor",
    "audit_session_close",
];

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
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("seed/audit-set-v1")
}

fn manifest() -> serde_json::Value {
    let path = seed_dir().join("manifest.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("manifest.json parses")
}

fn registrations(m: &serde_json::Value) -> Vec<serde_json::Value> {
    m["registrations"]
        .as_array()
        .expect("manifest has registrations")
        .clone()
}

/// Replay the whole seed into a fresh store and hand back the registry.
async fn replay(dir: &Path) -> (Registry, serde_json::Value) {
    let m = manifest();
    let registry = Registry::open(dir).expect("open registry");

    for entry in registrations(&m) {
        let file = entry["tree_file"].as_str().expect("tree_file");
        let body = std::fs::read_to_string(seed_dir().join(file))
            .unwrap_or_else(|e| panic!("cannot read seed tree {file}: {e}"));

        let receipt = match entry["kind"].as_str().expect("kind") {
            "vendor" => registry
                .submit_vendor(&body)
                .await
                .unwrap_or_else(|e| panic!("{file} rejected: {e}")),
            "template" => registry
                .submit_template(&body)
                .await
                .unwrap_or_else(|e| panic!("{file} rejected: {e}")),
            other => panic!("unexpected kind {other:?} in the manifest"),
        };

        // Sequence numbers are assigned by the registry, so this also asserts
        // the manifest's recorded order is the order the seed replays in.
        assert_eq!(
            receipt.seq,
            entry["seq"].as_u64().expect("seq"),
            "{file} replayed at the wrong sequence number"
        );
        assert_eq!(
            receipt.tree_tip,
            entry["tree_tip"].as_str().expect("tree_tip"),
            "{file} tip hash differs from the manifest"
        );
    }

    (registry, m)
}

// ---------------------------------------------------------------------------
// 1. The whole set replays, and every tree still verifies.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn seed_set_replays_into_a_fresh_registry() {
    let dir = TempDir::new("audit-replay");
    let (registry, m) = replay(dir.path()).await;

    let did = m["publisher_did"].as_str().expect("publisher_did");
    assert!(
        did.starts_with("did:key:z6Mk"),
        "publisher DID is a did:key"
    );

    let stats = registry.stats();
    assert_eq!(stats.head_seq, 12, "one vendor plus eleven templates");
    assert_eq!(stats.vendors, 1);
    assert_eq!(stats.templates, 11);
    assert_eq!(stats.aliases, 0);
    assert_eq!(stats.publishers, 1, "the whole set has one publisher");

    // The vendor namespace is owned by the publisher named in the manifest.
    let vendor = registry.vendor("inblockio").expect("vendor is registered");
    assert_eq!(vendor.vendor_did, did);
    assert_eq!(vendor.seq, 1);
}

// ---------------------------------------------------------------------------
// 2. Drift guard: seed hashes match the seed's own definitions.
// ---------------------------------------------------------------------------

/// Recompute every registered hash from the definition JSON shipped alongside
/// it, using core's `calculate_link`. This is the check that would catch a seed
/// regenerated against one version of a template while shipping another.
#[tokio::test]
async fn every_seed_hash_matches_its_definition() {
    let dir = TempDir::new("audit-drift");
    let (registry, m) = replay(dir.path()).await;

    let mut checked = 0;
    for entry in registrations(&m) {
        if entry["kind"] != "template" {
            continue;
        }
        let name = entry["name"].as_str().expect("name");
        let declared = entry["template_hash"].as_str().expect("template_hash");

        let def_path = seed_dir().join(entry["definition_file"].as_str().expect("definition_file"));
        let definition = std::fs::read_to_string(&def_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", def_path.display()));

        let recomputed = templates::template_hash_of_definition(&definition)
            .unwrap_or_else(|e| panic!("{name} definition does not hash: {e}"));

        assert_eq!(
            recomputed, declared,
            "{name}: the seed registers {declared} but its own definition hashes to {recomputed}"
        );

        // And the registry agrees, having indexed the registration itself.
        let resolved = registry
            .resolve("inblockio", name)
            .unwrap_or_else(|e| panic!("{name} does not resolve: {e}"));
        assert_eq!(
            resolved.template_hash, recomputed,
            "{name} resolves to a hash its definition does not produce"
        );

        checked += 1;
    }
    assert_eq!(checked, 11, "all eleven templates must be drift checked");
}

// ---------------------------------------------------------------------------
// 3. Lookups: names, the publisher-DID reverse index, and the feed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lookups_resolve_the_whole_audit_family() {
    let dir = TempDir::new("audit-lookup");
    let (registry, m) = replay(dir.path()).await;
    let did = m["publisher_did"]
        .as_str()
        .expect("publisher_did")
        .to_string();

    // Manifest name to hash, for cross-checking every lookup below.
    let expected: BTreeMap<String, String> = registrations(&m)
        .iter()
        .filter(|e| e["kind"] == "template")
        .map(|e| {
            (
                e["name"].as_str().unwrap().to_string(),
                e["template_hash"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(expected.len(), 11);

    // ---- resolve by qualified name -----------------------------------------
    for name in EXPECTED_NAMES {
        let hit = registry
            .resolve("inblockio", name)
            .unwrap_or_else(|e| panic!("inblockio/{name} does not resolve: {e}"));
        assert_eq!(
            &hit.template_hash, &expected[name],
            "inblockio/{name} resolved to the wrong hash"
        );
        assert_eq!(hit.qualified_name, format!("inblockio/{name}"));
        assert_eq!(hit.publisher_did.as_deref(), Some(did.as_str()));
        // Nothing in v1 supersedes anything, so each lineage is a single entry.
        assert_eq!(hit.lineage, vec![expected[name].clone()]);
    }

    // A spot check with the exact name from the task, spelled out.
    assert_eq!(
        registry
            .resolve("inblockio", "audit_user_turn_marker")
            .unwrap()
            .template_hash,
        expected["audit_user_turn_marker"]
    );

    // Latin case folding still applies to the qualified name.
    assert_eq!(
        registry
            .resolve("InBlockIO", "AUDIT_SESSION_CLOSE")
            .unwrap()
            .template_hash,
        expected["audit_session_close"]
    );

    // A name that is not in the set does not resolve.
    assert!(registry.resolve("inblockio", "audit_nonexistent").is_err());

    // ---- the publisher-DID reverse index -----------------------------------
    let listed = registry.publisher_templates(&did);
    assert_eq!(listed.len(), 11, "the reverse index lists the whole set");

    let listed_names: BTreeMap<String, String> = listed
        .iter()
        .map(|t| (t.name.clone(), t.template_hash.clone()))
        .collect();
    assert_eq!(
        listed_names, expected,
        "reverse index differs from the manifest"
    );

    // Every record carries the metadata the publisher set.
    for record in &listed {
        assert_eq!(record.vendor, "inblockio");
        assert_eq!(record.publisher_did, did);
        assert!(record.superseded_by.is_none());
        assert!(
            record.display_name.as_ref().is_some_and(|d| !d.is_empty()),
            "{} has no display name",
            record.name
        );
        assert!(
            record.description.as_ref().is_some_and(|d| d.len() > 20),
            "{} has no useful description",
            record.name
        );
    }

    // The namespace itself is indexed against the same DID.
    let vendors = registry.publisher_vendors(&did);
    assert_eq!(vendors.len(), 1);
    assert_eq!(vendors[0].vendor, "inblockio");

    // A different DID sees none of it.
    assert!(registry
        .publisher_templates("did:key:z6MkStranger")
        .is_empty());

    // ---- the feed ----------------------------------------------------------
    let page = registry.feed(&did, 0, None);
    assert_eq!(page.entries.len(), 12, "the feed carries the whole set");
    assert!(!page.has_more);
    assert_eq!(page.next, 12);

    let seqs: Vec<u64> = page.entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=12).collect::<Vec<u64>>(), "feed is in order");

    assert_eq!(page.entries[0].kind, RegistrationKind::Vendor);
    assert_eq!(page.entries[0].qualified_name, "inblockio");
    for (i, name) in EXPECTED_NAMES.iter().enumerate() {
        let entry = &page.entries[i + 1];
        assert_eq!(entry.kind, RegistrationKind::Template);
        assert_eq!(entry.qualified_name, format!("inblockio/{name}"));
        assert_eq!(entry.publisher_did, did);
    }

    // A consumer resuming mid-set gets exactly the tail.
    let tail = registry.feed(&did, 9, None);
    assert_eq!(tail.entries.len(), 3);
    assert_eq!(
        tail.entries[0].qualified_name,
        "inblockio/audit_agent_response"
    );
}

// ---------------------------------------------------------------------------
// 4. A consumer can fetch a tree back and verify it independently.
// ---------------------------------------------------------------------------

/// The point of storing trees verbatim: a consumer refetches one and verifies
/// it with core, without trusting the registry that served it.
#[tokio::test]
async fn refetched_trees_verify_independently() {
    let dir = TempDir::new("audit-refetch");
    let (registry, m) = replay(dir.path()).await;

    let aquafier = Aquafier::new();
    let mut verified = 0;

    for entry in registrations(&m) {
        if entry["kind"] != "template" {
            continue;
        }
        let hash = entry["template_hash"].as_str().unwrap();
        let name = entry["name"].as_str().unwrap();

        let stored = registry
            .template_tree(hash)
            .unwrap_or_else(|e| panic!("{name} tree is not stored: {e}"));

        // Byte-identical to the committed seed file.
        let seed_body =
            std::fs::read_to_string(seed_dir().join(entry["tree_file"].as_str().unwrap())).unwrap();
        assert_eq!(stored, seed_body, "{name} was not stored verbatim");

        let tree: Tree = serde_json::from_str(&stored).expect("stored tree parses");
        let result = aquafier
            .verify_aqua_tree_with_linked_trees(
                AquaTreeWrapper::new(tree, None, None),
                templates::linked_trees(),
                vec![],
            )
            .await
            .expect("verification ran");
        assert!(
            result.is_verified(),
            "{name} tree does not re-verify: {:?}",
            result.outcome
        );
        verified += 1;
    }
    assert_eq!(verified, 11);
}

// ---------------------------------------------------------------------------
// 5. Staleness check against the live core checkout.
// ---------------------------------------------------------------------------

/// The seed's definitions are copies of core's. This asserts they are still
/// byte-identical to the checkout next door, which catches a seed that has gone
/// stale because core moved.
///
/// `#[ignore]`d because it is a check on the relationship between two
/// repositories rather than on this one: core legitimately moves ahead of a
/// published v1 set, and a failure here means "time to publish v2", not "this
/// build is broken". Run it deliberately:
///
/// ```text
/// cargo test --test audit_set -- --ignored
/// ```
#[test]
#[ignore = "checks the seed against the neighbouring aqua-rs-sdk-core checkout"]
fn seed_definitions_still_match_the_core_checkout() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent of the manifest dir")
        .join("aqua-rs-sdk-core");
    let template_dir = core.join("src/schema/templates");
    assert!(
        template_dir.is_dir(),
        "no core checkout at {}",
        template_dir.display()
    );

    let mut stale = Vec::new();
    for name in EXPECTED_NAMES {
        let file = format!("{name}.json");
        let ours = std::fs::read(seed_dir().join("definitions").join(&file))
            .unwrap_or_else(|e| panic!("seed definition {file}: {e}"));
        let theirs = match std::fs::read(template_dir.join(&file)) {
            Ok(t) => t,
            Err(e) => {
                stale.push(format!("{file} is gone from core ({e})"));
                continue;
            }
        };
        if ours != theirs {
            stale.push(format!("{file} differs from core"));
        }
    }

    assert!(
        stale.is_empty(),
        "seed/audit-set-v1 has gone stale against core, publish a v2 set: {stale:?}"
    );
}
