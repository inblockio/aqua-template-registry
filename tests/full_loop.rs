//! R3: the whole loop, once, with nothing stubbed.
//!
//! Publish a template set into a real `registryd`, subscribe to it from a
//! separate store over real HTTP with the whitelist active, import what
//! verifies, then actually use an imported template: create an object of that
//! type with `aqua-rs-sdk-core` and verify it green by shipping the imported
//! definition back as a linked tree. Then publish one more template and prove
//! the subscriber picks up exactly the delta, and that the pin policy governs
//! whether it is allowed in.
//!
//! The point of the last part is that "picks up the delta" and "accepts the
//! delta" are different questions. A subscriber must notice new work without
//! automatically trusting it.

mod common;

use std::path::PathBuf;

use aqua_rs_sdk_core::primitives::{Method, RevisionLink};
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::httpclient::RegistryClient;
use aqua_template_registry::import::{ImportRejection, ImportStore};
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::subscribe::Subscriber;
use aqua_template_registry::templates;
use aqua_template_registry::trust::{ImportPolicy, PinMode};

use common::{RegistryDaemon, TempDir};

/// Turn a bare `0x<64hex>` template hash into the multihash link core wants.
fn link_of(bare: &str) -> RevisionLink {
    let bytes = hex::decode(bare.trim_start_matches("0x")).expect("hex");
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    RevisionLink::from_bytes(arr)
}

fn definition(name: &str) -> String {
    std::fs::read_to_string(
        common::seed_dir()
            .join("definitions")
            .join(format!("{name}.json")),
    )
    .unwrap_or_else(|e| panic!("read definition {name}: {e}"))
}

/// A template definition that `aqua-rs-sdk-core` has never seen.
///
/// The audit definitions in the seed set are all core built-ins, so core
/// resolves them with no linked tree at all. That makes them useless for
/// proving the portable-template pattern: a test using one would pass whether
/// or not the import worked. These are synthesised instead, with a distinct
/// nonce per call so each is a distinct type, and no `derives_from`, so nothing
/// about them exists in any SDK.
fn novel_definition(nonce_byte: u8, max_note_len: u32) -> String {
    let nonce = format!("0x{}", hex::encode([nonce_byte; 16]));
    serde_json::to_string_pretty(&serde_json::json!({
        "revision_type": "0x1620f3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155",
        "nonce": nonce,
        "local_timestamp": 1786060000u64,
        "version": "https://aqua-protocol.org/docs/v4/schema",
        "method": "scalar",
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "note": { "type": "string", "maxLength": max_note_len },
                "created_at": { "type": "integer" }
            },
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
    .expect("serialize the novel definition")
}

/// Publish one template plus its definition body over HTTP.
async fn publish_template(
    client: &RegistryClient,
    aquafier: &Aquafier,
    key: &PublisherKey,
    vendor: &str,
    name: &str,
    body: &str,
) -> String {
    let hash = templates::template_hash_of_definition(body).expect("hash the definition");
    let tree = publisher::template_registration(
        aquafier,
        key,
        TemplateRegistration {
            vendor: vendor.to_string(),
            name: name.to_string(),
            template_hash: hash.clone(),
            supersedes: None,
            display_name: Some(name.to_string()),
            description: Some(format!("{name}, published by the full-loop test.")),
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await
    .expect("build template registration");

    let response = client
        .post("/templates", publisher::to_json(&tree).unwrap())
        .await
        .expect("post template");
    assert_eq!(response.status, 201, "POST /templates: {}", response.body);

    let response = client
        .post("/definitions", body.to_string())
        .await
        .expect("post definition");
    assert_eq!(response.status, 201, "POST /definitions: {}", response.body);

    hash
}

/// Write a trust policy allowing `did` and pinning the given name to hash pairs.
fn write_policy(path: &PathBuf, did: &str, pins: &[(&str, &str)]) {
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(did);
    for (name, hash) in pins {
        policy.approve(name, hash).expect("pin");
    }
    policy.save(path).expect("save policy");
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_subscribe_import_use_then_pick_up_the_delta() {
    // ---- 0. a publisher and a running registry -----------------------------
    let server_dir = TempDir::new("loop-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).expect("client");
    assert!(client.healthy().await, "registryd should be up");

    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([21u8; 32]).expect("key");
    let did = key.did().to_string();

    let vendor_tree = publisher::vendor_registration(&aquafier, &key, "loopvendor", Some("Loop"))
        .await
        .expect("vendor tree");
    let response = client
        .post("/vendors", publisher::to_json(&vendor_tree).unwrap())
        .await
        .expect("post vendor");
    assert_eq!(response.status, 201, "{}", response.body);

    // Two templates that exist nowhere but this test. Using an audit
    // definition here would prove nothing: core ships those as built-ins and
    // resolves them with no linked tree, so the import could be a no-op and
    // every assertion below would still pass.
    let artifact_body = novel_definition(0xa1, 256);
    let prompt_body = novel_definition(0xb2, 512);

    let artifact_hash = publish_template(
        &client,
        &aquafier,
        &key,
        "loopvendor",
        "artifact",
        &artifact_body,
    )
    .await;

    // ---- 1. a subscriber in a SEPARATE store, with the whitelist active ----
    let consumer_dir = TempDir::new("loop-consumer");
    let policy_path = consumer_dir.join("trust.json");
    write_policy(
        &policy_path,
        &did,
        &[("loopvendor/artifact", &artifact_hash)],
    );

    let store = ImportStore::open(consumer_dir.join("imported")).expect("import store");
    let policy = ImportPolicy::load(&policy_path).expect("load policy");
    let mut subscriber = Subscriber::new(
        daemon.base_url(),
        &did,
        store,
        policy,
        Some(policy_path.clone()),
        consumer_dir.join("cursor.json"),
    )
    .expect("subscriber");

    let report = subscriber
        .sync(PinMode::PinnedOnly)
        .await
        .expect("first sync");

    assert_eq!(report.imported.len(), 1, "the pinned template imports");
    assert!(
        report.rejected.is_empty(),
        "nothing should be refused: {:?}",
        report.rejected
    );
    assert_eq!(report.imported[0].template_hash, artifact_hash);
    assert_eq!(report.imported[0].qualified_name, "loopvendor/artifact");
    assert_eq!(report.imported[0].publisher_did, did);
    // The vendor claim is seq 1 and the template seq 2, so a completed sync
    // leaves the cursor at 2.
    assert_eq!(report.cursor, 2);

    // ---- 2. the imported definition is exactly what was published ----------
    let imported_body = subscriber
        .store()
        .definition(&artifact_hash)
        .expect("stored definition");
    assert_eq!(
        imported_body, artifact_body,
        "the subscriber must store the published bytes, not a re-serialization"
    );

    // ---- 3. USE it: create an object of the imported type ------------------
    // This is the payoff. The consumer never had this template compiled in;
    // it arrived over the wire, was verified, and is now a usable type.
    let payload = serde_json::json!({
        "note": "an object of a type this process learned over the wire",
        "created_at": 1786060000u64,
    });
    let object_tree = aquafier
        .create_object(link_of(&artifact_hash), None, payload, Some(Method::Scalar))
        .expect("create an object of the imported type");

    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(object_tree, None, None),
            &key.credentials(),
            None,
            None,
        )
        .await
        .expect("sign the object");

    // Ship the template alongside, the portable-template pattern. Without this
    // linked tree the type would not resolve, which is exactly why importing
    // the definition body (and not merely the hash) is the point.
    let linked = subscriber
        .store()
        .linked_tree(&artifact_hash)
        .expect("imported template as a linked tree");

    let result = aquafier
        .verify_aqua_tree_with_linked_trees(
            AquaTreeWrapper::new(signed.aqua_tree.clone(), None, None),
            vec![linked],
            vec![],
        )
        .await
        .expect("verification ran");
    assert!(
        result.is_verified(),
        "an object of an imported type must verify: {:?}",
        result.outcome
    );

    // And it must NOT verify without the template, which proves the linked
    // tree is doing the work rather than the type resolving some other way.
    let without = aquafier
        .verify_aqua_tree(AquaTreeWrapper::new(signed.aqua_tree, None, None), vec![])
        .await
        .expect("verification ran");
    assert!(
        !without.is_verified(),
        "without the imported template the type cannot resolve"
    );

    // ---- 4. publish ONE more, assert the subscriber sees exactly the delta --
    let prompt_hash = publish_template(
        &client,
        &aquafier,
        &key,
        "loopvendor",
        "prompt",
        &prompt_body,
    )
    .await;

    // In PinnedOnly mode the new template is NOTICED but REFUSED: seeing new
    // work and trusting it are different things.
    let report = subscriber
        .sync(PinMode::PinnedOnly)
        .await
        .expect("second sync");
    assert!(
        report.imported.is_empty(),
        "an unpinned template must not import"
    );
    assert_eq!(report.rejected.len(), 1, "exactly the one new template");
    assert_eq!(report.rejected[0].qualified_name, "loopvendor/prompt");
    assert!(
        matches!(
            report.rejected[0].rejection,
            ImportRejection::NotPinned { .. }
        ),
        "expected NotPinned, got {:?}",
        report.rejected[0].rejection
    );
    // The cursor did not step over the refusal, so a later poll offers it again.
    assert_eq!(report.cursor, 2, "the cursor holds at the refused entry");
    assert_eq!(
        subscriber.store().hashes().unwrap().len(),
        1,
        "still only the first template in the store"
    );

    // ---- 5. approve it, and now exactly the delta arrives -------------------
    let report = subscriber
        .sync(PinMode::ApproveNew)
        .await
        .expect("third sync");
    assert_eq!(report.imported.len(), 1, "exactly the delta, not a resync");
    assert_eq!(report.imported[0].template_hash, prompt_hash);
    assert!(report.imported[0].newly_pinned);
    assert_eq!(report.newly_pinned, vec!["loopvendor/prompt".to_string()]);
    assert_eq!(report.cursor, 3);

    // The approval was written back, so it is durable and reviewable in a diff.
    let reloaded = ImportPolicy::load(&policy_path).expect("reload policy");
    assert_eq!(
        reloaded.pin("loopvendor/prompt"),
        Some(prompt_hash.as_str()),
        "ApproveNew must persist the pin, not just allow the import"
    );
    assert_eq!(reloaded.pin_count(), 2);

    // ---- 6. a fourth sync is a no-op ---------------------------------------
    let report = subscriber.sync(PinMode::ApproveNew).await.expect("fourth");
    assert!(
        report.imported.is_empty() && report.rejected.is_empty(),
        "a caught-up subscriber does no work"
    );
    assert_eq!(report.cursor, 3);

    let mut names: Vec<String> = subscriber
        .store()
        .records()
        .unwrap()
        .into_iter()
        .map(|r| r.qualified_name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["loopvendor/artifact", "loopvendor/prompt"]);

    let status = daemon.stop();
    assert!(status.success(), "registryd exited with {status}");
}

// ---------------------------------------------------------------------------

/// The cursor is on disk, so a subscriber restarted from scratch resumes rather
/// than reprocessing or skipping.
#[tokio::test]
async fn a_restarted_subscriber_resumes_from_its_persisted_cursor() {
    let server_dir = TempDir::new("loop-resume-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).expect("client");

    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([22u8; 32]).expect("key");
    let did = key.did().to_string();

    let vendor_tree = publisher::vendor_registration(&aquafier, &key, "resumevendor", None)
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

    let body = definition("audit_artifact");
    let hash = publish_template(&client, &aquafier, &key, "resumevendor", "artifact", &body).await;

    let consumer_dir = TempDir::new("loop-resume-consumer");
    let policy_path = consumer_dir.join("trust.json");
    write_policy(&policy_path, &did, &[("resumevendor/artifact", &hash)]);
    let cursor_path = consumer_dir.join("cursor.json");
    let store_path = consumer_dir.join("imported");

    // First subscriber instance: imports, then goes away.
    {
        let mut subscriber = Subscriber::new(
            daemon.base_url(),
            &did,
            ImportStore::open(&store_path).unwrap(),
            ImportPolicy::load(&policy_path).unwrap(),
            Some(policy_path.clone()),
            cursor_path.clone(),
        )
        .unwrap();
        let report = subscriber.sync(PinMode::PinnedOnly).await.unwrap();
        assert_eq!(report.imported.len(), 1);
        assert_eq!(report.cursor, 2);
    }

    // A brand new instance over the same directories picks up the cursor.
    let mut subscriber = Subscriber::new(
        daemon.base_url(),
        &did,
        ImportStore::open(&store_path).unwrap(),
        ImportPolicy::load(&policy_path).unwrap(),
        Some(policy_path.clone()),
        cursor_path.clone(),
    )
    .unwrap();
    assert_eq!(
        subscriber.cursor(),
        2,
        "the cursor must survive the subscriber process"
    );

    let report = subscriber.sync(PinMode::PinnedOnly).await.unwrap();
    assert!(
        report.is_empty(),
        "a resumed subscriber reprocesses nothing: {report:?}"
    );
    assert_eq!(subscriber.store().hashes().unwrap().len(), 1);

    daemon.stop();
}

// ---------------------------------------------------------------------------

/// The whitelist is the gate, and it is checked against a DID recovered from a
/// signature rather than against anything the registry reported. A subscriber
/// pointed at a publisher it does not trust imports nothing, no matter how
/// well formed that publisher's registrations are.
#[tokio::test]
async fn a_subscriber_imports_nothing_from_an_untrusted_publisher() {
    let server_dir = TempDir::new("loop-untrusted-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).expect("client");

    let aquafier = Aquafier::new();
    let stranger = PublisherKey::from_seed([23u8; 32]).expect("key");
    let trusted = PublisherKey::from_seed([24u8; 32]).expect("key");

    let vendor_tree = publisher::vendor_registration(&aquafier, &stranger, "stranger", None)
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
    let body = definition("audit_artifact");
    let hash = publish_template(&client, &aquafier, &stranger, "stranger", "artifact", &body).await;

    // The policy trusts a DIFFERENT publisher, and pins the very hash on offer,
    // so only the identity check can be what refuses it.
    let consumer_dir = TempDir::new("loop-untrusted-consumer");
    let policy_path = consumer_dir.join("trust.json");
    write_policy(&policy_path, trusted.did(), &[("stranger/artifact", &hash)]);

    let mut subscriber = Subscriber::new(
        daemon.base_url(),
        stranger.did(),
        ImportStore::open(consumer_dir.join("imported")).unwrap(),
        ImportPolicy::load(&policy_path).unwrap(),
        Some(policy_path),
        consumer_dir.join("cursor.json"),
    )
    .unwrap();

    let report = subscriber.sync(PinMode::ApproveNew).await.unwrap();
    assert!(
        report.imported.is_empty(),
        "an untrusted publisher must import nothing even in ApproveNew"
    );
    assert_eq!(report.rejected.len(), 1);
    assert!(
        matches!(
            report.rejected[0].rejection,
            ImportRejection::PublisherNotAllowed { .. }
        ),
        "expected PublisherNotAllowed, got {:?}",
        report.rejected[0].rejection
    );
    assert!(subscriber.store().hashes().unwrap().is_empty());

    daemon.stop();
}

// ---------------------------------------------------------------------------

/// The shipped trust config really does admit the shipped seed set. A config
/// that pins the wrong hashes would be worse than no config, since it would
/// look like protection and deny everything (or, if it drifted the other way,
/// admit something unreviewed).
#[tokio::test]
async fn the_shipped_trust_config_admits_the_shipped_audit_set() {
    let server_dir = TempDir::new("loop-shipped-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).expect("client");

    let did = common::publish_seed_over_http(&client).await;

    let consumer_dir = TempDir::new("loop-shipped-consumer");
    let policy = ImportPolicy::load(common::shipped_trust_config()).expect("shipped trust config");
    assert!(
        policy.allows_publisher(&did),
        "the shipped config must list the audit set publisher"
    );
    assert_eq!(policy.pin_count(), 11, "one pin per audit template");

    let mut subscriber = Subscriber::new(
        daemon.base_url(),
        &did,
        ImportStore::open(consumer_dir.join("imported")).unwrap(),
        policy,
        // No policy path: this must import with the pins as shipped, without
        // writing anything back.
        None,
        consumer_dir.join("cursor.json"),
    )
    .unwrap();

    // PinnedOnly, the strict mode. Every one of the eleven must already match.
    let report = subscriber.sync(PinMode::PinnedOnly).await.unwrap();
    assert!(
        report.rejected.is_empty(),
        "the shipped config must admit the shipped set without approvals: {:?}",
        report.rejected
    );
    assert_eq!(report.imported.len(), 11);
    assert!(
        report.newly_pinned.is_empty(),
        "nothing should need pinning"
    );
    assert_eq!(report.cursor, 12);

    // Every imported template is usable as a linked tree.
    for record in subscriber.store().records().unwrap() {
        let tree = subscriber
            .store()
            .template_tree(&record.template_hash)
            .unwrap_or_else(|e| panic!("{} is not usable: {e}", record.qualified_name));
        assert_eq!(tree.revisions.len(), 1);
    }

    daemon.stop();
}
