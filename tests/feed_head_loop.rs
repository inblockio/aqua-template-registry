//! Feed heads end to end, against a real registry and a real subscriber.
//!
//! `tests/feed_head_security.rs` proves the checks deny in isolation. These
//! prove the same checks fire through the whole stack: a head published over
//! HTTP, fetched by a subscriber, and used to refuse a registry that is
//! misbehaving. Refusing has to mean nothing was imported and the cursor did
//! not move, so that is asserted rather than assumed.
//!
//! The withholding and rollback cases are staged by editing the registry's data
//! directory between syncs. That is the closest available stand-in for a
//! hostile registry: the daemon is honest, its data is not.

mod common;

use std::path::{Path, PathBuf};

use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::feedhead::{self, HeadRejection};
use aqua_template_registry::httpclient::RegistryClient;
use aqua_template_registry::import::ImportStore;
use aqua_template_registry::model::TemplateRegistration;
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::subscribe::{HeadStatus, Subscriber, SyncError};
use aqua_template_registry::templates;
use aqua_template_registry::trust::{ImportPolicy, PinMode};

use common::{RegistryDaemon, TempDir};

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
            "properties": {
                "note": { "type": "string", "maxLength": 256 },
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
    .expect("serialize")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Publish a template plus its body, returning the registered hash.
async fn publish_template(
    client: &RegistryClient,
    aquafier: &Aquafier,
    key: &PublisherKey,
    vendor: &str,
    name: &str,
    body: &str,
) -> String {
    let hash = templates::template_hash_of_definition(body).expect("hash");
    let tree = publisher::template_registration(
        aquafier,
        key,
        TemplateRegistration {
            vendor: vendor.into(),
            name: name.into(),
            template_hash: hash.clone(),
            supersedes: None,
            display_name: Some(name.into()),
            description: None,
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await
    .expect("build");
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

/// Sign and submit a head covering everything this publisher has published.
async fn publish_head(
    client: &RegistryClient,
    aquafier: &Aquafier,
    key: &PublisherKey,
    tips: &[String],
) -> String {
    let tree = feedhead::build(aquafier, &key.credentials(), key.did(), tips, now_secs())
        .await
        .expect("build head");
    let body = publisher::to_json_pretty(&tree).unwrap();
    let response = client
        .post("/heads", body.clone())
        .await
        .expect("post head");
    assert_eq!(response.status, 201, "POST /heads: {}", response.body);
    body
}

/// The publisher's entry tips in feed order, as the registry serves them.
async fn feed_tips(client: &RegistryClient, did: &str) -> Vec<String> {
    let page: aqua_template_registry::model::FeedPage = client
        .get_json(&format!("/publishers/{did}/feed?since=0&limit=1000"))
        .await
        .expect("feed");
    page.entries.into_iter().map(|e| e.tree_tip).collect()
}

fn write_policy(path: &Path, did: &str, pins: &[(&str, &str)]) {
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(did);
    for (n, h) in pins {
        policy.approve(n, h).expect("pin");
    }
    policy.save(path).expect("save");
}

fn subscriber_at(
    base_url: &str,
    did: &str,
    consumer: &TempDir,
    policy_path: &PathBuf,
) -> Subscriber {
    Subscriber::new(
        base_url,
        did,
        ImportStore::open(consumer.join("imported")).unwrap(),
        ImportPolicy::load(policy_path).unwrap(),
        Some(policy_path.clone()),
        consumer.join("cursor.json"),
    )
    .expect("subscriber")
}

/// Set up a registry with one vendor and two templates, plus a head over all
/// three entries. Returns (daemon, key, policy path, consumer dir).
async fn staged() -> (RegistryDaemon, TempDir, PublisherKey, TempDir, PathBuf) {
    let server_dir = TempDir::new("head-server");
    let daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([31u8; 32]).unwrap();

    let vendor_tree = publisher::vendor_registration(&aquafier, &key, "headvendor", None)
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

    let h1 = publish_template(
        &client,
        &aquafier,
        &key,
        "headvendor",
        "one",
        &novel_definition(0xc1),
    )
    .await;
    let h2 = publish_template(
        &client,
        &aquafier,
        &key,
        "headvendor",
        "two",
        &novel_definition(0xc2),
    )
    .await;

    let tips = feed_tips(&client, key.did()).await;
    assert_eq!(tips.len(), 3, "vendor claim plus two templates");
    publish_head(&client, &aquafier, &key, &tips).await;

    let consumer = TempDir::new("head-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(
        &policy_path,
        key.did(),
        &[("headvendor/one", &h1), ("headvendor/two", &h2)],
    );

    (daemon, server_dir, key, consumer, policy_path)
}

// ---------------------------------------------------------------------------
// 1. The happy path, and what the head actually asserts.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_verified_head_lets_the_subscriber_advance() {
    let (mut daemon, _server, key, consumer, policy_path) = staged().await;
    let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);

    let report = sub.sync(PinMode::PinnedOnly).await.expect("sync");

    let head = match report.head.as_ref().expect("a head was checked") {
        HeadStatus::Verified(h) => h.clone(),
        HeadStatus::Bootstrapping => panic!("a head was published, so it must have verified"),
    };
    assert_eq!(head.head_seq, 3, "the head covers all three entries");
    assert_eq!(head.publisher_did, key.did());
    assert_eq!(head.leaf_version, feedhead::LEAF_VERSION);

    assert_eq!(report.imported.len(), 2);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(report.cursor, 3);

    // The cursor and the verified head height are both persisted, which is what
    // makes rollback detectable on the next sync.
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(consumer.join("cursor.json")).unwrap())
            .unwrap();
    assert_eq!(state["cursor"], 3);
    assert_eq!(state["head_seq"], 3);
    assert_eq!(state["head_root"], head.merkle_root);

    daemon.stop();
}

/// A publisher who has not adopted feed heads is followed, but the subscriber
/// says so every time. Refusing outright would make the feature unadoptable;
/// staying quiet would let a consumer believe it had a guarantee it does not.
#[tokio::test]
async fn a_publisher_with_no_head_bootstraps_and_is_reported() {
    let server_dir = TempDir::new("head-boot-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([32u8; 32]).unwrap();

    let vendor_tree = publisher::vendor_registration(&aquafier, &key, "nohead", None)
        .await
        .unwrap();
    client
        .post("/vendors", publisher::to_json(&vendor_tree).unwrap())
        .await
        .unwrap();
    let hash = publish_template(
        &client,
        &aquafier,
        &key,
        "nohead",
        "one",
        &novel_definition(0xd1),
    )
    .await;

    let consumer = TempDir::new("head-boot-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(&policy_path, key.did(), &[("nohead/one", &hash)]);
    let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);

    let report = sub.sync(PinMode::PinnedOnly).await.expect("sync");
    assert!(
        report.head.as_ref().unwrap().is_bootstrapping(),
        "no head was published, so this must report bootstrapping"
    );
    assert_eq!(report.imported.len(), 1, "import still proceeds");
    assert_eq!(report.cursor, 2);

    // Nothing was recorded as a verified head, so adopting one later is still
    // forward progress rather than a spurious rollback.
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(consumer.join("cursor.json")).unwrap())
            .unwrap();
    assert!(state["head_seq"].is_null());

    daemon.stop();
}

// ---------------------------------------------------------------------------
// 2. Withholding.
// ---------------------------------------------------------------------------

/// The headline case. The registry serves fewer entries than the publisher
/// signed for, which is exactly the attack a feed head exists to catch.
#[tokio::test]
async fn a_registry_withholding_entries_is_caught_and_nothing_is_imported() {
    let (mut daemon, server, key, consumer, policy_path) = staged().await;

    // Take the daemon down, delete the last feed entry, bring it back. The
    // daemon is honest; its data has been tampered with, which is the closest
    // stand-in available for a registry that chooses to omit an entry.
    daemon.stop();
    let entries = server.join("data").join("entries");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&entries)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    std::fs::remove_file(files.last().unwrap()).expect("drop the last entry");

    daemon.start_again();
    let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);

    let err = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect_err("a truncated feed must not be accepted");
    match &err {
        SyncError::Head(HeadRejection::Withholding {
            available,
            head_seq,
        }) => {
            assert_eq!(*available, 2, "the registry served two of three entries");
            assert_eq!(*head_seq, 3, "the signed head covers three");
        }
        other => panic!("expected Withholding, got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_WITHHOLDING");

    // Fail closed: nothing imported, nothing persisted.
    assert!(
        sub.store().hashes().unwrap().is_empty(),
        "a failed head check must import nothing"
    );
    assert_eq!(sub.cursor(), 0, "the cursor must not advance");
    assert!(
        !consumer.join("cursor.json").exists()
            || serde_json::from_str::<serde_json::Value>(
                &std::fs::read_to_string(consumer.join("cursor.json")).unwrap()
            )
            .unwrap()["cursor"]
                == 0,
        "no progress may be written after a head failure"
    );

    daemon.stop();
}

// ---------------------------------------------------------------------------
// 3. Rollback.
// ---------------------------------------------------------------------------

/// A subscriber that has verified a head at height 3 must refuse a registry
/// that later offers only the height-1 head, even though that head is a
/// perfectly valid signature from the right publisher.
#[tokio::test]
async fn a_replayed_older_head_is_refused_as_a_rollback() {
    let server_dir = TempDir::new("head-roll-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([33u8; 32]).unwrap();

    let vendor_tree = publisher::vendor_registration(&aquafier, &key, "rollvendor", None)
        .await
        .unwrap();
    client
        .post("/vendors", publisher::to_json(&vendor_tree).unwrap())
        .await
        .unwrap();

    // A head covering just the vendor claim.
    let tips_1 = feed_tips(&client, key.did()).await;
    assert_eq!(tips_1.len(), 1);
    publish_head(&client, &aquafier, &key, &tips_1).await;

    // Then a template and a head covering both.
    let hash = publish_template(
        &client,
        &aquafier,
        &key,
        "rollvendor",
        "one",
        &novel_definition(0xe1),
    )
    .await;
    let tips_2 = feed_tips(&client, key.did()).await;
    assert_eq!(tips_2.len(), 2);
    publish_head(&client, &aquafier, &key, &tips_2).await;

    let consumer = TempDir::new("head-roll-consumer");
    let policy_path = consumer.join("trust.json");
    write_policy(&policy_path, key.did(), &[("rollvendor/one", &hash)]);

    {
        let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);
        let report = sub.sync(PinMode::PinnedOnly).await.expect("first sync");
        assert_eq!(
            report.head.as_ref().unwrap().verified().unwrap().head_seq,
            2
        );
        assert_eq!(report.imported.len(), 1);
    }

    // The registry rolls back to the older head by deleting the newer one.
    daemon.stop();
    let heads = server_dir
        .join("data")
        .join("heads")
        .join(hex::encode(key.did().as_bytes()));
    let mut files: Vec<PathBuf> = std::fs::read_dir(&heads)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    files.sort();
    assert_eq!(files.len(), 2, "both heads were stored");
    std::fs::remove_file(files.last().unwrap()).expect("drop the newer head");
    daemon.start_again();

    let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);
    let err = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect_err("an older head must be refused once a newer one was verified");
    match &err {
        SyncError::Head(HeadRejection::Rollback { previous, offered }) => {
            assert_eq!(*previous, 2);
            assert_eq!(*offered, 1);
        }
        other => panic!("expected Rollback, got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_ROLLBACK");

    daemon.stop();
}

// ---------------------------------------------------------------------------
// 4. Disappearance.
// ---------------------------------------------------------------------------

/// Bootstrapping is tolerated only until the first head is seen. After that, a
/// registry serving none is failing, not bootstrapping. Without this asymmetry
/// a registry could opt a subscriber back out of the guarantee at will.
#[tokio::test]
async fn a_head_that_disappears_after_being_verified_is_a_failure() {
    let (mut daemon, server, key, consumer, policy_path) = staged().await;

    {
        let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);
        let report = sub.sync(PinMode::PinnedOnly).await.expect("first sync");
        assert_eq!(
            report.head.as_ref().unwrap().verified().unwrap().head_seq,
            3
        );
    }

    daemon.stop();
    std::fs::remove_dir_all(server.join("data").join("heads")).expect("remove every head");
    daemon.start_again();

    let mut sub = subscriber_at(daemon.base_url(), key.did(), &consumer, &policy_path);
    let err = sub
        .sync(PinMode::PinnedOnly)
        .await
        .expect_err("a head cannot un-exist");
    assert!(
        matches!(
            err,
            SyncError::Head(HeadRejection::Disappeared { previous: 3 })
        ),
        "got {err:?}"
    );
    assert_eq!(err.code(), "HEAD_DISAPPEARED");

    daemon.stop();
}

// ---------------------------------------------------------------------------
// 5. The registry's own ingest checks.
// ---------------------------------------------------------------------------

/// The registry refuses a head it cannot reproduce from its own entries. Not a
/// security control (a subscriber recomputes the root itself and does not rely
/// on this), but it turns a publisher's ordering mistake into an immediate 422
/// instead of a subscriber failing closed days later.
#[tokio::test]
async fn the_registry_refuses_a_head_that_does_not_match_its_own_feed() {
    let (mut daemon, _server, key, _consumer, _policy) = staged().await;
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aquafier = Aquafier::new();

    let mut tips = feed_tips(&client, key.did()).await;
    tips.reverse(); // a head built over the wrong order

    let tree = feedhead::build(&aquafier, &key.credentials(), key.did(), &tips, now_secs())
        .await
        .unwrap();
    let response = client
        .post("/heads", publisher::to_json_pretty(&tree).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status, 422, "{}", response.body);
    let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["error"]["code"], "HEAD_REJECTED");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("root mismatch"),
        "the message should say what was wrong: {}",
        body["error"]["message"]
    );

    daemon.stop();
}

/// A head from a publisher with no entries here has nothing to commit to.
#[tokio::test]
async fn the_registry_refuses_a_head_from_an_unknown_publisher() {
    let server_dir = TempDir::new("head-unknown-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let aquafier = Aquafier::new();
    let stranger = PublisherKey::from_seed([34u8; 32]).unwrap();

    let tree = feedhead::build(
        &aquafier,
        &stranger.credentials(),
        stranger.did(),
        &[format!("0x1620{}", hex::encode([7u8; 32]))],
        now_secs(),
    )
    .await
    .unwrap();
    let response = client
        .post("/heads", publisher::to_json_pretty(&tree).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status, 422, "{}", response.body);
    let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["error"]["code"], "HEAD_REJECTED");

    daemon.stop();
}

/// Heads are served per publisher and by height, and listing them is how a
/// consumer can see the sequence rather than only the tip.
#[tokio::test]
async fn heads_are_served_latest_by_height_and_listed() {
    let (mut daemon, _server, key, _consumer, _policy) = staged().await;
    let client = RegistryClient::new(daemon.base_url()).unwrap();
    let did = key.did();

    let heights: Vec<u64> = client
        .get_json(&format!("/publishers/{did}/heads"))
        .await
        .expect("list heads");
    assert_eq!(heights, vec![3]);

    let latest = client
        .get_raw(&format!("/publishers/{did}/head"))
        .await
        .expect("latest head");
    let at_3 = client
        .get_raw(&format!("/publishers/{did}/heads/3"))
        .await
        .expect("head at height 3");
    assert_eq!(latest, at_3, "the latest head is the one at the top height");

    // And it verifies, served verbatim.
    let verified = feedhead::verify_head(&Aquafier::new(), &latest, Some(did))
        .await
        .expect("the served head must verify");
    assert_eq!(verified.head_seq, 3);

    let missing = client
        .get(&format!("/publishers/{did}/heads/99"))
        .await
        .unwrap();
    assert_eq!(missing.status, 404);

    daemon.stop();
}

// ---------------------------------------------------------------------------
// 6. The shipped seed set.
// ---------------------------------------------------------------------------

/// The committed seed head must cover the committed seed set. A head that did
/// not would be worse than none: it would look like a guarantee and fail closed
/// for every subscriber.
#[tokio::test]
async fn the_shipped_seed_head_covers_the_shipped_seed_set() {
    let manifest = common::seed_manifest();
    let head_block = manifest
        .get("feed_head")
        .expect("the seed manifest must describe its feed head");

    let body = std::fs::read_to_string(
        common::seed_dir().join(head_block["file"].as_str().expect("file")),
    )
    .expect("read the seed head");

    let did = manifest["publisher_did"].as_str().unwrap();
    let head = feedhead::verify_head(&Aquafier::new(), &body, Some(did))
        .await
        .expect("the shipped head must verify");

    assert_eq!(head.head_seq, head_block["head_seq"].as_u64().unwrap());
    assert_eq!(
        head.merkle_root,
        head_block["merkle_root"].as_str().unwrap()
    );
    assert_eq!(head.tree_tip, head_block["tree_tip"].as_str().unwrap());
    assert_eq!(head.head_seq, 12, "one vendor claim plus eleven templates");

    // Recompute the root from the manifest's own tips, in seq order.
    let mut ordered: Vec<(u64, String)> = manifest["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["seq"].as_u64().unwrap(),
                r["tree_tip"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    ordered.sort_by_key(|(s, _)| *s);
    let tips: Vec<String> = ordered.into_iter().map(|(_, t)| t).collect();

    feedhead::check_against_entries(&head, &tips)
        .expect("the shipped head must reproduce from the shipped registrations");
}

/// Replaying the whole seed set, head included, through a real daemon.
#[tokio::test]
async fn the_seed_set_replays_with_its_head_and_a_subscriber_verifies_it() {
    let server_dir = TempDir::new("head-seed-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();

    let did = common::publish_seed_over_http(&client).await;

    let manifest = common::seed_manifest();
    let head_body = std::fs::read_to_string(
        common::seed_dir().join(manifest["feed_head"]["file"].as_str().unwrap()),
    )
    .unwrap();
    let response = client.post("/heads", head_body).await.expect("post head");
    assert_eq!(response.status, 201, "{}", response.body);

    let consumer = TempDir::new("head-seed-consumer");
    let mut sub = Subscriber::new(
        daemon.base_url(),
        &did,
        ImportStore::open(consumer.join("imported")).unwrap(),
        ImportPolicy::load(common::shipped_trust_config()).unwrap(),
        None,
        consumer.join("cursor.json"),
    )
    .unwrap();

    let report = sub.sync(PinMode::PinnedOnly).await.expect("sync");
    let head = report.head.as_ref().unwrap().verified().expect("verified");
    assert_eq!(head.head_seq, 12);
    assert_eq!(report.imported.len(), 11);
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);

    daemon.stop();
}
