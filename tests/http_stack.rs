//! Full-stack HTTP end-to-end tests against a real spawned `registryd`
//! process (backlog item R1).
//!
//! Every other integration test in this crate either drives the `Registry`
//! library directly (`audit_set.rs`, the library half of `e2e.rs`) or drives
//! the axum `Router` in process through `tower::ServiceExt::oneshot` (the
//! HTTP section of `e2e.rs`). Neither one exercises the actual wire: a real
//! TCP listener, a real `registryd` binary, a fresh client connection per
//! request. This file does. It spawns `registryd` as a child process through
//! `tests/common/mod.rs`, talks to it only through
//! `aqua_template_registry::httpclient::RegistryClient`, and never imports
//! `aqua_template_registry::Registry` at all.
//!
//! What is asserted, in order of how much it would hurt to get wrong:
//!
//! 1. The whole committed audit set publishes over HTTP, and every
//!    registration tree and definition body served back is byte-identical to
//!    the committed seed and re-verifies independently with
//!    `aqua-rs-sdk-core`. If this is wrong nothing else here matters, it is
//!    the load-bearing path a real publisher and a real consumer both walk.
//! 2. The subscription feed pages correctly through its `next` cursor, and a
//!    caught-up consumer does not get rewound. A subscriber that silently
//!    misses or replays an entry has a wrong view of the registry and never
//!    finds out.
//! 3. State and a consumer's cursor position survive a process restart, and
//!    the process exits cleanly on SIGTERM rather than needing to be killed.
//!    A registry that forgets state on restart, or that cannot shut down
//!    gracefully, is not fit to run as a service.
//! 4. HTTP error responses carry the status code and the stable `error.code`
//!    that a real client is expected to branch on, not just a message.
//!
//! Every test spawns its own daemon on its own temporary data directory, kept
//! in a local variable so its `Drop` runs, so the tests can run in parallel
//! without contention and without leaking a process or a socket.

mod common;

use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::httpclient::RegistryClient;
use aqua_template_registry::model::{
    FeedEntry, FeedPage, RegistrationKind, Resolution, ResolutionVia, Stats, VendorRecord,
};
use aqua_template_registry::templates;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Every `template` registration in the manifest, in the order the manifest
/// lists them (seq 2 through 12). Nothing that reads this ever hardcodes one
/// of the eleven names.
fn template_entries(manifest: &serde_json::Value) -> Vec<serde_json::Value> {
    manifest["registrations"]
        .as_array()
        .expect("manifest has a registrations array")
        .iter()
        .filter(|e| e["kind"] == "template")
        .cloned()
        .collect()
}

/// Assert an HTTP error body carries the expected stable `error.code`, the
/// thing a real client is supposed to branch on rather than parsing prose.
fn assert_error_code(body: &str, expected: &str, what: &str) {
    let value: serde_json::Value = serde_json::from_str(body)
        .unwrap_or_else(|e| panic!("{what}: error body is not JSON ({e}), body was: {body}"));
    let code = value["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: error body has no error.code field, body was: {body}"));
    assert_eq!(code, expected, "{what}: registry returned the wrong stable error code");
}

// ---------------------------------------------------------------------------
// 1. The headline path: publish the whole set over HTTP, read it all back.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_the_whole_set_over_http_and_read_it_back() {
    let dir = common::TempDir::new("http-stack-a");
    let daemon = common::RegistryDaemon::start(dir.path());
    let client = RegistryClient::new(daemon.base_url()).expect("base_url is always http://host:port");

    // 1. A freshly spawned registryd must answer /health before anything else
    // is attempted, otherwise every assertion below would just be timing out.
    assert!(client.healthy().await, "freshly spawned registryd did not answer /health");

    // 2. Publish the whole audit set through the HTTP API. This posts every
    // registration to /vendors or /templates and every body to /definitions,
    // asserting 201 along the way (see common::publish_seed_over_http), which
    // is already the "published over HTTP, not through the library" part.
    let did = common::publish_seed_over_http(&client).await;

    let manifest = common::seed_manifest();
    assert_eq!(
        did,
        manifest["publisher_did"].as_str().expect("manifest has publisher_did"),
        "publish_seed_over_http must hand back the manifest's own publisher DID"
    );

    // 3. GET /vendors lists exactly one vendor, inblockio, owned by that DID.
    let vendors: Vec<VendorRecord> = client.get_json("/vendors").await.expect("GET /vendors");
    assert_eq!(vendors.len(), 1, "the seed set claims exactly one vendor namespace");
    assert_eq!(vendors[0].vendor, "inblockio", "the seed's vendor namespace is inblockio");
    assert_eq!(
        vendors[0].vendor_did, did,
        "the vendor namespace must be owned by the manifest's publisher DID"
    );

    // 4. GET /vendors/inblockio returns the same record as the list.
    let vendor: VendorRecord = client
        .get_json("/vendors/inblockio")
        .await
        .expect("GET /vendors/inblockio");
    assert_eq!(
        vendor, vendors[0],
        "the by-name vendor lookup must agree with the list, both read the same index"
    );

    // Drive everything below from the manifest, never from a hardcoded list
    // of the eleven template names.
    let manifest_templates = template_entries(&manifest);
    assert_eq!(manifest_templates.len(), 11, "the audit set registers eleven templates");

    for entry in &manifest_templates {
        let name = entry["name"].as_str().expect("name");
        let expected_hash = entry["template_hash"].as_str().expect("template_hash");

        // 5. GET /resolve/inblockio/{name} resolves to the manifest's hash,
        // via a template registration, carrying the right publisher DID.
        let resolution: Resolution = client
            .get_json(&format!("/resolve/inblockio/{name}"))
            .await
            .unwrap_or_else(|e| panic!("inblockio/{name} did not resolve over HTTP: {e}"));
        assert_eq!(
            resolution.template_hash, expected_hash,
            "inblockio/{name} resolved to the wrong hash over HTTP"
        );
        assert_eq!(
            resolution.via,
            ResolutionVia::Template,
            "inblockio/{name} must resolve via a template registration, not an alias"
        );
        assert_eq!(
            resolution.publisher_did.as_deref(),
            Some(did.as_str()),
            "inblockio/{name} resolution must carry the publisher DID"
        );

        // 6. GET /templates/{hash} returns the registration tree, and it must
        // be byte-identical to the committed seed file, and it must still
        // verify independently with core after the round trip through HTTP.
        let tree_file = entry["tree_file"].as_str().expect("tree_file");
        let seed_body = std::fs::read_to_string(common::seed_dir().join(tree_file))
            .unwrap_or_else(|e| panic!("cannot read seed tree {tree_file}: {e}"));

        let stored = client
            .get_raw(&format!("/templates/{expected_hash}"))
            .await
            .unwrap_or_else(|e| panic!("GET /templates/{expected_hash} failed: {e}"));
        assert_eq!(
            stored, seed_body,
            "{name}: the tree served over HTTP must be byte-identical to the committed seed file"
        );

        let tree: Tree = serde_json::from_str(&stored)
            .unwrap_or_else(|e| panic!("{name}: tree served over HTTP does not parse: {e}"));
        let result = Aquafier::new()
            .verify_aqua_tree_with_linked_trees(
                AquaTreeWrapper::new(tree, None, None),
                templates::linked_trees(),
                vec![],
            )
            .await
            .expect("verification ran");
        assert!(
            result.is_verified(),
            "{name}: tree fetched over HTTP does not re-verify with core: {:?}",
            result.outcome
        );

        // 7. GET /definitions/{hash} returns the definition body, byte for
        // byte identical to the seed, and recomputing its hash must land back
        // on the exact hash used in the URL.
        let def_file = entry["definition_file"].as_str().expect("definition_file");
        let seed_def = std::fs::read_to_string(common::seed_dir().join(def_file))
            .unwrap_or_else(|e| panic!("cannot read seed definition {def_file}: {e}"));

        let served_def = client
            .get_raw(&format!("/definitions/{expected_hash}"))
            .await
            .unwrap_or_else(|e| panic!("GET /definitions/{expected_hash} failed: {e}"));
        assert_eq!(
            served_def, seed_def,
            "{name}: the definition body served over HTTP must be byte-identical to the seed"
        );

        let recomputed = templates::template_hash_of_definition(&served_def)
            .unwrap_or_else(|e| panic!("{name}: served definition does not hash: {e}"));
        assert_eq!(
            recomputed, expected_hash,
            "{name}: rehashing the served definition must reproduce the hash in the URL"
        );
    }

    // 8. GET /stats shows the whole set: one vendor, eleven templates, one
    // publisher, head_seq 12 (one vendor claim plus eleven template claims).
    let stats: Stats = client.get_json("/stats").await.expect("GET /stats");
    assert_eq!(stats.head_seq, 12, "one vendor registration plus eleven template registrations");
    assert_eq!(stats.vendors, 1, "exactly one vendor namespace was claimed");
    assert_eq!(stats.templates, 11, "exactly eleven templates were registered");
    assert_eq!(stats.publishers, 1, "the whole set has a single publisher DID");
}

// ---------------------------------------------------------------------------
// 2. Feed paging.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn feed_paging_walks_the_whole_publisher_history() {
    let dir = common::TempDir::new("http-stack-b");
    let daemon = common::RegistryDaemon::start(dir.path());
    let client = RegistryClient::new(daemon.base_url()).expect("base_url is always http://host:port");
    assert!(client.healthy().await, "freshly spawned registryd did not answer /health");

    let did = common::publish_seed_over_http(&client).await;
    let manifest = common::seed_manifest();
    let manifest_templates = template_entries(&manifest);

    // Walk the feed from since=0 in pages of 5 using the returned `next`
    // cursor, until has_more says there is nothing left to fetch.
    let mut collected: Vec<FeedEntry> = Vec::new();
    let mut since = 0u64;
    let mut pages_fetched = 0;
    loop {
        let page: FeedPage = client
            .get_json(&format!("/publishers/{did}/feed?since={since}&limit=5"))
            .await
            .unwrap_or_else(|e| panic!("GET feed since={since} failed: {e}"));
        collected.extend(page.entries.iter().cloned());
        since = page.next;
        pages_fetched += 1;
        // A guard, not a spec requirement: if has_more never went false this
        // would otherwise spin forever instead of failing with a clear cause.
        assert!(pages_fetched < 20, "feed paging did not converge after {pages_fetched} pages");
        if !page.has_more {
            break;
        }
    }

    // Exactly 12 entries collected: one vendor claim plus eleven templates.
    assert_eq!(collected.len(), 12, "paging must yield all twelve feed entries, no more, no fewer");

    // seq values are exactly 1..=12 in ascending order: no gap, duplicate, or
    // reorder introduced by paging across three requests.
    let seqs: Vec<u64> = collected.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=12).collect::<Vec<u64>>(), "the paged feed must reassemble into 1..=12 in order");

    // Entry 1 is the vendor claim.
    assert_eq!(collected[0].kind, RegistrationKind::Vendor, "the first feed entry must be the vendor claim");
    assert_eq!(
        collected[0].qualified_name, "inblockio",
        "the vendor claim's qualified name is the bare vendor name"
    );

    // Entries 2..=12 are the eleven templates, in manifest order, driven from
    // the manifest rather than a hardcoded name list.
    for (i, entry) in manifest_templates.iter().enumerate() {
        let name = entry["name"].as_str().expect("name");
        let feed_entry = &collected[i + 1];
        assert_eq!(feed_entry.kind, RegistrationKind::Template, "{name}'s feed entry must be kind template");
        assert_eq!(
            feed_entry.qualified_name,
            format!("inblockio/{name}"),
            "{name}'s feed entry has the wrong qualified name"
        );
    }

    // A poll at the head returns zero entries and does not rewind the cursor.
    let head_page: FeedPage = client
        .get_json(&format!("/publishers/{did}/feed?since=12"))
        .await
        .expect("GET feed at the head");
    assert!(head_page.entries.is_empty(), "a caught-up consumer must see zero new entries");
    assert_eq!(head_page.next, 12, "a caught-up consumer's cursor must not rewind");
    assert!(!head_page.has_more, "there is nothing more to fetch after seq 12");

    // An unknown DID returns an empty feed with 200, not an error.
    let unknown_response = client
        .get("/publishers/did:key:z6MkUnknownStranger/feed")
        .await
        .expect("GET feed for an unknown DID must reach the server");
    assert_eq!(
        unknown_response.status, 200,
        "an unknown publisher DID must not turn into an HTTP error"
    );
    let unknown_page: FeedPage = serde_json::from_str(&unknown_response.body)
        .expect("the unknown-DID feed response must still be a valid FeedPage");
    assert!(unknown_page.entries.is_empty(), "an unknown DID has no history for the feed to return");
}

// ---------------------------------------------------------------------------
// 3. Restart survival and clean shutdown.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_preserves_state_and_shuts_down_cleanly() {
    let dir = common::TempDir::new("http-stack-c");
    let mut daemon = common::RegistryDaemon::start(dir.path());
    let client = RegistryClient::new(daemon.base_url()).expect("base_url is always http://host:port");
    assert!(client.healthy().await, "freshly spawned registryd did not answer /health");

    let did = common::publish_seed_over_http(&client).await;

    let stats_before: Stats = client.get_json("/stats").await.expect("GET /stats before restart");
    let feed_before: FeedPage = client
        .get_json(&format!("/publishers/{did}/feed?since=0&limit=100"))
        .await
        .expect("GET feed before restart");
    assert_eq!(feed_before.entries.len(), 12, "the full feed must be twelve entries before restart");

    // The port changes on restart, by design (see tests/common/mod.rs). A
    // client built from the new base_url is required to prove the following
    // calls are actually reaching the new process, not a lingering old one.
    daemon.restart();
    let client = RegistryClient::new(daemon.base_url()).expect("base_url is always http://host:port");
    assert!(client.healthy().await, "the restarted daemon did not answer /health");

    // Stats are rebuilt from the persisted feed on startup, so they must come
    // back identical.
    let stats_after: Stats = client.get_json("/stats").await.expect("GET /stats after restart");
    assert_eq!(stats_after, stats_before, "stats must be identical after a restart, the feed is durable");

    // A consumer cursor parked at seq 9 must resume at exactly entries 10,
    // 11, 12 after the restart, proving the sequence numbers themselves
    // survived, not merely the count.
    let tail: FeedPage = client
        .get_json(&format!("/publishers/{did}/feed?since=9"))
        .await
        .expect("GET feed tail after restart");
    assert_eq!(tail.entries.len(), 3, "a cursor at seq 9 must still see exactly the last three entries");
    let tail_seqs: Vec<u64> = tail.entries.iter().map(|e| e.seq).collect();
    assert_eq!(tail_seqs, vec![10, 11, 12], "the surviving cursor must resume at exactly entries 10, 11, 12");

    // Name resolution survives the restart with the same answer.
    let resolution: Resolution = client
        .get_json("/resolve/inblockio/audit_artifact")
        .await
        .expect("resolve inblockio/audit_artifact after restart");

    let manifest = common::seed_manifest();
    let expected_hash = template_entries(&manifest)
        .iter()
        .find(|e| e["name"] == "audit_artifact")
        .and_then(|e| e["template_hash"].as_str())
        .expect("manifest has an audit_artifact template registration")
        .to_string();
    assert_eq!(
        resolution.template_hash, expected_hash,
        "inblockio/audit_artifact must resolve to the same hash after a restart"
    );

    // A definition body still serves for one of the templates after restart.
    let served_def = client
        .get_raw(&format!("/definitions/{expected_hash}"))
        .await
        .expect("GET /definitions after restart must still serve the body");
    assert!(!served_def.is_empty(), "the served definition body must not be empty after restart");

    // Clean shutdown: the process must exit 0 on SIGTERM, not require a kill.
    let status = daemon.stop();
    assert!(status.success(), "registryd must exit cleanly on SIGTERM, a killed daemon is a shutdown bug");
}

// ---------------------------------------------------------------------------
// 4. HTTP-level error behaviour.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_error_responses_carry_the_right_status_and_code() {
    let dir = common::TempDir::new("http-stack-d");
    let daemon = common::RegistryDaemon::start(dir.path());
    let client = RegistryClient::new(daemon.base_url()).expect("base_url is always http://host:port");
    assert!(client.healthy().await, "freshly spawned registryd did not answer /health");

    common::publish_seed_over_http(&client).await;
    let manifest = common::seed_manifest();
    let manifest_templates = template_entries(&manifest);
    let first_entry = &manifest_templates[0];

    // ---- posting the same template registration twice: 409 DUPLICATE_TEMPLATE
    let tree_file = first_entry["tree_file"].as_str().expect("tree_file");
    let body = std::fs::read_to_string(common::seed_dir().join(tree_file)).expect("read seed tree");

    let response = client
        .post("/templates", body)
        .await
        .expect("re-POST /templates must reach the server, not fail at the transport level");
    assert_eq!(
        response.status, 409,
        "registering the same template hash a second time must be rejected as a conflict"
    );
    assert_error_code(&response.body, "DUPLICATE_TEMPLATE", "duplicate template registration");

    // ---- GET /vendors/nope: 404 NOT_FOUND
    let response = client
        .get("/vendors/nope")
        .await
        .expect("GET /vendors/nope must reach the server");
    assert_eq!(response.status, 404, "an unregistered vendor namespace must 404");
    assert_error_code(&response.body, "NOT_FOUND", "unknown vendor lookup");

    // ---- GET /definitions/0x + 64 zeros: 404, nothing is stored under it
    let zero_hash = format!("0x{}", "0".repeat(64));
    let response = client
        .get(&format!("/definitions/{zero_hash}"))
        .await
        .expect("GET /definitions/{zero_hash} must reach the server");
    assert_eq!(response.status, 404, "a hash nobody ever stored a definition under must 404");
    assert_error_code(&response.body, "NOT_FOUND", "unstored definition hash lookup");

    // ---- POST /definitions with valid JSON that is not a template: 400
    let response = client
        .post("/definitions", r#"{"hello":"world"}"#.to_string())
        .await
        .expect("POST /definitions with non-template JSON must reach the server");
    assert_eq!(
        response.status, 400,
        "a body that parses as JSON but not as a template definition must be rejected as malformed"
    );

    // ---- POST /definitions with a well-formed but unregistered template: 404 DEFINITION_NOT_REGISTERED
    //
    // Take a seed definition, flip its nonce to a different 32-hex-char
    // value, and re-serialize. That changes the hash (the nonce is part of
    // what gets hashed) while keeping the body a well-formed template.
    let def_file = first_entry["definition_file"].as_str().expect("definition_file");
    let seed_def = std::fs::read_to_string(common::seed_dir().join(def_file)).expect("read seed definition");
    let mut value: serde_json::Value = serde_json::from_str(&seed_def).expect("seed definition parses as JSON");

    let original_nonce = value["nonce"]
        .as_str()
        .expect("seed definition has a nonce field")
        .to_string();
    let all_zero_nonce = format!("0x{}", "0".repeat(32));
    let different_nonce = if original_nonce.eq_ignore_ascii_case(&all_zero_nonce) {
        format!("0x{}", "f".repeat(32))
    } else {
        all_zero_nonce
    };
    assert_ne!(different_nonce, original_nonce, "the whole point of this fixture is a nonce that differs");
    value["nonce"] = serde_json::Value::String(different_nonce);
    let mutated_def = serde_json::to_string(&value).expect("re-serialize the mutated definition");

    let response = client
        .post("/definitions", mutated_def)
        .await
        .expect("POST /definitions with an unregistered hash must reach the server");
    assert_eq!(
        response.status, 404,
        "a well-formed template definition whose hash nobody registered must 404"
    );
    assert_error_code(&response.body, "DEFINITION_NOT_REGISTERED", "unregistered definition hash upload");
}
