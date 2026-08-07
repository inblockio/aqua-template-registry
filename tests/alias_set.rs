//! Replaying `seed/audit-aliases-v1` on top of `seed/audit-set-v1`.
//!
//! The aliases are a second, additive seed set rather than extra files inside
//! the first one. That is not tidiness: `audit-set-v1`'s twelve signed trees
//! and its feed head are published bytes, and its head commits to exactly
//! twelve entries. Adding eleven aliases to that directory would have made the
//! committed head cover a prefix of a longer feed, which is legal but means the
//! shipped head no longer describes the shipped set.
//!
//! So the invariant this file exists to hold is: the old set and its old head
//! keep working untouched, and the new head covers both.

mod common;

use std::path::{Path, PathBuf};

use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::feedhead;
use aqua_template_registry::httpclient::RegistryClient;
use aqua_template_registry::import::ImportStore;
use aqua_template_registry::subscribe::Subscriber;
use aqua_template_registry::trust::{ImportPolicy, PinMode};
use aqua_template_registry::Registry;

use common::{RegistryDaemon, TempDir};

fn alias_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("seed/audit-aliases-v1")
}

fn alias_manifest() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(alias_dir().join("manifest.json")).unwrap())
        .expect("alias manifest parses")
}

/// Replay both seed sets into a registry through the library API.
async fn replay_both(registry: &Registry) {
    let base = common::seed_manifest();
    for entry in base["registrations"].as_array().unwrap() {
        let body =
            std::fs::read_to_string(common::seed_dir().join(entry["tree_file"].as_str().unwrap()))
                .unwrap();
        match entry["kind"].as_str().unwrap() {
            "vendor" => registry.submit_vendor(&body).await.unwrap(),
            "template" => registry.submit_template(&body).await.unwrap(),
            other => panic!("unexpected {other}"),
        };
    }

    let aliases = alias_manifest();
    for entry in aliases["registrations"].as_array().unwrap() {
        let body = std::fs::read_to_string(alias_dir().join(entry["tree_file"].as_str().unwrap()))
            .unwrap();
        let receipt = registry
            .submit_alias(&body)
            .await
            .unwrap_or_else(|e| panic!("{} rejected: {e}", entry["tree_file"]));
        assert_eq!(receipt.seq, entry["seq"].as_u64().unwrap());
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_alias_set_replays_and_every_short_name_resolves() {
    let dir = TempDir::new("alias-replay");
    let registry = Registry::open(dir.path()).expect("open");
    replay_both(&registry).await;

    let stats = registry.stats();
    assert_eq!(
        stats.head_seq, 23,
        "twelve registrations plus eleven aliases"
    );
    assert_eq!(stats.templates, 11);
    assert_eq!(stats.aliases, 11, "one short name per audit template");
    assert_eq!(stats.vendors, 1);

    let manifest = alias_manifest();
    for entry in manifest["registrations"].as_array().unwrap() {
        let alias = entry["alias_name"].as_str().unwrap();
        let target_name = entry["targets"].as_str().unwrap();
        let target_hash = entry["target_hash"].as_str().unwrap();

        // The short name resolves.
        let short = registry
            .resolve("inblockio", alias)
            .unwrap_or_else(|e| panic!("inblockio/{alias} does not resolve: {e}"));
        assert_eq!(short.template_hash, target_hash);
        assert_eq!(
            short.via,
            aqua_template_registry::model::ResolutionVia::Alias
        );

        // And it resolves to the same place as the long name, which is the
        // only property an alias actually has to have.
        let long = registry.resolve("inblockio", target_name).unwrap();
        assert_eq!(
            short.template_hash, long.template_hash,
            "inblockio/{alias} and inblockio/{target_name} must be the same template"
        );
        assert_eq!(
            long.via,
            aqua_template_registry::model::ResolutionVia::Template
        );
    }

    // Spot check the names a human would actually type.
    for (short, long) in [
        ("prompt", "audit_user_prompt"),
        ("thinking", "audit_agent_thinking"),
        ("tool_call", "audit_agent_tool_call"),
        ("response", "audit_agent_response"),
    ] {
        assert_eq!(
            registry.resolve("inblockio", short).unwrap().template_hash,
            registry.resolve("inblockio", long).unwrap().template_hash,
        );
    }
}

/// The published head for the original set must keep verifying after the
/// aliases extend the feed, because a head covers a prefix. If this broke, the
/// aliases would have retroactively invalidated something already published.
#[tokio::test]
async fn the_original_head_still_verifies_over_the_longer_feed() {
    let dir = TempDir::new("alias-oldhead");
    let registry = Registry::open(dir.path()).expect("open");
    replay_both(&registry).await;

    let aquafier = Aquafier::new();
    let tips =
        registry.publisher_entry_tips(common::seed_manifest()["publisher_did"].as_str().unwrap());
    assert_eq!(tips.len(), 23);

    let old_body = std::fs::read_to_string(common::seed_dir().join("13-feed-head.json")).unwrap();
    let old = feedhead::verify_head(&aquafier, &old_body, None)
        .await
        .expect("the original head still verifies as a tree");
    assert_eq!(old.head_seq, 12);
    feedhead::check_against_entries(&old, &tips)
        .expect("a head covers a prefix, so a longer feed must still satisfy it");

    let new_body = std::fs::read_to_string(
        alias_dir().join(alias_manifest()["feed_head"]["file"].as_str().unwrap()),
    )
    .unwrap();
    let new = feedhead::verify_head(&aquafier, &new_body, None)
        .await
        .expect("the new head verifies");
    assert_eq!(new.head_seq, 23, "the new head covers everything");
    feedhead::check_against_entries(&new, &tips).expect("and reproduces from the full feed");

    // The two heads are at different heights, so one does not supersede the
    // other by equivocation: a subscriber moving from 12 to 23 is progress.
    assert!(
        feedhead::check_against_previous(&new, Some(old.head_seq), Some(&old.merkle_root)).is_ok()
    );
    // Going the other way is a rollback.
    assert!(
        feedhead::check_against_previous(&old, Some(new.head_seq), Some(&new.merkle_root)).is_err()
    );
}

/// Over HTTP, with a real subscriber: aliases advance the cursor but import
/// nothing, because an alias registration carries no template to import.
#[tokio::test]
async fn a_subscriber_walks_past_aliases_without_importing_them() {
    let server_dir = TempDir::new("alias-http-server");
    let mut daemon = RegistryDaemon::start(&server_dir.join("data"));
    let client = RegistryClient::new(daemon.base_url()).unwrap();

    let did = common::publish_seed_over_http(&client).await;

    for entry in alias_manifest()["registrations"].as_array().unwrap() {
        let body = std::fs::read_to_string(alias_dir().join(entry["tree_file"].as_str().unwrap()))
            .unwrap();
        let response = client.post("/aliases", body).await.unwrap();
        assert_eq!(response.status, 201, "{}", response.body);
    }
    let head_body = std::fs::read_to_string(
        alias_dir().join(alias_manifest()["feed_head"]["file"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(client.post("/heads", head_body).await.unwrap().status, 201);

    let consumer = TempDir::new("alias-http-consumer");
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
    assert_eq!(
        report.head.as_ref().unwrap().verified().unwrap().head_seq,
        23,
        "the subscriber verifies the head that covers the aliases too"
    );
    assert_eq!(report.imported.len(), 11, "eleven templates, no aliases");
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert_eq!(report.cursor, 23, "the cursor walks past the aliases");
    assert_eq!(sub.store().hashes().unwrap().len(), 11);

    // Resolving a short name over HTTP gets the same hash as the long one.
    let short: serde_json::Value = client
        .get_json("/resolve/inblockio/prompt")
        .await
        .expect("short name resolves over HTTP");
    let long: serde_json::Value = client
        .get_json("/resolve/inblockio/audit_user_prompt")
        .await
        .unwrap();
    assert_eq!(short["template_hash"], long["template_hash"]);
    assert_eq!(short["via"], "alias");

    daemon.stop();
}
