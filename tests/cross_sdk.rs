//! Cross-SDK compatibility: prove the vendored registration templates are the
//! same types the full `aqua-rs-sdk` ships as built-ins.
//!
//! # Why every test here is `#[ignore]`d
//!
//! This crate depends on `aqua-rs-sdk-core` at runtime, on purpose. The full
//! `aqua-rs-sdk` is a dev-dependency used only by this file, and it drags in
//! `wasmi`, `jsonschema`, blockchain and web hosts, and a trust store. Building
//! it roughly triples a cold `cargo test`. Running these on every `cargo test`
//! would tax everybody for a check that only matters when someone touches
//! `src/templates/*.json`.
//!
//! Run them explicitly:
//!
//! ```text
//! cargo test --test cross_sdk -- --ignored --nocapture
//! ```
//!
//! Run them whenever a vendored template file changes, and in CI on a schedule.
//! A failure here means the vendored copies drifted from the SDK, which means
//! this registry is minting a different type under the same name, which means
//! every tree registered against it is unverifiable by SDK users. There is no
//! benign failure mode.

use aqua_rs_sdk::schema::template::BuiltInTemplate as SdkBuiltInTemplate;
use aqua_rs_sdk::schema::templates::{
    AliasRegistration as SdkAlias, TemplateRegistration as SdkTemplate,
    VendorRegistration as SdkVendor,
};

use aqua_template_registry::model::{RegistrationKind, TemplateRegistration};
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::templates;

/// Strip the `0x1620` multihash prefix (SHA3-256, 32 bytes) that core's
/// `RevisionLink` carries, leaving the bare digest the SDK stores in
/// `TEMPLATE_LINK`.
fn bare_digest(link_hex: &str) -> [u8; 32] {
    let body = link_hex.strip_prefix("0x1620").expect("sha3-256 multihash");
    let bytes = hex::decode(body).expect("hex");
    bytes.try_into().expect("32 bytes")
}

// ---------------------------------------------------------------------------
// 1. The JSON files are byte-identical.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires the full aqua-rs-sdk; run with --ignored"]
fn vendored_json_is_byte_identical_to_the_sdk() {
    assert_eq!(
        templates::VENDOR_REGISTRATION_JSON,
        SdkVendor::TEMPLATE_JSON,
        "vendor_registration.json drifted from the SDK copy"
    );
    assert_eq!(
        templates::TEMPLATE_REGISTRATION_JSON,
        SdkTemplate::TEMPLATE_JSON,
        "template_registration.json drifted from the SDK copy"
    );
    assert_eq!(
        templates::ALIAS_REGISTRATION_JSON,
        SdkAlias::TEMPLATE_JSON,
        "alias_registration.json drifted from the SDK copy"
    );
}

// ---------------------------------------------------------------------------
// 2. The hashes we compute equal the SDK's TEMPLATE_LINK constants.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires the full aqua-rs-sdk; run with --ignored"]
fn vendored_hashes_equal_sdk_template_links() {
    let ours_vendor = bare_digest(&templates::link(RegistrationKind::Vendor).to_string());
    assert_eq!(
        ours_vendor,
        SdkVendor::TEMPLATE_LINK,
        "vendor-registration type identity differs from the SDK"
    );

    let ours_template = bare_digest(&templates::link(RegistrationKind::Template).to_string());
    assert_eq!(
        ours_template,
        SdkTemplate::TEMPLATE_LINK,
        "template-registration type identity differs from the SDK"
    );

    let ours_alias = bare_digest(&templates::link(RegistrationKind::Alias).to_string());
    assert_eq!(
        ours_alias,
        SdkAlias::TEMPLATE_LINK,
        "alias-registration type identity differs from the SDK"
    );

    println!("vendor   = 0x{}", hex::encode(ours_vendor));
    println!("template = 0x{}", hex::encode(ours_template));
    println!("alias    = 0x{}", hex::encode(ours_alias));
}

// ---------------------------------------------------------------------------
// 3. Trees we build verify under the FULL SDK with no linked trees at all.
// ---------------------------------------------------------------------------

/// The strongest statement of compatibility available: build a registration the
/// way this crate does (core plus a vendored template handed over as a linked
/// tree), serialize it to wire JSON, and verify it with the full SDK, which
/// needs no linked tree because it has these templates built in. If the vendored
/// copies had drifted by one byte the SDK would not resolve the type and this
/// would fail with TEMPLATE_NOT_FOUND.
#[tokio::test]
#[ignore = "requires the full aqua-rs-sdk; run with --ignored"]
async fn registration_trees_verify_under_the_full_sdk() {
    let core_aquafier = aqua_rs_sdk_core::Aquafier::new();
    let key = PublisherKey::from_seed([42u8; 32]).expect("key");

    let vendor_tree = publisher::vendor_registration(&core_aquafier, &key, "acme", Some("ACME"))
        .await
        .expect("build vendor registration");

    let template_tree = publisher::template_registration(
        &core_aquafier,
        &key,
        TemplateRegistration {
            vendor: "acme".into(),
            name: "invoice".into(),
            template_hash: format!("0x{}", "ab".repeat(32)),
            supersedes: None,
            display_name: Some("Invoice".into()),
            description: None,
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await
    .expect("build template registration");

    let alias_tree = publisher::alias_registration(
        &core_aquafier,
        &key,
        "acme",
        "inv",
        &format!("0x{}", "ab".repeat(32)),
    )
    .await
    .expect("build alias registration");

    let sdk_aquafier = aqua_rs_sdk::Aquafier::new();

    for (label, tree) in [
        ("vendor", &vendor_tree),
        ("template", &template_tree),
        ("alias", &alias_tree),
    ] {
        // Cross the crate boundary through the wire format, which is the only
        // thing the two SDKs actually share.
        let wire = publisher::to_json(tree).expect("serialize");
        let sdk_tree: aqua_rs_sdk::schema::tree::Tree =
            serde_json::from_str(&wire).expect("the full SDK must parse our wire format");

        let result = sdk_aquafier
            .verify_aqua_tree(
                aqua_rs_sdk::schema::AquaTreeWrapper::new(sdk_tree, None, None),
                vec![],
            )
            .await
            .expect("verification ran");

        assert!(
            result.is_verified(),
            "{label} registration did not verify under the full SDK: {:?}",
            result.outcome
        );
        println!(
            "{label:9} verified under the full SDK: {:?}",
            result.outcome
        );
    }
}

// ---------------------------------------------------------------------------
// 4. The payload structs are wire-compatible with the SDK's.
// ---------------------------------------------------------------------------

/// Our payload structs are hand-written mirrors of the SDK's. Round-trip one
/// through the other in both directions so a field rename cannot slip through.
#[test]
#[ignore = "requires the full aqua-rs-sdk; run with --ignored"]
fn payload_structs_round_trip_through_the_sdk() {
    let ours = aqua_template_registry::model::VendorRegistration {
        vendor_name: "acme".into(),
        display_name: Some("ACME".into()),
        vendor_did: "did:key:z6MkExample".into(),
    };
    let json = serde_json::to_string(&ours).unwrap();
    let theirs: SdkVendor = serde_json::from_str(&json).expect("SDK parses our vendor payload");
    assert_eq!(theirs.vendor_name, ours.vendor_name);
    assert_eq!(theirs.vendor_did, ours.vendor_did);

    let ours = TemplateRegistration {
        vendor: "acme".into(),
        name: "invoice".into(),
        template_hash: format!("0x{}", "cd".repeat(32)),
        supersedes: Some(format!("0x{}", "ab".repeat(32))),
        display_name: None,
        description: Some("an invoice".into()),
        daemon_trigger: Some(true),
        file_dependency: None,
    };
    let json = serde_json::to_string(&ours).unwrap();
    let theirs: SdkTemplate = serde_json::from_str(&json).expect("SDK parses our template payload");
    assert_eq!(theirs.template_hash, ours.template_hash);
    assert_eq!(theirs.supersedes, ours.supersedes);
    assert_eq!(theirs.daemon_trigger, ours.daemon_trigger);

    let ours = aqua_template_registry::model::AliasRegistration {
        vendor: "acme".into(),
        alias_name: "inv".into(),
        target_hash: format!("0x{}", "ef".repeat(32)),
    };
    let json = serde_json::to_string(&ours).unwrap();
    let theirs: SdkAlias = serde_json::from_str(&json).expect("SDK parses our alias payload");
    assert_eq!(theirs.target_hash, ours.target_hash);
}
