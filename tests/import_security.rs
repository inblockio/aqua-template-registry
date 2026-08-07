//! The negative-path security suite for the consumer-side import gate
//! (`src/import.rs`).
//!
//! `src/import.rs` documents the chain a candidate registration must pass
//! before it enters a consumer's local store: cryptographic verification,
//! the publisher allow list, namespace ownership, the size and WASM checks,
//! the hash-binding check, and the pin check. Every test here proves one
//! link of that chain actually denies when it should, and asserts on the
//! specific `ImportRejection` variant the chain returns, not merely that
//! some error came back. The suite closes with a small set of positive
//! controls (the honest path, the store, and using an imported template as
//! a linked tree) so the whole thing proves the gate opens as well as
//! closes.
//!
//! Everything here calls `aqua_template_registry::import` directly. None of
//! it needs a running server, and none of it needs the `Registry` type:
//! `verify_vendor` and `verify_template` are the whole surface under test.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use aqua_rs_sdk_core::primitives::{Method, RevisionLink};
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::import::{
    verify_template, verify_vendor, ImportRejection, ImportStore,
};
use aqua_template_registry::model::{
    RegistrationPayload, TemplateRegistration, VendorRegistration,
};
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::templates;
use aqua_template_registry::trust::{ImportPolicy, PinMode, MAX_DEFINITION_BYTES};

// ---------------------------------------------------------------------------
// Test-local helpers
// ---------------------------------------------------------------------------

/// A unique, self-cleaning directory under the OS temp dir for a single test
/// to use. Uniqueness comes from the current process id plus a per-process
/// atomic counter, so parallel test threads never collide on the same path.
///
/// Mirrors the pattern in `tests/audit_set.rs`, defined locally rather than
/// shared, since this test binary must not depend on `tests/common`.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aqua-template-registry-import-security-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir for test");
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

/// Directory holding the real, committed definition bodies from the seed
/// set. Reusing these means the honest fixtures in this suite are real
/// template definitions, not hand-rolled stand-ins.
fn seed_definitions_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("seed/audit-set-v1/definitions")
}

fn read_seed_definition(file_name: &str) -> String {
    let path = seed_definitions_dir().join(file_name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The honest baseline body used by most of this suite: `signer_did`
/// (string) plus `created_at` (integer), nothing else required.
fn audit_artifact_body() -> String {
    read_seed_definition("audit_artifact.json")
}

/// A second, unrelated real definition, used wherever a test needs a body
/// that is well-formed but is definitely not the one a registration claims.
fn audit_user_prompt_body() -> String {
    read_seed_definition("audit_user_prompt.json")
}

/// Build and sign a vendor registration for `vendor_name`, owned by `key`,
/// and serialize it the way a publisher would submit it.
async fn signed_vendor(aquafier: &Aquafier, key: &PublisherKey, vendor_name: &str) -> String {
    let tree = publisher::vendor_registration(aquafier, key, vendor_name, Some("Test Vendor"))
        .await
        .expect("build and sign a vendor registration");
    publisher::to_json(&tree).expect("serialize the vendor registration tree")
}

/// Build and sign a template registration for `<vendor_name>/<template_name>`
/// whose `template_hash` is honestly `template_hash_of_definition(definition_body)`.
/// Returns the serialized tree alongside the hash it claims, since almost
/// every test needs both.
async fn signed_template(
    aquafier: &Aquafier,
    key: &PublisherKey,
    vendor_name: &str,
    template_name: &str,
    definition_body: &str,
) -> (String, String) {
    let template_hash =
        templates::template_hash_of_definition(definition_body).expect("hash the definition body");
    let tree = publisher::template_registration(
        aquafier,
        key,
        TemplateRegistration {
            vendor: vendor_name.to_string(),
            name: template_name.to_string(),
            template_hash: template_hash.clone(),
            supersedes: None,
            display_name: Some("Test Template".to_string()),
            description: Some(
                "A template registration built for the import security test suite.".to_string(),
            ),
            daemon_trigger: None,
            file_dependency: None,
        },
    )
    .await
    .expect("build and sign a template registration");
    let json = publisher::to_json(&tree).expect("serialize the template registration tree");
    (json, template_hash)
}

// ---------------------------------------------------------------------------
// 1-2. The identity gate: internal consistency is not identity.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_but_non_whitelisted_publisher_is_rejected() {
    // Security property: a vendor registration that is perfectly
    // self-certifying (correctly signed, names its own signer) is still not
    // enough to import from. allowed_publishers is a separate, out-of-band
    // decision the consumer makes, and nothing about a well-formed
    // registration can satisfy it on its own. This is the central control
    // this whole module exists for.
    let aquafier = Aquafier::new();
    let stranger = PublisherKey::from_seed([1u8; 32]).unwrap();
    let someone_else = PublisherKey::from_seed([2u8; 32]).unwrap();

    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(someone_else.did());

    let vendor_json = signed_vendor(&aquafier, &stranger, "acme").await;
    let err = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect_err("the stranger's key is not on the allow list");

    match err.clone() {
        ImportRejection::PublisherNotAllowed { did, allowed } => {
            assert_eq!(did, stranger.did());
            assert_eq!(allowed, 1, "exactly one other publisher is allowed");
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "PUBLISHER_NOT_ALLOWED");
}

#[tokio::test]
async fn empty_trust_config_imports_nothing() {
    // Security property: there is no trust-on-first-use. An empty policy
    // allows no publisher, so even the very first registration this policy
    // ever sees, from a key nobody has flagged as bad, is refused exactly
    // like any other unlisted key. Seeing something once is never treated
    // as a reason to trust it.
    let aquafier = Aquafier::new();
    let first_ever_publisher = PublisherKey::from_seed([20u8; 32]).unwrap();
    let policy = ImportPolicy::empty();

    let vendor_json = signed_vendor(&aquafier, &first_ever_publisher, "acme").await;
    let err = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect_err("an empty policy allows nobody, including a first-ever publisher");

    assert!(
        matches!(err, ImportRejection::PublisherNotAllowed { allowed: 0, .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "PUBLISHER_NOT_ALLOWED");
    assert_eq!(
        policy.publisher_count(),
        0,
        "the policy truly has nobody allowed"
    );
}

// ---------------------------------------------------------------------------
// 3. The hash-binding check: a claim is not the bytes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_definition_body_is_rejected() {
    // Security property: a template registration is a signed claim that a
    // name means a hash. It says nothing about whether the bytes a consumer
    // actually has are the bytes that produce that hash, so the gate must
    // rehash whatever body it was given and compare, never trust the claim
    // by itself. Checked here in two ways: a wholesale body substitution,
    // and a single changed byte in an otherwise correct body.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([3u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let honest_body = audit_artifact_body();
    let (template_json, claimed_hash) =
        signed_template(&aquafier, &key, "acme", "artifact", &honest_body).await;

    // Variant 1: a completely different, but still well-formed, definition
    // body. The registration still claims the honest hash.
    let other_body = audit_user_prompt_body();
    let err = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &other_body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("a different definition body does not hash to the claimed template_hash");
    match &err {
        ImportRejection::HashMismatch {
            claimed, actual, ..
        } => {
            assert_eq!(claimed, &claimed_hash);
            assert_ne!(claimed, actual, "claimed and actual hashes must differ");
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "HASH_MISMATCH");

    // Variant 2: a single digit changed in the local_timestamp of an
    // otherwise correct body. Same length, one byte different. This is the
    // subtler case: not a substitution, a one-character edit.
    let mutated_body = honest_body.replacen("1747526400", "1747526401", 1);
    assert_ne!(
        mutated_body, honest_body,
        "the mutation must actually change the body"
    );
    assert_eq!(
        mutated_body.len(),
        honest_body.len(),
        "only a digit changed, the length must be identical"
    );

    let err2 = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &mutated_body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("a one-byte mutation must also fail the hash check");
    match &err2 {
        ImportRejection::HashMismatch {
            claimed, actual, ..
        } => {
            assert_eq!(claimed, &claimed_hash);
            assert_ne!(claimed, actual);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err2.code(), "HASH_MISMATCH");
}

// ---------------------------------------------------------------------------
// 4. The WASM refusal: unconditional, not a policy knob.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wasm_carrying_definition_is_rejected() {
    // Security property: a definition body that declares a `verification`
    // (WASM) section is refused unconditionally. This is not something a
    // policy can opt into: the check runs even though the publisher here is
    // whitelisted and the registered hash honestly matches the body's own
    // hash, exactly the conditions under which everything else would be
    // accepted.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([4u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    // A minimal but structurally valid `verification` section: present and
    // non-null is all `carries_wasm` requires, and keeping it well-formed
    // means the hash step underneath would otherwise have succeeded too.
    let mut body: serde_json::Value =
        serde_json::from_str(&audit_artifact_body()).expect("seed definition parses as JSON");
    body["verification"] = serde_json::json!({ "computations": [] });
    let wasm_body =
        serde_json::to_string(&body).expect("re-serialize the WASM-carrying definition");

    let (template_json, _hash) =
        signed_template(&aquafier, &key, "acme", "artifact", &wasm_body).await;

    let err = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &wasm_body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("a verification (WASM) section must be refused regardless of everything else");

    assert!(
        matches!(err, ImportRejection::CarriesWasm { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "CARRIES_WASM");
}

// ---------------------------------------------------------------------------
// 5-6. The pin check: bootstrapping a new name versus substituting a pinned one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unpinned_template_is_rejected_in_pinned_only_mode() {
    // Security property: being on the allow list is not the same as being
    // pinned for a specific name. PinnedOnly refuses an unpinned name even
    // from an allowed publisher, since PinnedOnly can never itself widen
    // what gets imported. ApproveNew, run against the exact same inputs,
    // accepts it and reports the new pin, which is the one deliberate way
    // this module's trust surface is allowed to grow.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([5u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let body = audit_artifact_body();
    let (template_json, _hash) = signed_template(&aquafier, &key, "acme", "artifact", &body).await;

    let err = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::PinnedOnly,
    )
    .await
    .expect_err("no pin exists yet, and PinnedOnly never adds one");
    assert!(
        matches!(err, ImportRejection::NotPinned { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "NOT_PINNED");

    let accepted = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect("ApproveNew accepts a not-yet-pinned template from an allowed publisher");
    assert!(
        accepted.template.newly_pinned,
        "ApproveNew must report that this pin is new"
    );
}

#[tokio::test]
async fn same_name_different_hash_is_rejected_in_both_modes() {
    // Security property: ApproveNew may bootstrap a pin for a name that has
    // none, but it must never let a later registration replace an existing
    // pin for that name with a different hash. A publisher (or an attacker
    // holding their key) offering a different hash for a name a consumer
    // already trusts is exactly the substitution attack pinning exists to
    // stop, so both modes must refuse it identically. ApproveNew approves
    // new names, never substitutions of pinned ones.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([6u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let body_a = audit_artifact_body();
    let (template_json_a, hash_a) =
        signed_template(&aquafier, &key, "acme", "artifact", &body_a).await;

    let accepted_a = verify_template(
        &aquafier,
        &vendor,
        &template_json_a,
        &body_a,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect("first import pins hash A honestly");
    policy
        .approve(&accepted_a.template.qualified_name, &hash_a)
        .expect("record the pin the way a real caller would after an ApproveNew import");

    // A different body, registered under the SAME qualified name, hashes to
    // a different value.
    let body_b = audit_user_prompt_body();
    let (template_json_b, hash_b) =
        signed_template(&aquafier, &key, "acme", "artifact", &body_b).await;
    assert_ne!(
        hash_a, hash_b,
        "the two bodies must hash differently for this test to mean anything"
    );

    let err_pinned_only = verify_template(
        &aquafier,
        &vendor,
        &template_json_b,
        &body_b,
        &policy,
        PinMode::PinnedOnly,
    )
    .await
    .expect_err("a different hash for a pinned name must be refused in PinnedOnly");
    assert!(
        matches!(err_pinned_only, ImportRejection::PinMismatch { .. }),
        "got {err_pinned_only:?}"
    );
    assert_eq!(err_pinned_only.code(), "PIN_MISMATCH");

    let err_approve_new = verify_template(
        &aquafier,
        &vendor,
        &template_json_b,
        &body_b,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("ApproveNew must not override a pin mismatch either");
    assert!(
        matches!(err_approve_new, ImportRejection::PinMismatch { .. }),
        "got {err_approve_new:?}"
    );
    assert_eq!(err_approve_new.code(), "PIN_MISMATCH");
}

// ---------------------------------------------------------------------------
// 7. The size cap.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversized_definition_is_rejected() {
    // Security property: a definition body over the hard byte cap is
    // refused by size alone, before it is parsed as a template or hashed.
    // A body that is merely huge cannot force expensive parsing work on a
    // consumer.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([7u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    // Pad a real, parseable definition past the cap. The padding lives
    // inside the free-form "schema" value, so the document still parses as
    // a well-formed template.
    let mut body: serde_json::Value =
        serde_json::from_str(&audit_artifact_body()).expect("seed definition parses as JSON");
    let padding = "x".repeat(MAX_DEFINITION_BYTES + 4096);
    body["schema"]["padding_for_the_size_test"] = serde_json::json!(padding);
    let oversized_body = serde_json::to_string(&body).expect("re-serialize the padded definition");
    assert!(
        oversized_body.len() > MAX_DEFINITION_BYTES,
        "the padded body must actually exceed the cap"
    );

    let (template_json, _hash) =
        signed_template(&aquafier, &key, "acme", "artifact", &oversized_body).await;

    let err = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &oversized_body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("an oversized definition body must be refused");

    match err.clone() {
        ImportRejection::TooLarge { bytes, max, .. } => {
            assert_eq!(bytes, oversized_body.len());
            assert_eq!(max, MAX_DEFINITION_BYTES);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "TOO_LARGE");
}

// ---------------------------------------------------------------------------
// 8-9. Namespace ownership and self-certification.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn template_signed_by_someone_other_than_the_namespace_owner_is_rejected() {
    // Security property: writing into a namespace requires owning that
    // specific namespace, not merely being allowed to publish at all. Key B
    // is whitelisted too, which proves the check is namespace ownership and
    // not a second, redundant allow-list lookup: without key B also being
    // allowed, a WrongSigner rejection could be mistaken for a
    // PublisherNotAllowed rejection that happened to fire at a different
    // step.
    let aquafier = Aquafier::new();
    let key_a = PublisherKey::from_seed([8u8; 32]).unwrap();
    let key_b = PublisherKey::from_seed([9u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key_a.did());
    policy.allow_publisher(key_b.did());

    let vendor_json = signed_vendor(&aquafier, &key_a, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("key A owns acme and is whitelisted");

    let body = audit_artifact_body();
    // Key B signs a template registration into the same "acme" namespace
    // that key A owns.
    let (template_json, _hash) =
        signed_template(&aquafier, &key_b, "acme", "artifact", &body).await;

    let err = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::ApproveNew,
    )
    .await
    .expect_err("key B does not own the acme namespace, however allowed it otherwise is");
    assert!(
        matches!(err, ImportRejection::WrongSigner { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "WRONG_SIGNER");
}

#[tokio::test]
async fn vendor_registration_claiming_another_did_is_rejected() {
    // Security property: a vendor registration is only trustworthy if it is
    // self-certifying, signed by the very DID it names. Key B signing a
    // payload that claims key A's DID must be refused, and this check runs
    // before the allow list is even consulted: a registration that fails
    // self-certification is rejected regardless of whether either key
    // happens to be allowed.
    let aquafier = Aquafier::new();
    let key_a = PublisherKey::from_seed([10u8; 32]).unwrap();
    let key_b = PublisherKey::from_seed([11u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key_a.did());
    policy.allow_publisher(key_b.did());

    // Build the payload by hand: vendor_did names key A, but key B signs it.
    let payload = RegistrationPayload::Vendor(VendorRegistration {
        vendor_name: "acme".to_string(),
        display_name: None,
        vendor_did: key_a.did().to_string(),
    });
    let tree = publisher::build(&aquafier, &key_b, &payload)
        .await
        .expect("build a vendor registration signed by key B, naming key A's DID");
    let json = publisher::to_json(&tree).expect("serialize the forged vendor registration");

    let err = verify_vendor(&aquafier, &json, &policy)
        .await
        .expect_err("signer (key B) does not match the claimed vendor_did (key A)");
    assert!(
        matches!(err, ImportRejection::NotSelfCertifying { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "NOT_SELF_CERTIFYING");
}

// ---------------------------------------------------------------------------
// 10. Cryptographic integrity of the registration tree itself.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_registration_tree_does_not_verify() {
    // Security property: the registration tree's signature covers its own
    // payload bytes. Any post-signing edit, however small, must make the
    // tree fail cryptographic verification rather than being accepted with
    // a silently different claim.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([12u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let honest_json = signed_vendor(&aquafier, &key, "acme").await;
    let needle = "\"vendor_name\":\"acme\"";
    assert!(
        honest_json.contains(needle),
        "expected to find the vendor_name field verbatim in the serialized tree"
    );

    let tampered_json = honest_json.replacen(needle, "\"vendor_name\":\"acmex\"", 1);
    assert_ne!(tampered_json, honest_json);

    let err = verify_vendor(&aquafier, &tampered_json, &policy)
        .await
        .expect_err("a tampered registration tree must not verify");
    assert!(
        matches!(err, ImportRejection::NotVerified(_)),
        "got {err:?}"
    );
    assert_eq!(err.code(), "NOT_VERIFIED");
}

// ---------------------------------------------------------------------------
// 11-13. Positive controls: the gate opens, the store holds what it verified,
// and an imported template is usable.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn honest_template_from_a_pinned_publisher_imports() {
    // Security property, positive control: when every check the gate
    // enforces is satisfied honestly, the import proceeds and the store
    // holds exactly what was verified, byte for byte. Proves the gate
    // opens, not merely that it closes.
    let dir = TempDir::new("happy-path");
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([13u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let body = audit_artifact_body();
    let (template_json, hash) = signed_template(&aquafier, &key, "acme", "artifact", &body).await;
    policy
        .approve("acme/artifact", &hash)
        .expect("pin the honest hash ahead of import");

    let accepted = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::PinnedOnly,
    )
    .await
    .expect("every check passes honestly");
    assert!(
        !accepted.template.newly_pinned,
        "the hash was already pinned before this import, so it is not newly pinned"
    );

    let store = ImportStore::open(dir.path()).expect("open the import store");
    store
        .insert(&accepted)
        .expect("insert the accepted candidate");

    assert!(
        store.contains(&hash),
        "the store must report the hash as present"
    );

    let stored_definition = store.definition(&hash).expect("read the definition back");
    assert_eq!(
        stored_definition, body,
        "the stored body must be byte-identical"
    );

    let record = store.record(&hash).expect("read the record back");
    assert_eq!(record.qualified_name, "acme/artifact");
    assert_eq!(record.publisher_did, key.did());

    let stored_registration = store
        .registration(&hash)
        .expect("read the registration back");
    assert_eq!(
        stored_registration, template_json,
        "the registration must be stored verbatim"
    );

    let hashes = store.hashes().expect("list every imported hash");
    assert_eq!(hashes.len(), 1, "exactly one hash has been imported");
    assert_eq!(hashes[0].to_ascii_lowercase(), hash.to_ascii_lowercase());
}

#[tokio::test]
async fn import_store_detects_a_tampered_definition_on_read() {
    // Security property: the store re-hashes a definition body every time
    // it is read and compares the result against the hash the file is
    // keyed by. Local corruption or tampering after import must therefore
    // surface as an error at read time, never be handed to an application
    // as a trusted body just because it once passed the import gate.
    let dir = TempDir::new("tamper-on-read");
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([14u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let body = audit_artifact_body();
    let (template_json, hash) = signed_template(&aquafier, &key, "acme", "artifact", &body).await;
    policy
        .approve("acme/artifact", &hash)
        .expect("pin the honest hash ahead of import");

    let accepted = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::PinnedOnly,
    )
    .await
    .expect("every check passes honestly");

    let store = ImportStore::open(dir.path()).expect("open the import store");
    store
        .insert(&accepted)
        .expect("insert the accepted candidate");

    // Overwrite the stored definition file with a different, still
    // well-formed, template definition body.
    let other_body = audit_user_prompt_body();
    assert_ne!(other_body, body);
    let file_key = format!("{}.json", hash.to_ascii_lowercase());
    let path = dir.path().join("templates").join(&file_key);
    std::fs::write(&path, &other_body).expect("overwrite the stored definition on disk");

    let err = store
        .definition(&hash)
        .expect_err("the file no longer hashes to its own storage key");
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("hash"),
        "the error should mention the hash mismatch, got: {message}"
    );

    let tree_err = store
        .template_tree(&hash)
        .expect_err("template_tree goes through the same verify-on-read guard");
    assert!(
        tree_err.to_string().to_lowercase().contains("hash"),
        "got: {tree_err}"
    );
}

#[tokio::test]
async fn imported_template_works_as_a_linked_tree() {
    // Security property, positive control completing the story: an
    // imported template is not just inert bytes on disk. It resolves as a
    // usable template type when handed to core as a linked tree, which is
    // the entire point of importing: an application can create objects of
    // this type and any verifier can resolve them without the template
    // being built into their own SDK.
    let dir = TempDir::new("linked-tree");
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([15u8; 32]).unwrap();
    let mut policy = ImportPolicy::empty();
    policy.allow_publisher(key.did());

    let vendor_json = signed_vendor(&aquafier, &key, "acme").await;
    let vendor = verify_vendor(&aquafier, &vendor_json, &policy)
        .await
        .expect("vendor is whitelisted and self-certifying");

    let body = audit_artifact_body();
    let (template_json, hash) = signed_template(&aquafier, &key, "acme", "artifact", &body).await;
    policy
        .approve("acme/artifact", &hash)
        .expect("pin the honest hash ahead of import");

    let accepted = verify_template(
        &aquafier,
        &vendor,
        &template_json,
        &body,
        &policy,
        PinMode::PinnedOnly,
    )
    .await
    .expect("every check passes honestly");

    let store = ImportStore::open(dir.path()).expect("open the import store");
    store
        .insert(&accepted)
        .expect("insert the accepted candidate");

    // Turn the bare `0x<64hex>` template hash into the RevisionLink core
    // needs in order to create an object of this type.
    let bare = hash
        .strip_prefix("0x")
        .expect("template hashes are 0x-prefixed");
    let bytes = hex::decode(bare).expect("64 hex digits decode to exactly 32 bytes");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let link = RevisionLink::from_bytes(arr);

    // audit_artifact's schema requires signer_did (string) and created_at
    // (integer); nothing else.
    let payload = serde_json::json!({
        "signer_did": key.did(),
        "created_at": 1_747_526_400i64,
    });

    let unsigned = aquafier
        .create_object(link, None, payload, Some(Method::Scalar))
        .expect("create an object of the imported template's type");
    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(unsigned, None, None),
            &key.credentials(),
            None,
            None,
        )
        .await
        .expect("sign the object");

    let linked = store
        .linked_tree(&hash)
        .expect("the imported template as a linked tree");
    let result = aquafier
        .verify_aqua_tree_with_linked_trees(
            AquaTreeWrapper::new(signed.aqua_tree, None, None),
            vec![linked],
            vec![],
        )
        .await
        .expect("verification ran to completion");
    assert!(
        result.is_verified(),
        "an object of the imported type must verify: {:?}",
        result.outcome
    );
}
