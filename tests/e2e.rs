//! End-to-end tests.
//!
//! These go through the whole thing with real cryptography: an Ed25519 key
//! generated through `aqua-rs-sdk-core`, real signed Aqua trees built with
//! core's `Aquafier`, real verification against the vendored registration
//! templates, real files on disk, and (for the HTTP half) the real axum router.
//! Nothing is stubbed. If any of it were, the test would prove nothing about
//! whether a publisher can actually publish.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::error::RegistryError;
use aqua_template_registry::model::{RegistrationKind, TemplateRegistration};
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::{templates, Registry};

// ---------------------------------------------------------------------------
// helpers
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

fn hash_of(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
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

/// Register a vendor namespace and return the registry receipt.
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

// ---------------------------------------------------------------------------
// 1. The headline end-to-end path, through the library API.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_publish_subscribe_and_reverify() {
    let dir = TempDir::new("e2e-lib");
    let registry = Registry::open(dir.path()).expect("open registry");

    // A publisher generates an identity through core.
    let key = PublisherKey::generate().expect("generate key");
    assert!(key.did().starts_with("did:key:z6Mk"));

    // ---- claim a namespace ------------------------------------------------
    let vendor_tree = publisher::vendor_registration(
        registry.aquafier(),
        &key,
        "InBlock", // deliberately mixed case, must canonicalize to "inblock"
        Some("InBlock AG"),
    )
    .await
    .expect("build vendor registration");

    let receipt = registry
        .submit_vendor(&publisher::to_json(&vendor_tree).unwrap())
        .await
        .expect("vendor registration accepted");
    assert_eq!(receipt.seq, 1);
    assert_eq!(receipt.kind, RegistrationKind::Vendor);
    assert_eq!(receipt.publisher_did, key.did());
    assert_eq!(receipt.qualified_name, "inblock");

    // ---- register a template into it ---------------------------------------
    let payload_hash = hash_of(0xa1);
    let template_tree = publisher::template_registration(
        registry.aquafier(),
        &key,
        TemplateRegistration {
            vendor: "inblock".into(),
            name: "Email-Claim".into(),
            template_hash: payload_hash.clone(),
            supersedes: None,
            display_name: Some("Email Claim".into()),
            description: Some("Proves control of an email address.".into()),
            daemon_trigger: Some(false),
            file_dependency: None,
        },
    )
    .await
    .expect("build template registration");

    let receipt = registry
        .submit_template(&publisher::to_json(&template_tree).unwrap())
        .await
        .expect("template registration accepted");
    assert_eq!(receipt.seq, 2);
    assert_eq!(receipt.qualified_name, "inblock/email-claim");

    // ---- consumer side: resolve by name ------------------------------------
    let hit = registry.resolve("inblock", "email-claim").expect("resolve");
    assert_eq!(hit.template_hash, payload_hash);
    assert_eq!(hit.publisher_did.as_deref(), Some(key.did()));
    assert_eq!(hit.lineage, vec![payload_hash.clone()]);

    // Case-insensitive for Latin, per the name rules.
    let hit2 = registry.resolve("INBLOCK", "EMAIL-CLAIM").expect("resolve");
    assert_eq!(hit2.template_hash, payload_hash);

    // ---- consumer side: list by publisher DID (the reverse index) ----------
    let listed = registry.publisher_templates(key.did());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].template_hash, payload_hash);
    assert_eq!(listed[0].qualified_name, "inblock/email-claim");
    assert_eq!(listed[0].display_name.as_deref(), Some("Email Claim"));

    // A DID nobody registered under sees nothing.
    assert!(registry
        .publisher_templates("did:key:z6MkNobody")
        .is_empty());

    // ---- consumer side: fetch the full signed tree and re-verify it --------
    let stored = registry.template_tree(&payload_hash).expect("stored tree");
    let parsed: Tree = serde_json::from_str(&stored).expect("stored tree parses");

    // Signatures are intact: the tree still has its signature revision.
    let signature_count = parsed
        .revisions
        .values()
        .filter(|r| matches!(r, aqua_rs_sdk_core::schema::AnyRevision::Signature(_)))
        .count();
    assert_eq!(
        signature_count, 1,
        "the stored tree must keep its signature"
    );

    // And it re-verifies with core, using the same vendored templates.
    let aquafier = Aquafier::new();
    let result = aquafier
        .verify_aqua_tree_with_linked_trees(
            AquaTreeWrapper::new(parsed, None, None),
            templates::linked_trees(),
            vec![],
        )
        .await
        .expect("verification ran");
    assert!(
        result.is_verified(),
        "refetched tree must re-verify: {:?}",
        result.outcome
    );

    // The stored bytes are byte-identical to what was submitted.
    assert_eq!(
        stored,
        publisher::to_json(&template_tree).unwrap(),
        "the registry must store exactly the bytes the publisher signed"
    );
}

// ---------------------------------------------------------------------------
// 2. Subscription feed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn feed_is_monotonic_scoped_and_restart_safe() {
    let dir = TempDir::new("e2e-feed");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    let bob = PublisherKey::from_seed([2u8; 32]).unwrap();

    {
        let registry = Registry::open(dir.path()).expect("open");
        claim(&registry, &alice, "alice").await;
        claim(&registry, &bob, "bob").await;

        for (i, name) in ["one", "two", "three"].iter().enumerate() {
            let t = publisher::template_registration(
                registry.aquafier(),
                &alice,
                template_reg("alice", name, &hash_of(i as u8 + 1)),
            )
            .await
            .unwrap();
            registry
                .submit_template(&publisher::to_json(&t).unwrap())
                .await
                .expect("accepted");
        }

        // Alice's feed is hers alone: 1 vendor plus 3 templates.
        let page = registry.feed(alice.did(), 0, None);
        assert_eq!(page.entries.len(), 4);
        assert_eq!(page.since, 0);
        assert_eq!(page.next, 5); // seqs 1,3,4,5 (2 is bob's vendor claim)
        assert!(!page.has_more);
        assert!(page.entries.windows(2).all(|w| w[0].seq < w[1].seq));
        assert!(page.entries.iter().all(|e| e.publisher_did == alice.did()));

        // Bob sees only his own.
        let bobs = registry.feed(bob.did(), 0, None);
        assert_eq!(bobs.entries.len(), 1);
        assert_eq!(bobs.entries[0].kind, RegistrationKind::Vendor);

        // Cursor semantics: since = the last seq seen.
        let tail = registry.feed(alice.did(), 3, None);
        assert_eq!(tail.entries.len(), 2);
        assert_eq!(tail.entries[0].seq, 4);
        assert_eq!(tail.next, 5);

        // Caught up: nothing new, and next does not rewind.
        let caught_up = registry.feed(alice.did(), 5, None);
        assert!(caught_up.entries.is_empty());
        assert_eq!(caught_up.next, 5);

        // Paging.
        let first = registry.feed(alice.did(), 0, Some(2));
        assert_eq!(first.entries.len(), 2);
        assert!(first.has_more);
        let second = registry.feed(alice.did(), first.next, Some(2));
        assert_eq!(second.entries.len(), 2);
        assert!(!second.has_more);

        // An unknown DID gets an empty feed, not an error.
        let none = registry.feed("did:key:z6MkGhost", 0, None);
        assert!(none.entries.is_empty());
        assert_eq!(none.next, 0);
    }

    // ---- restart -----------------------------------------------------------
    let registry = Registry::open(dir.path()).expect("reopen");
    let stats = registry.stats();
    assert_eq!(stats.head_seq, 5, "sequence counter survives a restart");
    assert_eq!(stats.vendors, 2);
    assert_eq!(stats.templates, 3);
    assert_eq!(stats.publishers, 2);

    // A consumer's cursor is still valid across the restart.
    let page = registry.feed(alice.did(), 3, None);
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].seq, 4);

    // And the next registration continues the sequence rather than reusing one.
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("alice", "four", &hash_of(9)),
    )
    .await
    .unwrap();
    let receipt = registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .expect("accepted");
    assert_eq!(receipt.seq, 6);
}

// ---------------------------------------------------------------------------
// 3. Publisher-DID trust model (spec-type-registry.md section 3.7).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vendor_registration_must_be_self_certifying() {
    let dir = TempDir::new("e2e-selfcert");
    let registry = Registry::open(dir.path()).expect("open");

    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    let mallory = PublisherKey::from_seed([2u8; 32]).unwrap();

    // Mallory signs a vendor registration that claims Alice's DID.
    let payload = aqua_template_registry::model::RegistrationPayload::Vendor(
        aqua_template_registry::model::VendorRegistration {
            vendor_name: "alice".into(),
            display_name: None,
            vendor_did: alice.did().to_string(),
        },
    );
    let tree = publisher::build(registry.aquafier(), &mallory, &payload)
        .await
        .expect("tree builds fine, it is cryptographically valid");

    // The tree verifies. The registry rejects it anyway, on the trust rule.
    let err = registry
        .submit_vendor(&publisher::to_json(&tree).unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::NotSelfCertifying { .. }),
        "expected NotSelfCertifying, got {err:?}"
    );
    assert_eq!(err.status(), 403);
}

#[tokio::test]
async fn only_the_namespace_owner_can_write_into_it() {
    let dir = TempDir::new("e2e-owner");
    let registry = Registry::open(dir.path()).expect("open");

    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    let mallory = PublisherKey::from_seed([2u8; 32]).unwrap();

    claim(&registry, &alice, "alice").await;

    // Mallory tries to register a template under alice/.
    let t = publisher::template_registration(
        registry.aquafier(),
        &mallory,
        template_reg("alice", "backdoor", &hash_of(0xff)),
    )
    .await
    .unwrap();
    let err = registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::NotNamespaceOwner { .. }),
        "expected NotNamespaceOwner, got {err:?}"
    );

    // And the same for an alias.
    let a = publisher::alias_registration(
        registry.aquafier(),
        &mallory,
        "alice",
        "backdoor",
        &hash_of(0xff),
    )
    .await
    .unwrap();
    assert!(matches!(
        registry
            .submit_alias(&publisher::to_json(&a).unwrap())
            .await
            .unwrap_err(),
        RegistryError::NotNamespaceOwner { .. }
    ));

    // Alice's own registration into her namespace works.
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("alice", "real", &hash_of(0x11)),
    )
    .await
    .unwrap();
    registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .expect("owner may write");
}

#[tokio::test]
async fn vendor_names_are_first_come_first_served() {
    let dir = TempDir::new("e2e-fcfs");
    let registry = Registry::open(dir.path()).expect("open");

    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    let mallory = PublisherKey::from_seed([2u8; 32]).unwrap();

    claim(&registry, &alice, "inblock").await;

    // Mallory claims the same name for himself. Self-certifying, but taken.
    let tree = publisher::vendor_registration(registry.aquafier(), &mallory, "inblock", None)
        .await
        .unwrap();
    let err = registry
        .submit_vendor(&publisher::to_json(&tree).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::VendorNameTaken { .. }));

    // Nor via a case variation, since Latin names are folded.
    let tree = publisher::vendor_registration(registry.aquafier(), &mallory, "InBlock", None)
        .await
        .unwrap();
    assert!(matches!(
        registry
            .submit_vendor(&publisher::to_json(&tree).unwrap())
            .await
            .unwrap_err(),
        RegistryError::VendorNameTaken { .. }
    ));

    // Alice may re-register to update her display name.
    let tree =
        publisher::vendor_registration(registry.aquafier(), &alice, "inblock", Some("InBlock AG"))
            .await
            .unwrap();
    registry
        .submit_vendor(&publisher::to_json(&tree).unwrap())
        .await
        .expect("owner may update");
    assert_eq!(
        registry.vendor("inblock").unwrap().display_name.as_deref(),
        Some("InBlock AG")
    );
}

#[tokio::test]
async fn templates_need_a_registered_vendor() {
    let dir = TempDir::new("e2e-novendor");
    let registry = Registry::open(dir.path()).expect("open");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();

    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("ghost", "thing", &hash_of(1)),
    )
    .await
    .unwrap();
    let err = registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::VendorNotRegistered(_)));
    assert_eq!(err.status(), 404);
}

// ---------------------------------------------------------------------------
// 4. Version lineage (spec section 3.5, module-ecosystem section 11).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn version_chains_resolve_to_the_newest_unsuperseded_version() {
    let dir = TempDir::new("e2e-versions");
    let registry = Registry::open(dir.path()).expect("open");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    claim(&registry, &alice, "inblock").await;

    let v1 = hash_of(0x01);
    let v2 = hash_of(0x02);
    let v3 = hash_of(0x03);

    // v1
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("inblock", "email-claim", &v1),
    )
    .await
    .unwrap();
    registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap();
    assert_eq!(
        registry
            .resolve("inblock", "email-claim")
            .unwrap()
            .template_hash,
        v1
    );

    // v2 supersedes v1
    let mut reg2 = template_reg("inblock", "email-claim", &v2);
    reg2.supersedes = Some(v1.clone());
    let t = publisher::template_registration(registry.aquafier(), &alice, reg2)
        .await
        .unwrap();
    registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap();

    let hit = registry.resolve("inblock", "email-claim").unwrap();
    assert_eq!(
        hit.template_hash, v2,
        "resolution follows the chain forward"
    );
    assert_eq!(hit.lineage, vec![v1.clone(), v2.clone()]);

    // Pinning an old version by hash still works.
    let old = registry.template(&v1).unwrap();
    assert_eq!(old.superseded_by.as_deref(), Some(v2.as_str()));
    assert!(old.supersedes.is_none());

    // v3 supersedes v2
    let mut reg3 = template_reg("inblock", "email-claim", &v3);
    reg3.supersedes = Some(v2.clone());
    let t = publisher::template_registration(registry.aquafier(), &alice, reg3)
        .await
        .unwrap();
    registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap();

    let hit = registry.resolve("inblock", "email-claim").unwrap();
    assert_eq!(hit.template_hash, v3);
    assert_eq!(hit.lineage, vec![v1.clone(), v2.clone(), v3.clone()]);

    // The chain must stay linear: a second v2 successor is refused.
    let mut fork = template_reg("inblock", "email-claim", &hash_of(0x04));
    fork.supersedes = Some(v2.clone());
    let t = publisher::template_registration(registry.aquafier(), &alice, fork)
        .await
        .unwrap();
    assert!(matches!(
        registry
            .submit_template(&publisher::to_json(&t).unwrap())
            .await
            .unwrap_err(),
        RegistryError::AlreadySuperseded(_)
    ));

    // And a supersedes target from a different name is not a version of this one.
    let mut wrong = template_reg("inblock", "other", &hash_of(0x05));
    wrong.supersedes = Some(v3.clone());
    let t = publisher::template_registration(registry.aquafier(), &alice, wrong)
        .await
        .unwrap();
    assert!(matches!(
        registry
            .submit_template(&publisher::to_json(&t).unwrap())
            .await
            .unwrap_err(),
        RegistryError::UnknownSupersedes { .. }
    ));

    // Registering the same hash twice is refused.
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("inblock", "duplicate", &v3),
    )
    .await
    .unwrap();
    assert!(matches!(
        registry
            .submit_template(&publisher::to_json(&t).unwrap())
            .await
            .unwrap_err(),
        RegistryError::DuplicateTemplate(_)
    ));
}

// ---------------------------------------------------------------------------
// 5. Aliases, including cross-vendor.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aliases_resolve_and_may_point_across_vendors() {
    let dir = TempDir::new("e2e-alias");
    let registry = Registry::open(dir.path()).expect("open");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();
    let bob = PublisherKey::from_seed([2u8; 32]).unwrap();

    claim(&registry, &alice, "inblock").await;
    claim(&registry, &bob, "acme").await;

    let target = hash_of(0x77);
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("inblock", "email-claim", &target),
    )
    .await
    .unwrap();
    registry
        .submit_template(&publisher::to_json(&t).unwrap())
        .await
        .unwrap();

    // Alice aliases within her own namespace.
    let a = publisher::alias_registration(registry.aquafier(), &alice, "inblock", "email", &target)
        .await
        .unwrap();
    registry
        .submit_alias(&publisher::to_json(&a).unwrap())
        .await
        .unwrap();

    let hit = registry.resolve("inblock", "email").unwrap();
    assert_eq!(hit.template_hash, target);
    assert_eq!(hit.via, aqua_template_registry::model::ResolutionVia::Alias);
    assert_eq!(hit.publisher_did.as_deref(), Some(alice.did()));

    // Bob aliases Alice's template inside his own namespace. Allowed: he only
    // needs to control the namespace the NAME lives in.
    let a = publisher::alias_registration(registry.aquafier(), &bob, "acme", "email", &target)
        .await
        .unwrap();
    registry
        .submit_alias(&publisher::to_json(&a).unwrap())
        .await
        .unwrap();
    let hit = registry.resolve("acme", "email").unwrap();
    assert_eq!(hit.template_hash, target);
    assert_eq!(hit.publisher_did.as_deref(), Some(alice.did()));

    // A name cannot be both an alias and a template in the same namespace.
    let t = publisher::template_registration(
        registry.aquafier(),
        &alice,
        template_reg("inblock", "email", &hash_of(0x78)),
    )
    .await
    .unwrap();
    assert!(matches!(
        registry
            .submit_template(&publisher::to_json(&t).unwrap())
            .await
            .unwrap_err(),
        RegistryError::NameCollision(_)
    ));

    // Nor registered twice.
    let a = publisher::alias_registration(registry.aquafier(), &alice, "inblock", "email", &target)
        .await
        .unwrap();
    assert!(matches!(
        registry
            .submit_alias(&publisher::to_json(&a).unwrap())
            .await
            .unwrap_err(),
        RegistryError::DuplicateAlias(_)
    ));
}

// ---------------------------------------------------------------------------
// 6. Things the registry must refuse.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refuses_unverifiable_and_non_registration_submissions() {
    let dir = TempDir::new("e2e-refuse");
    let registry = Registry::open(dir.path()).expect("open");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();

    // Not JSON at all.
    assert!(matches!(
        registry.submit_vendor("{").await.unwrap_err(),
        RegistryError::MalformedTree(_)
    ));

    // A tree typed as something that is not a registration template.
    let aquafier = Aquafier::new();
    let stranger = aquafier
        .create_object(
            aqua_rs_sdk_core::primitives::RevisionLink::from_bytes([0x5a; 32]),
            None,
            serde_json::json!({"anything": 1}),
            None,
        )
        .unwrap();
    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(stranger, None, None),
            &alice.credentials(),
            None,
            None,
        )
        .await
        .unwrap();
    // Core cannot resolve that template, so this is refused before we ever get
    // to look at what kind of object it is.
    let err = registry
        .submit_vendor(&serde_json::to_string(&signed.aqua_tree).unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::TreeNotVerified(_)),
        "got {err:?}"
    );
    assert_eq!(err.status(), 422);

    // A valid vendor registration submitted to the template endpoint.
    let tree = publisher::vendor_registration(registry.aquafier(), &alice, "alice", None)
        .await
        .unwrap();
    let err = registry
        .submit_template(&publisher::to_json(&tree).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::WrongRegistrationKind { .. }));

    // An unsigned registration.
    let unsigned = registry
        .aquafier()
        .create_object(
            templates::link(RegistrationKind::Vendor).clone(),
            None,
            serde_json::json!({"vendor_name": "alice", "vendor_did": alice.did()}),
            Some(aqua_rs_sdk_core::primitives::Method::Scalar),
        )
        .unwrap();
    let err = registry
        .submit_vendor(&serde_json::to_string(&unsigned).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::Unsigned), "got {err:?}");

    // A tampered tree: flip a byte in the payload after signing.
    let tree = publisher::vendor_registration(registry.aquafier(), &alice, "alice", None)
        .await
        .unwrap();
    let body = publisher::to_json(&tree)
        .unwrap()
        .replace("alice", "mallory");
    let err = registry.submit_vendor(&body).await.unwrap_err();
    assert!(
        matches!(err, RegistryError::TreeNotVerified(_)),
        "a tampered tree must not verify, got {err:?}"
    );

    // Nothing was accepted.
    assert_eq!(registry.stats().head_seq, 0);
}

#[tokio::test]
async fn rejects_names_that_violate_the_character_rules() {
    let dir = TempDir::new("e2e-names");
    let registry = Registry::open(dir.path()).expect("open");
    let alice = PublisherKey::from_seed([1u8; 32]).unwrap();

    // Latin plus a Cyrillic homoglyph. The tree is perfectly valid; the name is
    // not, so acceptance stops at the name rules.
    let tree = publisher::vendor_registration(registry.aquafier(), &alice, "inbl\u{043E}ck", None)
        .await
        .unwrap();
    let err = registry
        .submit_vendor(&publisher::to_json(&tree).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::InvalidName(_)), "got {err:?}");
    assert_eq!(err.status(), 400);

    // A non-Latin script on its own is fine.
    let tree = publisher::vendor_registration(registry.aquafier(), &alice, "阿里巴巴", None)
        .await
        .unwrap();
    let receipt = registry
        .submit_vendor(&publisher::to_json(&tree).unwrap())
        .await
        .expect("pure Han vendor name is allowed");
    assert_eq!(receipt.qualified_name, "阿里巴巴");
    assert!(registry.vendor("阿里巴巴").is_ok());
}

// ---------------------------------------------------------------------------
// 7. The same flow over HTTP.
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
mod http_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
        let response = app.clone().oneshot(req).await.expect("router responded");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn post(path: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn full_http_publish_subscribe_flow() {
        let dir = TempDir::new("e2e-http");
        let registry = Arc::new(Registry::open(dir.path()).expect("open"));
        let app = aqua_template_registry::http::router(registry.clone());
        let key = PublisherKey::from_seed([7u8; 32]).unwrap();
        let did = key.did().to_string();

        // The registry publishes the template hashes a publisher needs.
        let (status, body) = send(&app, get("/registration-templates")).await;
        assert_eq!(status, StatusCode::OK);
        let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 3);

        // ---- POST /vendors -------------------------------------------------
        let tree = publisher::vendor_registration(registry.aquafier(), &key, "acme", Some("ACME"))
            .await
            .unwrap();
        let (status, body) = send(&app, post("/vendors", publisher::to_json(&tree).unwrap())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let receipt: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(receipt["seq"], 1);
        assert_eq!(receipt["publisher_did"], did);

        // ---- POST /templates -----------------------------------------------
        let target = hash_of(0x33);
        let tree = publisher::template_registration(
            registry.aquafier(),
            &key,
            template_reg("acme", "invoice", &target),
        )
        .await
        .unwrap();
        let (status, body) =
            send(&app, post("/templates", publisher::to_json(&tree).unwrap())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        // ---- POST /aliases -------------------------------------------------
        let alias =
            publisher::alias_registration(registry.aquafier(), &key, "acme", "inv", &target)
                .await
                .unwrap();
        let (status, _) = send(&app, post("/aliases", publisher::to_json(&alias).unwrap())).await;
        assert_eq!(status, StatusCode::CREATED);

        // ---- GET /vendors/{name} -------------------------------------------
        let (status, body) = send(&app, get("/vendors/acme")).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["vendor_did"], did);
        assert_eq!(v["display_name"], "ACME");

        // ---- GET /resolve/{vendor}/{name} ----------------------------------
        let (status, body) = send(&app, get("/resolve/acme/invoice")).await;
        assert_eq!(status, StatusCode::OK);
        let r: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(r["template_hash"], target);
        assert_eq!(r["via"], "template");

        let (_, body) = send(&app, get("/resolve/acme/inv")).await;
        let r: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(r["template_hash"], target);
        assert_eq!(r["via"], "alias");

        // ---- GET /publishers/{did}/templates -------------------------------
        let (status, body) = send(&app, get(&format!("/publishers/{did}/templates"))).await;
        assert_eq!(status, StatusCode::OK);
        let list: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["template_hash"], target);

        // ---- GET /templates/{hash} returns the full signed tree ------------
        let (status, body) = send(&app, get(&format!("/templates/{target}"))).await;
        assert_eq!(status, StatusCode::OK);
        let refetched: Tree = serde_json::from_str(&body).expect("a real Aqua tree comes back");
        let result = Aquafier::new()
            .verify_aqua_tree_with_linked_trees(
                AquaTreeWrapper::new(refetched, None, None),
                templates::linked_trees(),
                vec![],
            )
            .await
            .unwrap();
        assert!(
            result.is_verified(),
            "a tree fetched over HTTP must re-verify: {:?}",
            result.outcome
        );

        // ---- GET /publishers/{did}/feed?since= -----------------------------
        let (status, body) = send(&app, get(&format!("/publishers/{did}/feed?since=0"))).await;
        assert_eq!(status, StatusCode::OK);
        let page: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(page["entries"].as_array().unwrap().len(), 3);
        assert_eq!(page["next"], 3);
        assert_eq!(page["has_more"], false);

        let (_, body) = send(&app, get(&format!("/publishers/{did}/feed?since=2"))).await;
        let page: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(page["entries"].as_array().unwrap().len(), 1);
        assert_eq!(page["entries"][0]["kind"], "alias");

        // ---- errors carry a stable code ------------------------------------
        let (status, body) = send(&app, get("/vendors/nobody")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let e: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(e["error"]["code"], "NOT_FOUND");

        let (status, body) = send(&app, post("/vendors", "not json".to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let e: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(e["error"]["code"], "MALFORMED_TREE");

        // A foreign publisher writing into acme/ is refused with 403.
        let mallory = PublisherKey::from_seed([8u8; 32]).unwrap();
        let t = publisher::template_registration(
            registry.aquafier(),
            &mallory,
            template_reg("acme", "backdoor", &hash_of(0x99)),
        )
        .await
        .unwrap();
        let (status, body) = send(&app, post("/templates", publisher::to_json(&t).unwrap())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let e: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(e["error"]["code"], "NOT_NAMESPACE_OWNER");

        // ---- GET /stats ----------------------------------------------------
        let (_, body) = send(&app, get("/stats")).await;
        let s: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(s["head_seq"], 3);
        assert_eq!(s["vendors"], 1);
        assert_eq!(s["templates"], 1);
        assert_eq!(s["aliases"], 1);
        assert_eq!(s["publishers"], 1);
    }
}
