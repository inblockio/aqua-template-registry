//! The negative-path security suite for signed feed heads (`src/feedhead.rs`,
//! backlog R10).
//!
//! A feed head is a publisher's own signature over "my feed has at least N
//! entries, and this is the Merkle root over them". `src/feedhead.rs`
//! documents the gap it closes: the registry assembling a feed page is not
//! itself signed, so a registry can withhold, reorder, or replay entries
//! without a signed head, none of which lets it forge something the
//! publisher never signed. Every test here proves one of those fail-closed
//! paths actually denies, and asserts on the specific `HeadRejection`
//! variant returned, not merely that some error came back. Test 1 and the
//! tail of tests 9 and 10 are positive controls, so the suite proves the
//! gate opens as well as closes.
//!
//! Everything here is library-level: `feedhead::build`, `verify_head`,
//! `check_against_entries`, and `check_against_previous` directly. None of
//! it needs a running server, which keeps it fast and deterministic.

use aqua_rs_sdk_core::primitives::Method;
use aqua_rs_sdk_core::schema::AquaTreeWrapper;
use aqua_rs_sdk_core::Aquafier;

use aqua_template_registry::feedhead::{
    self, check_against_entries, check_against_previous, compute_root, leaf_hash, leaf_preimage,
    verify_head, HeadRejection, LEAF_VERSION,
};
use aqua_template_registry::publisher::{self, PublisherKey};
use aqua_template_registry::templates;

// ---------------------------------------------------------------------------
// Test-local helpers
// ---------------------------------------------------------------------------

/// A deterministic stand-in for a registration tree's tip hash: a
/// `0x1620`-prefixed (SHA3-256 multihash) lowercase digest, distinguished by
/// `n` alone.
fn tip(n: u8) -> String {
    format!("0x1620{}", hex::encode([n; 32]))
}

/// Build and sign an honest feed head over `tips`, naming `key` as the
/// publisher, and serialize it the way a publisher would submit it.
async fn signed_head(aquafier: &Aquafier, key: &PublisherKey, tips: &[String]) -> String {
    let tree = feedhead::build(aquafier, &key.credentials(), key.did(), tips, 1_700_000_000)
        .await
        .expect("build and sign an honest feed head");
    publisher::to_json_pretty(&tree).expect("serialize the feed head tree")
}

// ---------------------------------------------------------------------------
// 1. Positive control: the honest path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_honest_head_verifies_and_matches_its_entries() {
    // Security property, positive control: when a head is built and signed
    // honestly, verification succeeds both when a subscriber names the
    // specific publisher they follow and when an ingest path accepts any
    // self-certifying publisher, and the recovered claims match what was
    // signed. Proves the gate opens, not merely that it closes.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([101u8; 32]).unwrap();
    let tips: Vec<String> = (1..=5).map(tip).collect();

    let head_json = signed_head(&aquafier, &key, &tips).await;

    let verified = verify_head(&aquafier, &head_json, Some(key.did()))
        .await
        .expect("an honest head from the expected publisher must verify");
    assert_eq!(verified.head_seq, 5);
    assert_eq!(verified.leaf_version, LEAF_VERSION);
    assert_eq!(verified.publisher_did, key.did());

    check_against_entries(&verified, &tips)
        .expect("the entries the head actually covers must match its signed root");

    // The ingest path: any self-certifying publisher is accepted.
    verify_head(&aquafier, &head_json, None)
        .await
        .expect("verify_head with no expected publisher must also accept an honest head");
}

// ---------------------------------------------------------------------------
// 2. Tamper-evidence of the signed tree itself.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tampered_head_tree_does_not_verify() {
    // Security property: the signature covers the tree's own payload bytes,
    // so any post-signing edit to a field the signature covers must be
    // caught at verification, never accepted with a silently different
    // claim. Checked two ways: a mutated merkle_root and a mutated
    // head_seq. Both mutations are constructed to stay valid JSON with a
    // schema-valid value (a hex digit swapped for a different hex digit;
    // one decimal digit incremented), so what fails is exactly the
    // signature check, not JSON parsing or schema validation.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([102u8; 32]).unwrap();
    let tips: Vec<String> = (1..=4).map(tip).collect();
    let honest_json = signed_head(&aquafier, &key, &tips).await;

    // Variant (a): flip one hex digit inside the merkle_root value.
    let root = compute_root(&tips).unwrap();
    let mutated_root_char = if root.as_bytes()[3] == b'0' { '1' } else { '0' };
    let mut mutated_root = root.clone();
    mutated_root.replace_range(3..4, &mutated_root_char.to_string());
    assert_ne!(
        mutated_root, root,
        "the root mutation must actually change the value"
    );
    assert_eq!(
        mutated_root.len(),
        root.len(),
        "same length, one digit different"
    );

    let needle = format!("\"merkle_root\": \"{root}\"");
    assert!(
        honest_json.contains(&needle),
        "expected to find merkle_root verbatim in the pretty-printed tree"
    );
    let tampered_root_json =
        honest_json.replacen(&needle, &format!("\"merkle_root\": \"{mutated_root}\""), 1);
    assert_ne!(tampered_root_json, honest_json);

    let err = verify_head(&aquafier, &tampered_root_json, Some(key.did()))
        .await
        .expect_err("a tampered merkle_root must not verify");
    assert!(matches!(err, HeadRejection::NotVerified(_)), "got {err:?}");
    assert_eq!(err.code(), "HEAD_NOT_VERIFIED");

    // Variant (b): change one digit of head_seq (4 covered entries -> 5).
    let needle_seq = "\"head_seq\": 4";
    assert!(
        honest_json.contains(needle_seq),
        "expected to find head_seq verbatim in the pretty-printed tree"
    );
    let tampered_seq_json = honest_json.replacen(needle_seq, "\"head_seq\": 5", 1);
    assert_ne!(tampered_seq_json, honest_json);

    let err2 = verify_head(&aquafier, &tampered_seq_json, Some(key.did()))
        .await
        .expect_err("a tampered head_seq must not verify");
    assert!(
        matches!(err2, HeadRejection::NotVerified(_)),
        "got {err2:?}"
    );
    assert_eq!(err2.code(), "HEAD_NOT_VERIFIED");
}

// ---------------------------------------------------------------------------
// 3. The publisher-scoping gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_head_signed_by_a_different_key_is_refused_for_this_publisher() {
    // Security property: a head that is perfectly self-certifying for its
    // own signer is still refused when a subscriber asked for a different
    // publisher. Being validly signed by SOMEONE is not the same as being
    // signed by the ONE DID a subscriber follows.
    let aquafier = Aquafier::new();
    let key_a = PublisherKey::from_seed([103u8; 32]).unwrap();
    let key_b = PublisherKey::from_seed([104u8; 32]).unwrap();
    let tips: Vec<String> = (1..=3).map(tip).collect();

    let head_json_b = signed_head(&aquafier, &key_b, &tips).await;

    let err = verify_head(&aquafier, &head_json_b, Some(key_a.did()))
        .await
        .expect_err("a head honestly signed by key B must be refused when following key A");
    match &err {
        HeadRejection::WrongPublisher { expected, actual } => {
            assert_eq!(expected, key_a.did());
            assert_eq!(actual, key_b.did());
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_WRONG_PUBLISHER");
}

// ---------------------------------------------------------------------------
// 4. Self-certification: naming a DID is not the same as being it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_head_claiming_someone_elses_did_is_not_self_certifying() {
    // Security property: a feed head's payload names the publisher it
    // speaks for, but that claim is only trustworthy if the signer IS that
    // DID. Built by hand, since `feedhead::build` always fills signer_did
    // from its own `signer_did` argument: key B signs the tree, but the
    // payload claims key A's DID. This must be refused before publisher
    // scoping or leaf-version checks ever run, regardless of who a
    // subscriber is following.
    let aquafier = Aquafier::new();
    let key_a = PublisherKey::from_seed([105u8; 32]).unwrap();
    let key_b = PublisherKey::from_seed([106u8; 32]).unwrap();
    let tips: Vec<String> = (1..=2).map(tip).collect();

    let tree = feedhead::build(
        &aquafier,
        &key_b.credentials(),
        key_a.did(),
        &tips,
        1_700_000_000,
    )
    .await
    .expect("build a head signed by key B but naming key A's DID");
    let head_json = publisher::to_json_pretty(&tree).expect("serialize the forged head");

    let err = verify_head(&aquafier, &head_json, None)
        .await
        .expect_err("signer (key B) does not match the claimed signer_did (key A)");
    match &err {
        HeadRejection::NotSelfCertifying { signer, claimed } => {
            assert_eq!(signer, key_b.did());
            assert_eq!(claimed, key_a.did());
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_NOT_SELF_CERTIFYING");
}

// ---------------------------------------------------------------------------
// 5. Type confusion: a registration is not a feed head.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registration_tree_is_not_accepted_as_a_feed_head() {
    // Security property: a normal signed vendor registration verifies
    // perfectly well through core (it is a validly signed, self-certifying
    // tree), so only the template-hash check distinguishes it from a feed
    // head. Without that check, a registration could be replayed at a
    // subscriber's feed-head endpoint.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([107u8; 32]).unwrap();

    let tree = publisher::vendor_registration(&aquafier, &key, "acme", Some("Test Vendor"))
        .await
        .expect("build and sign a vendor registration");
    let registration_json =
        publisher::to_json_pretty(&tree).expect("serialize the vendor registration tree");

    let err = verify_head(&aquafier, &registration_json, None)
        .await
        .expect_err("a vendor registration must not be accepted as a feed head");
    assert!(matches!(err, HeadRejection::NotAFeedHead), "got {err:?}");
    assert_eq!(err.code(), "NOT_A_FEED_HEAD");
}

// ---------------------------------------------------------------------------
// 6. Unknown constructions are refused, not guessed at.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unsupported_leaf_version_is_refused_not_guessed() {
    // Security property: a verifier that does not implement a head's
    // declared leaf_version must refuse it rather than check the root under
    // an assumed construction. Guessing would let a verifier report a root
    // as "checked" without having used the right construction at all, which
    // is worse than an honest refusal. `feedhead::build` always emits
    // LEAF_VERSION, so this is constructed by hand with leaf_version 2 and
    // an otherwise valid, self-certifying payload.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([108u8; 32]).unwrap();
    let tips: Vec<String> = (1..=3).map(tip).collect();

    let payload = serde_json::json!({
        "signer_did": key.did(),
        "head_seq": tips.len() as u64,
        "merkle_root": compute_root(&tips).unwrap(),
        "leaf_version": 2,
        "covered_at": 1_700_000_000u64,
    });

    let unsigned = aquafier
        .create_object(
            templates::feed_head_link().clone(),
            None,
            payload,
            Some(Method::Scalar),
        )
        .expect("create a feed_head object with an unsupported leaf_version");
    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(unsigned, None, None),
            &key.credentials(),
            None,
            None,
        )
        .await
        .expect("sign the leaf_version 2 head");
    let head_json =
        serde_json::to_string_pretty(&signed.aqua_tree).expect("serialize the leaf_version 2 head");

    let err = verify_head(&aquafier, &head_json, None)
        .await
        .expect_err("leaf_version 2 is not implemented by this build and must be refused");
    match &err {
        HeadRejection::UnsupportedLeafVersion { found, supported } => {
            assert_eq!(*found, 2);
            assert_eq!(*supported, LEAF_VERSION);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_UNSUPPORTED_LEAF_VERSION");
}

// ---------------------------------------------------------------------------
// 7-8. The root actually commits to order and content.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reordered_entries_break_the_root() {
    // Security property: the ordinal is inside the leaf, which is what
    // makes a pure reorder of otherwise identical entries detectable at
    // all. A construction over tips alone (no ordinal) would produce the
    // same root for both orderings and would miss this entirely.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([109u8; 32]).unwrap();
    let tips = vec![tip(1), tip(2), tip(3)];
    let head_json = signed_head(&aquafier, &key, &tips).await;
    let verified = verify_head(&aquafier, &head_json, None)
        .await
        .expect("honest head must verify");

    let reordered = vec![tip(2), tip(1), tip(3)];
    let err = check_against_entries(&verified, &reordered)
        .expect_err("a pure reorder of the covered entries must break the root");
    assert!(
        matches!(err, HeadRejection::RootMismatch { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "HEAD_ROOT_MISMATCH");
}

#[tokio::test]
async fn a_substituted_entry_breaks_the_root() {
    // Security property: swapping one covered entry for a different one,
    // keeping position and count the same, must also be caught by the root
    // check.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([110u8; 32]).unwrap();
    let tips = vec![tip(1), tip(2), tip(3)];
    let head_json = signed_head(&aquafier, &key, &tips).await;
    let verified = verify_head(&aquafier, &head_json, None)
        .await
        .expect("honest head must verify");

    let substituted = vec![tip(1), tip(99), tip(3)];
    let err = check_against_entries(&verified, &substituted)
        .expect_err("a substituted entry must break the root");
    assert!(
        matches!(err, HeadRejection::RootMismatch { .. }),
        "got {err:?}"
    );
    assert_eq!(err.code(), "HEAD_ROOT_MISMATCH");
}

// ---------------------------------------------------------------------------
// 9. Withholding, and the prefix rule that makes "more" fine.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn withheld_entries_are_detected() {
    // Security property: a registry serving fewer entries than a verified
    // head covers is withholding, and must be detected. The flip side is
    // equally load-bearing: a head covers a PREFIX of a publisher's feed, so
    // a registry offering MORE entries than a head covers (because the
    // publisher has since published more without yet signing a new head) is
    // the normal state of affairs, not an error.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([111u8; 32]).unwrap();
    let tips: Vec<String> = (1..=5).map(tip).collect();
    let head_json = signed_head(&aquafier, &key, &tips).await;
    let verified = verify_head(&aquafier, &head_json, None)
        .await
        .expect("honest head must verify");

    // Only 3 of the 5 covered entries offered.
    let err = check_against_entries(&verified, &tips[..3])
        .expect_err("offering fewer entries than head_seq must be withholding");
    assert!(
        matches!(
            err,
            HeadRejection::Withholding {
                available: 3,
                head_seq: 5
            }
        ),
        "got {err:?}"
    );
    assert_eq!(err.code(), "HEAD_WITHHOLDING");

    // 7 entries offered against a head covering 5, where the first 5 match:
    // fine, since a head covers a prefix.
    let mut more = tips.clone();
    more.push(tip(6));
    more.push(tip(7));
    check_against_entries(&verified, &more)
        .expect("offering more entries than the head covers, with the prefix intact, must be fine");
}

// ---------------------------------------------------------------------------
// 10. Rollback across time.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_head_that_goes_backwards_is_a_rollback() {
    // Security property: a subscriber that has already verified a head at
    // some height must refuse any later head claiming a lower height, since
    // that can only mean a registry replaying an older, superseded head.
    // Forward progress and an idempotent re-fetch at the same height must
    // both remain unaffected, or the check would be too strict to use.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([112u8; 32]).unwrap();
    let tips_4: Vec<String> = (1..=4).map(tip).collect();
    let tips_9: Vec<String> = (1..=9).map(tip).collect();

    let head_json_4 = signed_head(&aquafier, &key, &tips_4).await;
    let head_4 = verify_head(&aquafier, &head_json_4, None)
        .await
        .expect("honest head at height 4 must verify");

    let head_json_9 = signed_head(&aquafier, &key, &tips_9).await;
    let head_9 = verify_head(&aquafier, &head_json_9, None)
        .await
        .expect("honest head at height 9 must verify");

    // A head at height 4 offered after height 9 was already verified: rollback.
    let err = check_against_previous(&head_4, Some(head_9.head_seq), Some(&head_9.merkle_root))
        .expect_err("offering height 4 after height 9 was verified must be a rollback");
    assert!(
        matches!(
            err,
            HeadRejection::Rollback {
                previous: 9,
                offered: 4
            }
        ),
        "got {err:?}"
    );
    assert_eq!(err.code(), "HEAD_ROLLBACK");

    // Forward progress: height 9 offered after height 4 was verified, is fine.
    check_against_previous(&head_9, Some(head_4.head_seq), Some(&head_4.merkle_root))
        .expect("forward progress from height 4 to height 9 must be accepted");

    // An idempotent re-fetch of the very same height 9 head is also fine.
    check_against_previous(&head_9, Some(head_9.head_seq), Some(&head_9.merkle_root))
        .expect("re-fetching an identical head at the same height must be accepted");
}

// ---------------------------------------------------------------------------
// 11. Equivocation: two different roots at one height.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_different_roots_at_the_same_height_is_equivocation() {
    // Security property: a publisher signing two different roots at the
    // same head_seq has equivocated, since there is no honest reading of
    // it: the covered entries at a fixed height determine one root, so two
    // roots means two conflicting histories were each signed as authoritative.
    let aquafier = Aquafier::new();
    let key_a = PublisherKey::from_seed([113u8; 32]).unwrap();
    let key_b = PublisherKey::from_seed([114u8; 32]).unwrap();

    // Two different publishers' honest 3-entry feeds happen to sit at the
    // same height (3) but, being different entries, produce different roots.
    let tips_a = vec![tip(1), tip(2), tip(3)];
    let tips_b = vec![tip(4), tip(5), tip(6)];

    let head_json_a = signed_head(&aquafier, &key_a, &tips_a).await;
    let head_a = verify_head(&aquafier, &head_json_a, None)
        .await
        .expect("honest head A must verify");

    let head_json_b = signed_head(&aquafier, &key_b, &tips_b).await;
    let head_b = verify_head(&aquafier, &head_json_b, None)
        .await
        .expect("honest head B must verify");

    assert_eq!(
        head_a.head_seq, head_b.head_seq,
        "both heads sit at height 3"
    );
    assert_ne!(
        head_a.merkle_root, head_b.merkle_root,
        "different entries at the same height must produce different roots"
    );

    let err = check_against_previous(&head_b, Some(head_a.head_seq), Some(&head_a.merkle_root))
        .expect_err("a different root at the same previously-verified height is equivocation");
    match &err {
        HeadRejection::ForkedHead { head_seq, a, b } => {
            assert_eq!(*head_seq, 3);
            assert_eq!(a, &head_a.merkle_root);
            assert_eq!(b, &head_b.merkle_root);
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(err.code(), "HEAD_FORKED");
}

// ---------------------------------------------------------------------------
// 12. An unsigned head carries no commitment at all.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unsigned_head_is_refused() {
    // Security property: a feed head is a signature, so a tree with the
    // right shape but no signature over it must be refused. Which layer
    // catches it is an implementation detail either way it is a fail-closed
    // refusal: `HeadRejection::Signing` if the module's own single-signer
    // check runs, or `HeadRejection::NotVerified` if core's own pipeline
    // refuses an unsigned tree first, since `verify_aqua_tree_with_linked_trees`
    // runs before this module ever inspects who signed. In this build the
    // observed outcome is `NotVerified`, caught inside core's own pipeline
    // before feedhead's signer-count check ever runs.
    let aquafier = Aquafier::new();
    let key = PublisherKey::from_seed([115u8; 32]).unwrap();
    let tips: Vec<String> = (1..=3).map(tip).collect();

    let payload = serde_json::json!({
        "signer_did": key.did(),
        "head_seq": tips.len() as u64,
        "merkle_root": compute_root(&tips).unwrap(),
        "leaf_version": LEAF_VERSION,
        "covered_at": 1_700_000_000u64,
    });

    let unsigned = aquafier
        .create_object(
            templates::feed_head_link().clone(),
            None,
            payload,
            Some(Method::Scalar),
        )
        .expect("create an unsigned feed_head object");
    let head_json =
        serde_json::to_string_pretty(&unsigned).expect("serialize the unsigned head tree");

    let err = verify_head(&aquafier, &head_json, None)
        .await
        .expect_err("an unsigned head must be refused");
    assert!(
        matches!(err, HeadRejection::Signing(_)) || matches!(err, HeadRejection::NotVerified(_)),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 13. Wire-format regression anchor.
// ---------------------------------------------------------------------------

#[test]
fn leaf_construction_is_pinned_byte_for_byte() {
    // Security property: this pins the leaf and root construction to exact
    // bytes, not merely to "some deterministic function of the inputs".
    // These are frozen wire constants: a change to any of them means every
    // previously signed feed head stops verifying against a build with the
    // new code, silently splitting the ecosystem into two constructions that
    // both call themselves leaf_version 1.
    assert_eq!(leaf_preimage(3, "0xABC"), b"3\x1f0xabc".to_vec());

    // A single-leaf tree returns the leaf itself (core's merkle_root
    // convention), so compute_root over one tip must equal 0x plus the hex
    // of that one leaf's hash.
    let single = compute_root(&[tip(1)]).unwrap();
    assert_eq!(single, format!("0x{}", hex::encode(leaf_hash(1, &tip(1)))));

    // Two known multi-leaf roots, hardcoded from this construction's actual
    // output. A change here means the wire format moved.
    let two = compute_root(&[tip(1), tip(2)]).unwrap();
    assert_eq!(
        two,
        "0x869d9e35a050c44b52d946cacb17da5715ddc07e569fa2cdc86aa68cb6682f42"
    );

    let three = compute_root(&[tip(1), tip(2), tip(3)]).unwrap();
    assert_eq!(
        three,
        "0xd68519d56035349a19b9734091a7e78915b4d0e00ef2825a9ac01d4341984cfb"
    );
}
