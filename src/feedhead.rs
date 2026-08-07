//! Signed feed heads: a publisher's commitment to their own feed.
//!
//! # The gap this closes
//!
//! Every registration a subscriber acts on is signed, so a registry cannot
//! forge one. But the *feed* is not signed: a feed page is assembled by the
//! registry, so a registry can omit entries, serve a stale view, delay entries,
//! or reorder them. None of that lets it make a consumer accept something the
//! publisher did not sign. It does let it stop a consumer from seeing something
//! the publisher did sign, which for a template registry means pinning a
//! consumer to a superseded template long after a fix was published.
//!
//! A feed head is the publisher signing "my feed has at least N entries, and
//! this is the Merkle root over them". A subscriber that has verified one can
//! detect a registry serving fewer entries than N (withholding), a registry
//! replaying an older head (rollback), and any reordering or substitution of
//! the covered entries (root mismatch).
//!
//! # Leaf and root construction, version 1
//!
//! Entries are the publisher's OWN entries, in registry sequence order,
//! numbered from 1. The publisher-local ordinal is used rather than the
//! registry-global `seq` on purpose: the global number depends on what other
//! publishers did, so a head built from it would only be verifiable against the
//! one registry that assigned it. Ordinals make a head portable, so the same
//! signed head verifies against a mirror.
//!
//! For the n-th covered entry, with `tip` its registration tree's tip hash as
//! the lowercase `0x`-prefixed multihash string the registry stores:
//!
//! ```text
//! preimage_n = ascii(decimal(n)) || 0x1F || ascii(tip)
//! leaf_n     = SHA3-256(0x00 || preimage_n)
//! root       = merkle_root([leaf_1 .. leaf_N], SHA3-256)
//! ```
//!
//! `0x1F` is ASCII Unit Separator. It cannot occur in either field (one is
//! decimal digits, the other is `0x` plus lowercase hex), so the concatenation
//! is unambiguous and no length prefix is needed. Without a separator,
//! `(1, "0x12...")` and `(11, "0x2...")` could collide.
//!
//! `0x00` is the RFC 6962 leaf prefix, applied by core's `batch_leaf_hash`, and
//! internal nodes get `0x01` via core's `merkle_root`. Domain separation is
//! what stops a leaf digest being reinterpreted as an internal node. Odd nodes
//! are promoted rather than duplicated, which is core's convention and the one
//! `audit_round_anchor` already uses.
//!
//! The ordinal is inside the leaf, so the tree commits to each entry's
//! POSITION as well as its content. Reordering two entries changes both their
//! leaves and therefore the root, which a construction over tips alone would
//! not catch.
//!
//! # What a head does not do
//!
//! It binds a publisher to what they published. It says nothing about a
//! publisher who signs a head that omits their own entries: a publisher can
//! always lie about their own history, and a subscriber trusting that DID has
//! already accepted that. Collusion between a registry and the publisher's own
//! key is out of scope by definition, since the key IS the authority.

use aqua_rs_sdk_core::primitives::{merkle, HashType, Method};
use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AquaTreeWrapper, SigningCredentials};
use aqua_rs_sdk_core::Aquafier;
use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};
use crate::model::RegistrationKind;
use crate::templates;

/// The leaf and root construction implemented here.
///
/// A head declaring any other version is refused rather than verified with
/// these rules. Guessing at an unknown construction is how a verifier ends up
/// accepting a root it did not actually check.
pub const LEAF_VERSION: u64 = 1;

/// ASCII Unit Separator, the field separator inside a leaf preimage.
const FIELD_SEPARATOR: u8 = 0x1f;

/// Payload of a `feed_head` object. Mirrors `src/templates/feed_head.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedHead {
    /// DID of the publisher committing to their feed.
    pub signer_did: String,
    /// Number of the publisher's own entries covered, counted from their first.
    pub head_seq: u64,
    /// Merkle root over the covered entries.
    pub merkle_root: String,
    /// Version of the leaf and root construction.
    pub leaf_version: u64,
    /// Unix seconds at which the publisher made the commitment.
    pub covered_at: u64,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// The preimage of the leaf for the `ordinal`-th covered entry.
///
/// Exposed so a test can assert the exact bytes rather than only the digest,
/// and so the README's byte-level description has something to point at.
pub fn leaf_preimage(ordinal: u64, tree_tip: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + tree_tip.len());
    out.extend_from_slice(ordinal.to_string().as_bytes());
    out.push(FIELD_SEPARATOR);
    out.extend_from_slice(tree_tip.to_ascii_lowercase().as_bytes());
    out
}

/// The leaf digest for the `ordinal`-th covered entry.
pub fn leaf_hash(ordinal: u64, tree_tip: &str) -> Vec<u8> {
    merkle::batch_leaf_hash(&HashType::Sha3_256, &leaf_preimage(ordinal, tree_tip))
}

/// Merkle root over a publisher's entries, given their tip hashes in feed order.
///
/// `tips[0]` is the publisher's first entry, so ordinals are `1..=tips.len()`.
/// Returns the root as a bare `0x`-prefixed lowercase digest.
pub fn compute_root(tips: &[String]) -> Result<String> {
    if tips.is_empty() {
        return Err(RegistryError::Core(
            "a feed head must cover at least one entry".to_string(),
        ));
    }
    let leaves: Vec<Vec<u8>> = tips
        .iter()
        .enumerate()
        .map(|(i, tip)| leaf_hash(i as u64 + 1, tip))
        .collect();
    Ok(format!(
        "0x{}",
        hex::encode(merkle::merkle_root(&leaves, &HashType::Sha3_256))
    ))
}

/// Build and sign a feed head covering `tips`.
///
/// `tips` are the publisher's own registration tree tips in feed order. The
/// caller is responsible for that ordering being the publisher's real history;
/// nothing here can check it, which is the point of the trust boundary.
pub async fn build(
    aquafier: &Aquafier,
    credentials: &SigningCredentials,
    signer_did: &str,
    tips: &[String],
    covered_at: u64,
) -> Result<Tree> {
    let payload = FeedHead {
        signer_did: signer_did.to_string(),
        head_seq: tips.len() as u64,
        merkle_root: compute_root(tips)?,
        leaf_version: LEAF_VERSION,
        covered_at,
    };
    let value = serde_json::to_value(&payload).map_err(|e| RegistryError::Core(e.to_string()))?;

    let unsigned = aquafier
        .create_object(
            templates::feed_head_link().clone(),
            None,
            value,
            Some(Method::Scalar),
        )
        .map_err(|e| RegistryError::Core(e.to_string()))?;

    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(unsigned, None, None),
            credentials,
            None,
            None,
        )
        .await
        .map_err(|e| RegistryError::Core(e.to_string()))?;

    Ok(signed.aqua_tree)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Why a feed head was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeadRejection {
    /// The tree did not verify through aqua-rs-sdk-core.
    #[error("feed head does not verify: {0}")]
    NotVerified(String),

    /// The tree verified but is not a feed head.
    #[error("submitted tree is not a feed head")]
    NotAFeedHead,

    /// The payload did not match the feed_head shape.
    #[error("feed head payload is malformed: {0}")]
    MalformedPayload(String),

    /// The tree carries no signature, or more than one signer.
    #[error("feed head signing is not a single signer: {0}")]
    Signing(String),

    /// The signer is not the DID the head claims to speak for.
    #[error("feed head signed by {signer} but claims to be {claimed}'s")]
    NotSelfCertifying {
        /// DID recovered from the signature.
        signer: String,
        /// DID named in the payload.
        claimed: String,
    },

    /// The head belongs to a different publisher than the one being followed.
    #[error("feed head is {actual}'s, not {expected}'s")]
    WrongPublisher {
        /// The publisher being followed.
        expected: String,
        /// Who actually signed.
        actual: String,
    },

    /// The construction version is not one this build implements.
    #[error("feed head uses leaf_version {found}, this build implements {supported}")]
    UnsupportedLeafVersion {
        /// The version declared.
        found: u64,
        /// The version implemented.
        supported: u64,
    },

    /// The recomputed root differs from the signed one.
    #[error(
        "feed head root mismatch over {covered} entries: signed {signed}, recomputed {recomputed}"
    )]
    RootMismatch {
        /// How many entries were hashed.
        covered: u64,
        /// The root the publisher signed.
        signed: String,
        /// The root the entries actually produce.
        recomputed: String,
    },

    /// The registry served fewer entries than a verified head covers.
    #[error("registry served {available} entries but a signed head covers {head_seq}: entries are being withheld")]
    Withholding {
        /// What the registry offered.
        available: u64,
        /// What the publisher signed for.
        head_seq: u64,
    },

    /// A head went backwards relative to one already verified.
    #[error("feed head went backwards: previously verified {previous}, now offered {offered}")]
    Rollback {
        /// The highest head_seq previously verified.
        previous: u64,
        /// What is on offer now.
        offered: u64,
    },

    /// A head was verified before but the registry no longer serves one.
    #[error("a feed head covering {previous} entries was verified before, but the registry now serves none")]
    Disappeared {
        /// The head_seq last verified.
        previous: u64,
    },

    /// Two heads at the same height disagree.
    #[error("two heads at height {head_seq} disagree: {a} and {b}")]
    ForkedHead {
        /// The height.
        head_seq: u64,
        /// One root.
        a: String,
        /// The other.
        b: String,
    },
}

impl HeadRejection {
    /// Short stable label for logs and CLI output.
    pub fn code(&self) -> &'static str {
        match self {
            HeadRejection::NotVerified(_) => "HEAD_NOT_VERIFIED",
            HeadRejection::NotAFeedHead => "NOT_A_FEED_HEAD",
            HeadRejection::MalformedPayload(_) => "HEAD_MALFORMED_PAYLOAD",
            HeadRejection::Signing(_) => "HEAD_SIGNING",
            HeadRejection::NotSelfCertifying { .. } => "HEAD_NOT_SELF_CERTIFYING",
            HeadRejection::WrongPublisher { .. } => "HEAD_WRONG_PUBLISHER",
            HeadRejection::UnsupportedLeafVersion { .. } => "HEAD_UNSUPPORTED_LEAF_VERSION",
            HeadRejection::RootMismatch { .. } => "HEAD_ROOT_MISMATCH",
            HeadRejection::Withholding { .. } => "HEAD_WITHHOLDING",
            HeadRejection::Rollback { .. } => "HEAD_ROLLBACK",
            HeadRejection::Disappeared { .. } => "HEAD_DISAPPEARED",
            HeadRejection::ForkedHead { .. } => "HEAD_FORKED",
        }
    }
}

/// A feed head whose tree verified and whose signer is who it claims to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedHead {
    /// The publisher DID, recovered from the signature.
    pub publisher_did: String,
    /// Entries covered.
    pub head_seq: u64,
    /// The signed root.
    pub merkle_root: String,
    /// Construction version.
    pub leaf_version: u64,
    /// When the publisher committed.
    pub covered_at: u64,
    /// Tip hash of the head tree itself.
    pub tree_tip: String,
}

/// Verify a feed head tree: signature, shape, and self-certification.
///
/// Does NOT check the root against any entries; that needs the entries and is
/// [`check_against_entries`]. Splitting them keeps this usable at ingest, where
/// the registry has the entries, and at sync, where the subscriber has a
/// different (possibly withheld) view of them.
///
/// `expected_publisher` narrows the head to one DID. Pass `None` at ingest,
/// where any publisher may submit their own head, and `Some` when following a
/// specific one.
pub async fn verify_head(
    aquafier: &Aquafier,
    head_json: &str,
    expected_publisher: Option<&str>,
) -> std::result::Result<VerifiedHead, HeadRejection> {
    let tree: Tree = serde_json::from_str(head_json)
        .map_err(|e| HeadRejection::NotVerified(format!("not a tree: {e}")))?;

    let tip = tree
        .get_latest_revision_link()
        .ok_or_else(|| HeadRejection::NotVerified("tree has no tip".to_string()))?;

    let result = aquafier
        .verify_aqua_tree_with_linked_trees(
            AquaTreeWrapper::new(tree.clone(), None, None),
            templates::linked_trees(),
            vec![],
        )
        .await
        .map_err(|e| HeadRejection::NotVerified(e.to_string()))?;

    if !result.is_verified() {
        let detail = result
            .errors()
            .iter()
            .map(|e| format!("{}: {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(HeadRejection::NotVerified(if detail.is_empty() {
            format!("{:?}", result.outcome)
        } else {
            detail
        }));
    }

    // Exactly one typed object, and it must be a feed head. A registration
    // tree verifies just as well, so without this a template registration
    // could be presented as a head.
    let objects: Vec<_> = tree
        .revisions
        .iter()
        .filter_map(|(h, r)| r.as_object().map(|o| (h.clone(), o)))
        .collect();
    let (object_hash, object) = match objects.len() {
        1 => objects.into_iter().next().expect("len checked"),
        _ => return Err(HeadRejection::NotAFeedHead),
    };
    if object.revision_type() != templates::feed_head_link() {
        return Err(HeadRejection::NotAFeedHead);
    }
    // Belt and braces: a registration type must never reach here.
    debug_assert_eq!(
        templates::kind_for_link(object.revision_type()),
        Option::<RegistrationKind>::None
    );

    let signatures = tree.get_signatures_for(&object_hash);
    let signers: std::collections::BTreeSet<String> = signatures
        .iter()
        .filter_map(|(_, r)| match r {
            aqua_rs_sdk_core::schema::AnyRevision::Signature(s) => Some(s.signer().to_string()),
            _ => None,
        })
        .collect();
    let signer = match signers.len() {
        0 => return Err(HeadRejection::Signing("unsigned".to_string())),
        1 => signers.into_iter().next().expect("len checked"),
        n => return Err(HeadRejection::Signing(format!("{n} distinct signers"))),
    };

    let payload: FeedHead = serde_json::from_value(object.payloads().clone())
        .map_err(|e| HeadRejection::MalformedPayload(e.to_string()))?;

    if payload.signer_did != signer {
        return Err(HeadRejection::NotSelfCertifying {
            signer,
            claimed: payload.signer_did,
        });
    }

    if let Some(expected) = expected_publisher {
        if expected != signer {
            return Err(HeadRejection::WrongPublisher {
                expected: expected.to_string(),
                actual: signer,
            });
        }
    }

    if payload.leaf_version != LEAF_VERSION {
        return Err(HeadRejection::UnsupportedLeafVersion {
            found: payload.leaf_version,
            supported: LEAF_VERSION,
        });
    }

    Ok(VerifiedHead {
        publisher_did: signer,
        head_seq: payload.head_seq,
        merkle_root: payload.merkle_root,
        leaf_version: payload.leaf_version,
        covered_at: payload.covered_at,
        tree_tip: tip.to_string(),
    })
}

/// Check a verified head against the entries actually on hand.
///
/// `tips` are the publisher's entry tips in feed order, as the caller received
/// them. Fewer than `head_seq` means the source is withholding. More is fine
/// and expected: a head covers a prefix, and a publisher signs heads less often
/// than they publish.
pub fn check_against_entries(
    head: &VerifiedHead,
    tips: &[String],
) -> std::result::Result<(), HeadRejection> {
    let available = tips.len() as u64;
    if available < head.head_seq {
        return Err(HeadRejection::Withholding {
            available,
            head_seq: head.head_seq,
        });
    }

    let covered = &tips[..head.head_seq as usize];
    let recomputed =
        compute_root(covered).map_err(|e| HeadRejection::MalformedPayload(e.to_string()))?;

    if !recomputed.eq_ignore_ascii_case(&head.merkle_root) {
        return Err(HeadRejection::RootMismatch {
            covered: head.head_seq,
            signed: head.merkle_root.clone(),
            recomputed,
        });
    }
    Ok(())
}

/// Check a head against what was verified before, catching rollback and forks.
///
/// `previous` is the highest head this subscriber has already verified, if any.
pub fn check_against_previous(
    head: &VerifiedHead,
    previous_seq: Option<u64>,
    previous_root: Option<&str>,
) -> std::result::Result<(), HeadRejection> {
    let Some(previous_seq) = previous_seq else {
        return Ok(());
    };

    if head.head_seq < previous_seq {
        return Err(HeadRejection::Rollback {
            previous: previous_seq,
            offered: head.head_seq,
        });
    }

    // Same height must mean the same root. A publisher signing two different
    // roots at one height has equivocated, and there is no honest reading of it.
    if head.head_seq == previous_seq {
        if let Some(previous_root) = previous_root {
            if !previous_root.eq_ignore_ascii_case(&head.merkle_root) {
                return Err(HeadRejection::ForkedHead {
                    head_seq: head.head_seq,
                    a: previous_root.to_string(),
                    b: head.merkle_root.clone(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(n: u8) -> String {
        format!("0x1620{}", hex::encode([n; 32]))
    }

    #[test]
    fn leaf_preimage_is_ordinal_separator_tip() {
        // The exact bytes documented in the README and the module header.
        let p = leaf_preimage(7, "0xABCD");
        assert_eq!(p[0], b'7');
        assert_eq!(p[1], 0x1f);
        // The tip is lowercased so a case variation cannot produce two roots.
        assert_eq!(&p[2..], b"0xabcd");
    }

    #[test]
    fn the_separator_prevents_ordinal_tip_collisions() {
        // Without a separator, (1, "0x12") and (11, "0x2") would share a
        // preimage. With one they cannot.
        assert_ne!(leaf_preimage(1, "0x12"), leaf_preimage(11, "0x2"));
    }

    #[test]
    fn leaf_uses_the_rfc6962_prefix() {
        // Domain separation is what stops a leaf being read as an internal node.
        let expected = merkle::batch_leaf_hash(&HashType::Sha3_256, &leaf_preimage(1, &tip(1)));
        assert_eq!(leaf_hash(1, &tip(1)), expected);
    }

    #[test]
    fn root_is_stable_and_position_sensitive() {
        // Same entries, same root.
        let a = compute_root(&[tip(1), tip(2), tip(3)]).unwrap();
        let b = compute_root(&[tip(1), tip(2), tip(3)]).unwrap();
        assert_eq!(a, b);

        // Swapping two entries changes the root, because the ordinal is inside
        // the leaf. A construction over tips alone would miss this.
        let reordered = compute_root(&[tip(2), tip(1), tip(3)]).unwrap();
        assert_ne!(a, reordered);
    }

    #[test]
    fn root_is_prefix_sensitive() {
        // A head over 3 entries must not equal a head over 2 of them.
        let two = compute_root(&[tip(1), tip(2)]).unwrap();
        let three = compute_root(&[tip(1), tip(2), tip(3)]).unwrap();
        assert_ne!(two, three);
    }

    #[test]
    fn single_entry_root_is_the_leaf() {
        // core's merkle_root returns the leaf for a one-leaf tree.
        let root = compute_root(&[tip(9)]).unwrap();
        assert_eq!(root, format!("0x{}", hex::encode(leaf_hash(1, &tip(9)))));
    }

    #[test]
    fn empty_head_is_refused() {
        // head_seq 0 has no root to speak of, and the schema forbids it too.
        assert!(compute_root(&[]).is_err());
    }

    #[test]
    fn root_format_is_a_bare_lowercase_digest() {
        let root = compute_root(&[tip(1), tip(2)]).unwrap();
        assert_eq!(root.len(), 66);
        assert!(root.starts_with("0x"));
        assert!(root[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn withholding_is_detected() {
        let tips = vec![tip(1), tip(2), tip(3)];
        let head = VerifiedHead {
            publisher_did: "did:key:z6Mk".into(),
            head_seq: 3,
            merkle_root: compute_root(&tips).unwrap(),
            leaf_version: LEAF_VERSION,
            covered_at: 0,
            tree_tip: "0x00".into(),
        };
        assert!(check_against_entries(&head, &tips).is_ok());

        // Two entries offered against a head covering three.
        let err = check_against_entries(&head, &tips[..2]).unwrap_err();
        assert!(matches!(
            err,
            HeadRejection::Withholding {
                available: 2,
                head_seq: 3
            }
        ));
    }

    #[test]
    fn extra_entries_beyond_the_head_are_fine() {
        // A head covers a prefix. Publishing more than the last head covers is
        // the normal state of affairs, not an error.
        let covered = vec![tip(1), tip(2)];
        let head = VerifiedHead {
            publisher_did: "did:key:z6Mk".into(),
            head_seq: 2,
            merkle_root: compute_root(&covered).unwrap(),
            leaf_version: LEAF_VERSION,
            covered_at: 0,
            tree_tip: "0x00".into(),
        };
        let more = vec![tip(1), tip(2), tip(3), tip(4)];
        assert!(check_against_entries(&head, &more).is_ok());
    }

    #[test]
    fn substituted_entry_is_detected() {
        let covered = vec![tip(1), tip(2), tip(3)];
        let head = VerifiedHead {
            publisher_did: "did:key:z6Mk".into(),
            head_seq: 3,
            merkle_root: compute_root(&covered).unwrap(),
            leaf_version: LEAF_VERSION,
            covered_at: 0,
            tree_tip: "0x00".into(),
        };
        let swapped = vec![tip(1), tip(99), tip(3)];
        let err = check_against_entries(&head, &swapped).unwrap_err();
        assert!(matches!(err, HeadRejection::RootMismatch { .. }));
        assert_eq!(err.code(), "HEAD_ROOT_MISMATCH");
    }

    #[test]
    fn rollback_and_forks_are_detected() {
        let head = VerifiedHead {
            publisher_did: "did:key:z6Mk".into(),
            head_seq: 5,
            merkle_root: "0xaa".into(),
            leaf_version: LEAF_VERSION,
            covered_at: 0,
            tree_tip: "0x00".into(),
        };

        // Nothing seen before: anything goes.
        assert!(check_against_previous(&head, None, None).is_ok());
        // Forward progress is fine.
        assert!(check_against_previous(&head, Some(3), Some("0xbb")).is_ok());
        // Same height, same root: an idempotent re-fetch.
        assert!(check_against_previous(&head, Some(5), Some("0xaa")).is_ok());

        // Backwards is a rollback.
        let err = check_against_previous(&head, Some(9), Some("0xbb")).unwrap_err();
        assert!(matches!(
            err,
            HeadRejection::Rollback {
                previous: 9,
                offered: 5
            }
        ));

        // Same height, different root: the publisher equivocated.
        let err = check_against_previous(&head, Some(5), Some("0xcc")).unwrap_err();
        assert!(matches!(err, HeadRejection::ForkedHead { head_seq: 5, .. }));
    }
}
