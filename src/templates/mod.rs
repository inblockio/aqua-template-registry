//! The three vendored registration template definitions.
//!
//! `aqua-rs-sdk-core` deliberately ships no registration templates: it is the
//! WASM-free protocol core and template distribution is out of its scope. This
//! registry therefore vendors the three definitions itself, as byte-identical
//! copies of the files in `aqua-rs-sdk/src/schema/templates/`.
//!
//! **Byte identity is the whole point.** A template's hash is its type identity.
//! One changed byte (even reordered whitespace) produces a different hash, which
//! produces a different type, which makes every tree built against it
//! unverifiable by anyone using the full SDK. Never reformat these files. The
//! `#[ignore]`d tests in `tests/cross_sdk.rs` assert our computed hashes equal
//! the full SDK's `VendorRegistration::TEMPLATE_LINK` and friends.
//!
//! Vendoring these files also exercises `aqua-rs-sdk-core`'s custom-template
//! path end to end: parse JSON into [`Template`], hash it with
//! `calculate_link(HashType::Sha3_256)`, wrap it in a single-revision [`Tree`],
//! and hand that tree to the verifier as a linked tree so the object's type
//! resolves. Nothing here hand-rolls a hash.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aqua_rs_sdk_core::primitives::{HashType, RevisionLink};
use aqua_rs_sdk_core::schema::template::Template;
use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AnyRevision, AquaTreeWrapper};
use aqua_rs_sdk_core::verification::Linkable;

use crate::model::RegistrationKind;

/// Byte-identical copy of `aqua-rs-sdk/src/schema/templates/vendor_registration.json`.
pub const VENDOR_REGISTRATION_JSON: &str = include_str!("vendor_registration.json");
/// Byte-identical copy of `aqua-rs-sdk/src/schema/templates/template_registration.json`.
pub const TEMPLATE_REGISTRATION_JSON: &str = include_str!("template_registration.json");
/// Byte-identical copy of `aqua-rs-sdk/src/schema/templates/alias_registration.json`.
pub const ALIAS_REGISTRATION_JSON: &str = include_str!("alias_registration.json");

/// The `feed_head` template, defined by THIS project rather than vendored.
///
/// The three registration templates above are copies of the full SDK's, and
/// their hashes are frozen ecosystem constants. This one is different: no SDK
/// defines a feed head, so this file is the definition, and its hash becomes a
/// constant the moment anything is published against it. It carries a pinned
/// nonce and `local_timestamp` for exactly that reason: both feed into the
/// hash, so leaving either to chance would mint a new type on every build.
///
/// Data only, like everything else here. No `verification` section, nothing to
/// execute, and no `derives_from`: a feed head is not an audit artifact and
/// does not belong to that family.
pub const FEED_HEAD_JSON: &str = include_str!("feed_head.json");

/// A parsed, hashed registration template plus the single-revision tree that
/// carries it to the verifier.
pub struct RegistrationTemplate {
    /// Which registration kind this template defines.
    pub kind: RegistrationKind,
    /// Name used in the tree's `file_index` and in diagnostics.
    pub name: &'static str,
    /// The raw JSON, byte for byte.
    pub json: &'static str,
    /// SHA3-256 identity of the template, as a multihash `RevisionLink`.
    pub link: RevisionLink,
    /// Single-revision tree wrapping the template, ready to pass as a linked
    /// tree at verification time.
    pub tree: Tree,
}

fn build(kind: RegistrationKind, name: &'static str, json: &'static str) -> RegistrationTemplate {
    // Parse with core's own Template type. `Template` is `deny_unknown_fields`,
    // so a drifted JSON file fails loudly here rather than hashing to something
    // plausible-looking.
    let template: Template = serde_json::from_str(json).unwrap_or_else(|e| {
        panic!("vendored template {name}.json does not parse as a core Template: {e}")
    });

    // Template ids are always SHA3-256 (PCA-0015 section 3.9), regardless of the
    // template's own `method`. Let core compute it; never hand-roll.
    let link = template
        .calculate_link(HashType::Sha3_256)
        .unwrap_or_else(|e| panic!("cannot hash vendored template {name}.json: {e}"));

    let mut revisions = BTreeMap::new();
    revisions.insert(link.clone(), AnyRevision::Template(template));
    let mut file_index = BTreeMap::new();
    file_index.insert(link.clone(), name.to_string());

    RegistrationTemplate {
        kind,
        name,
        json,
        link,
        tree: Tree {
            revisions,
            file_index,
        },
    }
}

fn all() -> &'static [RegistrationTemplate; 3] {
    static ALL: OnceLock<[RegistrationTemplate; 3]> = OnceLock::new();
    ALL.get_or_init(|| {
        [
            build(
                RegistrationKind::Vendor,
                "vendor_registration",
                VENDOR_REGISTRATION_JSON,
            ),
            build(
                RegistrationKind::Template,
                "template_registration",
                TEMPLATE_REGISTRATION_JSON,
            ),
            build(
                RegistrationKind::Alias,
                "alias_registration",
                ALIAS_REGISTRATION_JSON,
            ),
        ]
    })
}

/// The vendored template for a registration kind.
pub fn get(kind: RegistrationKind) -> &'static RegistrationTemplate {
    all()
        .iter()
        .find(|t| t.kind == kind)
        .expect("every RegistrationKind has a vendored template")
}

/// Template identity hash for a registration kind.
pub fn link(kind: RegistrationKind) -> &'static RevisionLink {
    &get(kind).link
}

/// Reverse lookup: which registration kind does this template hash denote?
///
/// Returns `None` for any other template, which is how the registry refuses
/// trees that verify fine but are not registrations.
pub fn kind_for_link(link_in: &RevisionLink) -> Option<RegistrationKind> {
    all().iter().find(|t| &t.link == link_in).map(|t| t.kind)
}

/// Every template this project defines, wrapped for
/// `verify_aqua_tree_with_linked_trees`.
///
/// That is the three registration templates plus `feed_head`. Passing all four
/// on every verification costs four extra single-revision tree verifications
/// and removes any need for the submitter to embed the template themselves.
/// Submitters who do embed it still verify: core's `resolve_template` checks
/// the tree's own revisions before the linked trees.
///
/// Offering a template does not accept it. What a given endpoint will accept is
/// decided afterwards by checking the object's own `revision_type`, so making
/// `feed_head` resolvable here does not make a feed head a valid registration.
pub fn linked_trees() -> Vec<AquaTreeWrapper> {
    all()
        .iter()
        .map(|t| AquaTreeWrapper::new(t.tree.clone(), None, None))
        .chain(std::iter::once(AquaTreeWrapper::new(
            feed_head_tree().clone(),
            None,
            None,
        )))
        .collect()
}

/// The three registration templates, for introspection endpoints and tests.
pub fn catalog() -> &'static [RegistrationTemplate] {
    all().as_slice()
}

// ---------------------------------------------------------------------------
// The feed_head template
// ---------------------------------------------------------------------------

fn feed_head_entry() -> &'static (RevisionLink, Tree) {
    static FEED_HEAD: OnceLock<(RevisionLink, Tree)> = OnceLock::new();
    FEED_HEAD.get_or_init(|| {
        let template: Template = serde_json::from_str(FEED_HEAD_JSON)
            .unwrap_or_else(|e| panic!("feed_head.json does not parse as a core Template: {e}"));
        let link = template
            .calculate_link(HashType::Sha3_256)
            .unwrap_or_else(|e| panic!("cannot hash feed_head.json: {e}"));
        let mut revisions = BTreeMap::new();
        revisions.insert(link.clone(), AnyRevision::Template(template));
        let mut file_index = BTreeMap::new();
        file_index.insert(link.clone(), "feed_head".to_string());
        (
            link,
            Tree {
                revisions,
                file_index,
            },
        )
    })
}

/// Identity hash of the `feed_head` template.
pub fn feed_head_link() -> &'static RevisionLink {
    &feed_head_entry().0
}

/// The `feed_head` template as a single-revision tree.
pub fn feed_head_tree() -> &'static Tree {
    &feed_head_entry().1
}

// ---------------------------------------------------------------------------
// Hashing arbitrary template definitions
// ---------------------------------------------------------------------------

/// Compute the identity `RevisionLink` of any template definition JSON.
///
/// This is the operation a publisher needs before they can register anything:
/// the `template_hash` in a `template-registration` is the SHA3-256 identity of
/// the template definition being published. Parsing goes through core's own
/// `Template` type, which is `deny_unknown_fields`, so a definition that is not
/// a well-formed template is rejected here rather than registered under a hash
/// nobody can resolve.
///
/// Template ids are always SHA3-256 (PCA-0015 section 3.9), regardless of the
/// template's own `method`.
pub fn link_of_definition(definition_json: &str) -> crate::error::Result<RevisionLink> {
    let template: Template = serde_json::from_str(definition_json).map_err(|e| {
        crate::error::RegistryError::MalformedPayload(format!(
            "not a well-formed template definition: {e}"
        ))
    })?;
    template
        .calculate_link(HashType::Sha3_256)
        .map_err(|e| crate::error::RegistryError::Core(e.to_string()))
}

/// Strip the `0x1620` SHA3-256 multihash prefix from a link, leaving the bare
/// 32-byte digest as `0x` plus 64 hex characters.
///
/// Core carries template ids on the wire as multihashes. The `template_hash`
/// field of a `template-registration` is the bare digest (its JSON Schema
/// constrains it to exactly 64 hex characters), and so is core's own
/// `tests/audit_template_hashes.txt` ledger. This is the conversion between
/// the two.
pub fn bare_digest(link: &RevisionLink) -> crate::error::Result<String> {
    let full = link.to_string();
    full.strip_prefix("0x1620")
        .filter(|rest| rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|rest| format!("0x{rest}"))
        .ok_or_else(|| crate::error::RegistryError::InvalidHash {
            field: "template_hash",
            reason: format!("{full} is not a SHA3-256 multihash link"),
        })
}

/// The bare `template_hash` of a template definition, ready to put straight
/// into a `template-registration` payload.
///
/// Equivalent to [`bare_digest`] of [`link_of_definition`]. This is the one
/// call a publisher usually wants.
pub fn template_hash_of_definition(definition_json: &str) -> crate::error::Result<String> {
    bare_digest(&link_of_definition(definition_json)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The vendored hashes are frozen constants of the ecosystem. If one of these
    // changes, the vendored JSON drifted and every previously registered tree
    // became unverifiable. These literals are the full SDK's TEMPLATE_LINK
    // values (see tests/cross_sdk.rs, which asserts equality against the SDK
    // itself rather than against a copied literal).
    const VENDOR_LINK_HEX: &str =
        "0x1620fe0db62677dad4b648e6ef2f4a96c64c98212765341be8e815388915f2c15b21";
    const TEMPLATE_LINK_HEX: &str =
        "0x1620a02b06af0daa6ecf19ca9495118a46af255a898445f71dd167900350a2f39197";
    const ALIAS_LINK_HEX: &str =
        "0x1620d82b8cb8caef2658cd6f529663dbf9e915f25c04a0b56807329562d39260f294";
    const FEED_HEAD_LINK_HEX: &str =
        "0x162077c13274ab93b2707017db0ba8e5b872fce94e86ba54064235bcb528d1879cb9";

    #[test]
    fn vendored_templates_parse_and_hash() {
        // Every vendored file parses as a core Template and hashes without error.
        for t in catalog() {
            assert!(
                !t.link.to_string().is_empty(),
                "{} must produce a link",
                t.name
            );
            assert_eq!(
                t.tree.revisions.len(),
                1,
                "{} tree is single-revision",
                t.name
            );
        }
    }

    #[test]
    fn vendored_hashes_are_frozen() {
        // Pins the type identities. A failure here means a vendored JSON changed.
        assert_eq!(link(RegistrationKind::Vendor).to_string(), VENDOR_LINK_HEX);
        assert_eq!(
            link(RegistrationKind::Template).to_string(),
            TEMPLATE_LINK_HEX
        );
        assert_eq!(link(RegistrationKind::Alias).to_string(), ALIAS_LINK_HEX);
    }

    #[test]
    fn kind_lookup_round_trips() {
        // The reverse index used to classify submissions.
        for kind in [
            RegistrationKind::Vendor,
            RegistrationKind::Template,
            RegistrationKind::Alias,
        ] {
            assert_eq!(kind_for_link(link(kind)), Some(kind));
        }
    }

    #[test]
    fn unknown_link_is_not_a_registration() {
        // A template hash we do not vendor must not classify as a registration.
        let other = RevisionLink::from_bytes([7u8; 32]);
        assert_eq!(kind_for_link(&other), None);
    }

    #[test]
    fn four_linked_trees_are_offered() {
        // Three registration templates plus feed_head.
        assert_eq!(linked_trees().len(), 4);
    }

    #[test]
    fn feed_head_parses_hashes_and_is_frozen() {
        // feed_head's hash is this project's own constant. It is pinned here so
        // that an accidental reformat of the JSON, or a change to its nonce or
        // local_timestamp, is caught rather than silently minting a new type
        // that no previously published head verifies against.
        let link = feed_head_link();
        assert_eq!(link.to_string(), FEED_HEAD_LINK_HEX);
        assert_eq!(&link_of_definition(FEED_HEAD_JSON).unwrap(), link);
        assert_eq!(feed_head_tree().revisions.len(), 1);
    }

    #[test]
    fn feed_head_is_not_a_registration_kind() {
        // It resolves as a linked tree but must never classify as a
        // registration, or a feed head could be POSTed to /templates.
        assert_eq!(kind_for_link(feed_head_link()), None);
    }

    #[test]
    fn feed_head_carries_no_executable_content() {
        // Data only, asserted rather than assumed.
        let v: serde_json::Value = serde_json::from_str(FEED_HEAD_JSON).unwrap();
        assert!(v.get("verification").is_none());
        assert!(v.get("derives_from").is_none());
    }

    #[test]
    fn definition_hashing_round_trips_against_our_own_templates() {
        // link_of_definition on a vendored file must reproduce that file's
        // frozen link, and bare_digest must strip exactly the 0x1620 prefix.
        for t in catalog() {
            let link = link_of_definition(t.json).expect("vendored template hashes");
            assert_eq!(&link, &t.link, "{} link mismatch", t.name);

            let bare = bare_digest(&link).expect("bare digest");
            assert_eq!(bare.len(), 66, "0x plus 64 hex characters");
            assert_eq!(format!("0x1620{}", &bare[2..]), link.to_string());

            assert_eq!(template_hash_of_definition(t.json).unwrap(), bare);
        }
    }

    #[test]
    fn definition_hashing_rejects_non_templates() {
        // A publisher pointing at the wrong file must find out here, not after
        // registering a hash nobody can resolve.
        assert!(link_of_definition("{}").is_err());
        assert!(link_of_definition("not json").is_err());
        assert!(link_of_definition(r#"{"schema":{},"surprise":1}"#).is_err());
    }
}
