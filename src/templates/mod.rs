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

/// All three template trees, wrapped for `verify_aqua_tree_with_linked_trees`.
///
/// Passing all three on every verification costs three extra single-revision
/// tree verifications and removes any need for the submitter to embed the
/// template themselves. Submitters who do embed it still verify: core's
/// `resolve_template` checks the tree's own revisions before the linked trees.
pub fn linked_trees() -> Vec<AquaTreeWrapper> {
    all()
        .iter()
        .map(|t| AquaTreeWrapper::new(t.tree.clone(), None, None))
        .collect()
}

/// The three templates, for introspection endpoints and tests.
pub fn catalog() -> &'static [RegistrationTemplate] {
    all().as_slice()
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
    fn three_linked_trees_are_offered() {
        assert_eq!(linked_trees().len(), 3);
    }
}
