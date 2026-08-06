//! Turning a submitted JSON blob into an accepted registration.
//!
//! Registration is not an API write. A publisher submits the full signed Aqua
//! tree they built elsewhere, and the registry re-derives everything it will
//! index from that tree. Nothing a caller says outside the tree is trusted: the
//! publisher DID comes from the tree's signature revision, not from a header,
//! a query parameter, or a field the caller could set freely.
//!
//! The acceptance pipeline, in order:
//!
//! 1. Parse the body as an Aqua tree.
//! 2. Verify it with `aqua-rs-sdk-core`, handing it the three vendored
//!    registration templates as linked trees so the object's type resolves.
//!    Verification runs under `VerificationPolicy::strict()`: a tree whose
//!    template cannot be resolved is rejected, never tolerated.
//! 3. Require exactly one typed object, and require its template hash to be one
//!    of the three registration templates. A tree that verifies but carries some
//!    other type is not a registration.
//! 4. Require at least one signature over that object, and require every
//!    signature to come from the same DID. That DID is the publisher.
//! 5. Decode the payload into the matching Rust struct and canonicalize its
//!    names per spec-type-registry.md section 3.3.
//!
//! Steps 3 and 4 are what stop a caller from submitting an arbitrary verified
//! tree and having the registry index it. The publisher-DID trust rules from
//! section 3.7 (self-certifying vendor registrations, namespace ownership) are
//! applied one layer up, in [`crate::registry`], because they need the index.

use std::collections::BTreeSet;

use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AnyRevision, AquaTreeWrapper};
use aqua_rs_sdk_core::Aquafier;

use crate::error::{RegistryError, Result};
use crate::model::{
    AliasRegistration, RegistrationKind, RegistrationPayload, TemplateRegistration,
    VendorRegistration,
};
use crate::name::NameValidator;
use crate::templates;

/// A submission that passed cryptographic acceptance and payload decoding, but
/// not yet the index-level trust rules.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// Which registration template the object used.
    pub kind: RegistrationKind,
    /// DID recovered from the signature revision. The publisher.
    pub publisher_did: String,
    /// Tip revision hash of the tree (0x-prefixed hex).
    pub tree_tip: String,
    /// Decoded payload.
    pub payload: RegistrationPayload,
    /// Canonical vendor name (NFC, Latin case-folded).
    pub vendor: String,
    /// Canonical template or alias name. Empty for a vendor registration.
    pub name: String,
    /// The tree itself, unmodified.
    pub tree: Tree,
    /// The exact bytes that were submitted, stored verbatim. Never
    /// re-serialized: a re-serialization could reorder keys and the stored blob
    /// would no longer be the thing the publisher signed.
    pub raw: String,
}

impl Accepted {
    /// Canonical name this registration claims: `<vendor>/<name>`, or just the
    /// vendor name for a vendor registration.
    pub fn qualified_name(&self) -> String {
        if self.name.is_empty() {
            self.vendor.clone()
        } else {
            crate::name::qualified(&self.vendor, &self.name)
        }
    }
}

/// Parse a submitted body into a tree without verifying it.
pub fn parse_tree(body: &str) -> Result<Tree> {
    serde_json::from_str::<Tree>(body).map_err(|e| RegistryError::MalformedTree(e.to_string()))
}

/// Run the full acceptance pipeline over a submitted body.
///
/// `expected` narrows the accepted kind, so `POST /vendors` cannot be used to
/// slip in a template registration. Pass `None` to accept any of the three.
pub async fn accept(
    aquafier: &Aquafier,
    body: &str,
    expected: Option<RegistrationKind>,
) -> Result<Accepted> {
    let tree = parse_tree(body)?;

    let tip = tree
        .get_latest_revision_link()
        .ok_or(RegistryError::EmptyTree)?;

    // ---- 2. cryptographic verification -------------------------------------
    // The vendored registration templates are handed over as linked trees. Core
    // verifies each linked tree first and only then uses it to resolve types,
    // so a template tree that did not itself verify cannot be used to satisfy a
    // type reference.
    let result = aquafier
        .verify_aqua_tree_with_linked_trees(
            AquaTreeWrapper::new(tree.clone(), None, None),
            templates::linked_trees(),
            vec![],
        )
        .await
        .map_err(|e| RegistryError::Core(e.to_string()))?;

    if !result.is_verified() {
        let detail = result
            .errors()
            .iter()
            .map(|e| format!("{}: {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RegistryError::TreeNotVerified(if detail.is_empty() {
            format!("{:?}", result.outcome)
        } else {
            detail
        }));
    }

    // ---- 3. exactly one typed object, of a registration type ----------------
    let objects: Vec<_> = tree
        .revisions
        .iter()
        .filter_map(|(hash, rev)| rev.as_object().map(|obj| (hash.clone(), obj)))
        .collect();

    let (object_hash, object) = match objects.len() {
        1 => objects.into_iter().next().expect("len checked"),
        n => return Err(RegistryError::AmbiguousRegistration(n)),
    };

    let kind =
        templates::kind_for_link(object.revision_type()).ok_or(RegistryError::NotARegistration)?;

    if let Some(want) = expected {
        if kind != want {
            return Err(RegistryError::WrongRegistrationKind {
                submitted: kind.as_str(),
                expected: want.as_str(),
            });
        }
    }

    // ---- 4. signature over that object, one signer --------------------------
    // `get_signatures_for` walks the signature branches attached to the given
    // revision, so this asserts the signature actually covers the registration
    // object rather than merely existing somewhere in the tree.
    let signatures = tree.get_signatures_for(&object_hash);
    if signatures.is_empty() {
        return Err(RegistryError::Unsigned);
    }
    let signers: BTreeSet<String> = signatures
        .iter()
        .filter_map(|(_, rev)| match rev {
            AnyRevision::Signature(sig) => Some(sig.signer().to_string()),
            _ => None,
        })
        .collect();
    if signers.is_empty() {
        return Err(RegistryError::Unsigned);
    }
    if signers.len() > 1 {
        return Err(RegistryError::MultipleSigners(signers.len()));
    }
    let publisher_did = signers.into_iter().next().expect("len checked");

    // ---- 5. payload decode and name canonicalization ------------------------
    let raw_payload = object.payloads().clone();
    let (payload, vendor, name) = decode_payload(kind, raw_payload)?;

    Ok(Accepted {
        kind,
        publisher_did,
        tree_tip: tip.to_string(),
        payload,
        vendor,
        name,
        tree,
        raw: body.to_string(),
    })
}

/// Decode a registration payload and return the canonicalized `(vendor, name)`.
fn decode_payload(
    kind: RegistrationKind,
    value: serde_json::Value,
) -> Result<(RegistrationPayload, String, String)> {
    match kind {
        RegistrationKind::Vendor => {
            let p: VendorRegistration = serde_json::from_value(value)
                .map_err(|e| RegistryError::MalformedPayload(e.to_string()))?;
            if !p.vendor_did.starts_with("did:") {
                return Err(RegistryError::MalformedPayload(format!(
                    "vendor_did {:?} is not a DID",
                    p.vendor_did
                )));
            }
            let vendor = NameValidator::validate_vendor_name(&p.vendor_name)?;
            Ok((RegistrationPayload::Vendor(p), vendor, String::new()))
        }
        RegistrationKind::Template => {
            let p: TemplateRegistration = serde_json::from_value(value)
                .map_err(|e| RegistryError::MalformedPayload(e.to_string()))?;
            check_hash("template_hash", &p.template_hash)?;
            if let Some(s) = &p.supersedes {
                check_hash("supersedes", s)?;
            }
            let vendor = NameValidator::validate_vendor_name(&p.vendor)?;
            let name = NameValidator::validate_template_name(&p.name)?;
            Ok((RegistrationPayload::Template(p), vendor, name))
        }
        RegistrationKind::Alias => {
            let p: AliasRegistration = serde_json::from_value(value)
                .map_err(|e| RegistryError::MalformedPayload(e.to_string()))?;
            check_hash("target_hash", &p.target_hash)?;
            let vendor = NameValidator::validate_vendor_name(&p.vendor)?;
            let name = NameValidator::validate_template_name(&p.alias_name)?;
            Ok((RegistrationPayload::Alias(p), vendor, name))
        }
    }
}

/// A registered hash must be 0x-prefixed hex. The JSON Schema already enforces
/// 32 bytes for the fields it constrains, but the registry re-checks rather than
/// relying on a schema it only vendors.
fn check_hash(field: &'static str, value: &str) -> Result<()> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| RegistryError::InvalidHash {
            field,
            reason: "missing 0x prefix".to_string(),
        })?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(RegistryError::InvalidHash {
            field,
            reason: format!("{} hex digits is not a whole number of bytes", body.len()),
        });
    }
    hex::decode(body).map_err(|e| RegistryError::InvalidHash {
        field,
        reason: e.to_string(),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_must_be_0x_hex() {
        // Pins the hash field format check used on template_hash/supersedes/target_hash.
        assert!(check_hash("h", &format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(check_hash("h", &"ab".repeat(32)).is_err()); // no 0x
        assert!(check_hash("h", "0x").is_err()); // empty
        assert!(check_hash("h", "0xabc").is_err()); // odd length
        assert!(check_hash("h", "0xzz").is_err()); // not hex
    }

    #[test]
    fn vendor_payload_requires_a_did() {
        // A vendor registration that does not name a DID cannot be self-certifying.
        let v = serde_json::json!({"vendor_name": "inblock", "vendor_did": "0xabc"});
        let err = decode_payload(RegistrationKind::Vendor, v).unwrap_err();
        assert!(matches!(err, RegistryError::MalformedPayload(_)));
    }

    #[test]
    fn payload_names_are_canonicalized() {
        // Mixed-case Latin input is folded on the way into the index.
        let v = serde_json::json!({
            "vendor": "InBlock",
            "name": "Email-Claim",
            "template_hash": format!("0x{}", "ab".repeat(32)),
        });
        let (_, vendor, name) = decode_payload(RegistrationKind::Template, v).unwrap();
        assert_eq!(vendor, "inblock");
        assert_eq!(name, "email-claim");
    }

    #[test]
    fn unknown_payload_fields_are_rejected() {
        // The vendored schemas are additionalProperties:false, and so are we.
        let v = serde_json::json!({
            "vendor_name": "inblock",
            "vendor_did": "did:key:z6Mk",
            "surprise": 1,
        });
        assert!(decode_payload(RegistrationKind::Vendor, v).is_err());
    }

    #[test]
    fn mixed_script_names_are_rejected_at_decode() {
        // Latin plus Cyrillic homoglyph, per spec section 3.3.
        let v = serde_json::json!({
            "vendor_name": "inbl\u{043E}ck",
            "vendor_did": "did:key:z6Mk",
        });
        let err = decode_payload(RegistrationKind::Vendor, v).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidName(_)));
    }

    #[test]
    fn malformed_body_is_not_a_tree() {
        assert!(matches!(
            parse_tree("not json"),
            Err(RegistryError::MalformedTree(_))
        ));
    }
}
