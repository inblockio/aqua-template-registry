//! Publisher-side helpers: build and sign registration trees.
//!
//! A registration is a signed Aqua tree, so a publisher needs a way to make one.
//! The full `aqua-rs-sdk` has `registry::workflow` for this, but this crate
//! depends only on `aqua-rs-sdk-core`, and a registry whose own quickstart
//! requires a different SDK is not a quickstart. Everything here is a thin
//! wrapper over core: `create_object` with the vendored template hash, then
//! `sign_aqua_tree` with the publisher's key.
//!
//! Nothing in this module is privileged. A publisher can build the same tree
//! with any tooling; the registry only ever sees the finished bytes.

use aqua_rs_sdk_core::core::signature::sign_did::DIDSigner;
use aqua_rs_sdk_core::primitives::{Method, Nonce};
use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AquaTreeWrapper, SigningCredentials};
use aqua_rs_sdk_core::Aquafier;

use crate::error::{RegistryError, Result};
use crate::model::{
    AliasRegistration, RegistrationPayload, TemplateRegistration, VendorRegistration,
};
use crate::templates;

/// An Ed25519 publisher identity: a 32-byte seed and the `did:key` it derives.
#[derive(Clone)]
pub struct PublisherKey {
    seed: [u8; 32],
    did: String,
}

impl std::fmt::Debug for PublisherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the seed.
        f.debug_struct("PublisherKey")
            .field("did", &self.did)
            .finish()
    }
}

impl PublisherKey {
    /// Derive a publisher identity from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let did = DIDSigner::new()
            .derive_did(&seed)
            .map_err(|e| RegistryError::Core(e.to_string()))?;
        Ok(Self { seed, did })
    }

    /// Generate a fresh publisher identity.
    ///
    /// Entropy comes from `aqua-rs-sdk-core`'s `Nonce::random()`, taken twice.
    /// Core exposes no keypair generator of its own (see the README's notes on
    /// core), and pulling in a second RNG and a second `ed25519-dalek` here
    /// would risk a version skew against the one core signs with.
    pub fn generate() -> Result<Self> {
        let a = Nonce::random();
        let b = Nonce::random();
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(AsRef::<[u8]>::as_ref(&a));
        seed[16..].copy_from_slice(AsRef::<[u8]>::as_ref(&b));
        Self::from_seed(seed)
    }

    /// The `did:key:z6Mk...` identifier for this key. This is the publisher DID
    /// that consumers subscribe to.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The raw seed. Handle accordingly.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Signing credentials for `Aquafier::sign_aqua_tree`.
    pub fn credentials(&self) -> SigningCredentials {
        SigningCredentials::Did {
            did_key: self.seed.to_vec(),
        }
    }
}

/// Build and sign a registration tree for any of the three payload kinds.
///
/// The tree is a genesis anchor linking to the vendored registration template,
/// the typed object carrying the payload, and one signature revision over that
/// object. The template itself is not embedded: the registry supplies it as a
/// linked tree at verification time, which keeps the published bytes minimal.
pub async fn build(
    aquafier: &Aquafier,
    key: &PublisherKey,
    payload: &RegistrationPayload,
) -> Result<Tree> {
    let kind = payload.kind();
    let value = match payload {
        RegistrationPayload::Vendor(p) => serde_json::to_value(p),
        RegistrationPayload::Template(p) => serde_json::to_value(p),
        RegistrationPayload::Alias(p) => serde_json::to_value(p),
    }
    .map_err(|e| RegistryError::MalformedPayload(e.to_string()))?;

    let unsigned = aquafier
        .create_object(
            templates::link(kind).clone(),
            None,
            value,
            Some(Method::Scalar),
        )
        .map_err(|e| RegistryError::Core(e.to_string()))?;

    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(unsigned, None, None),
            &key.credentials(),
            None,
            None,
        )
        .await
        .map_err(|e| RegistryError::Core(e.to_string()))?;

    Ok(signed.aqua_tree)
}

/// Build and sign a vendor registration claiming `vendor_name` for `key`.
///
/// The `vendor_did` is filled in from the key, because a vendor registration
/// that names any other DID is rejected as not self-certifying.
pub async fn vendor_registration(
    aquafier: &Aquafier,
    key: &PublisherKey,
    vendor_name: &str,
    display_name: Option<&str>,
) -> Result<Tree> {
    let payload = RegistrationPayload::Vendor(VendorRegistration {
        vendor_name: vendor_name.to_string(),
        display_name: display_name.map(str::to_string),
        vendor_did: key.did().to_string(),
    });
    build(aquafier, key, &payload).await
}

/// Build and sign a template registration.
pub async fn template_registration(
    aquafier: &Aquafier,
    key: &PublisherKey,
    registration: TemplateRegistration,
) -> Result<Tree> {
    build(aquafier, key, &RegistrationPayload::Template(registration)).await
}

/// Build and sign an alias registration.
pub async fn alias_registration(
    aquafier: &Aquafier,
    key: &PublisherKey,
    vendor: &str,
    alias_name: &str,
    target_hash: &str,
) -> Result<Tree> {
    let payload = RegistrationPayload::Alias(AliasRegistration {
        vendor: vendor.to_string(),
        alias_name: alias_name.to_string(),
        target_hash: target_hash.to_string(),
    });
    build(aquafier, key, &payload).await
}

/// Serialize a tree to the JSON a publisher POSTs to the registry.
pub fn to_json(tree: &Tree) -> Result<String> {
    serde_json::to_string(tree).map_err(|e| RegistryError::Core(e.to_string()))
}

/// Serialize a tree to indented JSON, for a readable `curl -d @file`.
pub fn to_json_pretty(tree: &Tree) -> Result<String> {
    serde_json::to_string_pretty(tree).map_err(|e| RegistryError::Core(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_seed_is_deterministic() {
        // Same seed, same DID. Tests depend on this for reproducible fixtures.
        let a = PublisherKey::from_seed([3u8; 32]).unwrap();
        let b = PublisherKey::from_seed([3u8; 32]).unwrap();
        assert_eq!(a.did(), b.did());
        assert!(a.did().starts_with("did:key:z6Mk"));
    }

    #[test]
    fn generated_keys_differ() {
        let a = PublisherKey::generate().unwrap();
        let b = PublisherKey::generate().unwrap();
        assert_ne!(a.did(), b.did());
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let k = PublisherKey::from_seed([9u8; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(!s.contains("999"));
        assert!(s.contains("did:key:"));
    }
}
