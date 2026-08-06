//! # aqua-template-registry
//!
//! A publisher-DID scoped registry for Aqua templates.
//!
//! Publishers register templates under a vendor namespace they own; consumers
//! subscribe to a publisher DID and fetch templates by name or by hash. It is
//! the distribution layer that [`aqua-rs-sdk-core`](https://github.com/inblockio/aqua-rs-sdk-core)
//! deliberately leaves out: core knows how to hash, sign, and verify a template,
//! and says nothing about how you find one.
//!
//! ## What a registration is
//!
//! Not an API write. A registration is a **signed Aqua tree** that the publisher
//! builds themselves (see [`publisher`]) and POSTs whole. The registry verifies
//! it with `aqua-rs-sdk-core` under a strict policy, reads the publisher DID off
//! the signature revision, applies the trust rules from spec-type-registry.md
//! section 3.7, and stores the tree bytes verbatim. Consumers can fetch those
//! bytes back and re-verify them, so nobody has to trust the registry.
//!
//! ## Trust model in one paragraph
//!
//! A `vendor-registration` is self-certifying: it is accepted only if the tree's
//! signer DID equals the `vendor_did` inside it. Namespaces are then first come,
//! first served. Every later `template-registration` or `alias-registration`
//! naming that namespace must be signed by the same DID. The registry decides
//! nothing about who is trustworthy; consumers subscribe to DIDs they already
//! trust.
//!
//! ## Quickstart (library)
//!
//! ```rust,no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use aqua_template_registry::{publisher, Registry};
//! use aqua_template_registry::model::TemplateRegistration;
//!
//! let registry = Registry::open("./data")?;
//! let key = publisher::PublisherKey::generate()?;
//!
//! // 1. Claim a namespace.
//! let tree = publisher::vendor_registration(
//!     registry.aquafier(), &key, "acme", Some("ACME Corp"),
//! ).await?;
//! registry.submit_vendor(&publisher::to_json(&tree)?).await?;
//!
//! // 2. Register a template into it.
//! let tree = publisher::template_registration(
//!     registry.aquafier(),
//!     &key,
//!     TemplateRegistration {
//!         vendor: "acme".into(),
//!         name: "invoice".into(),
//!         template_hash: format!("0x{}", "ab".repeat(32)),
//!         supersedes: None,
//!         display_name: None,
//!         description: None,
//!         daemon_trigger: None,
//!         file_dependency: None,
//!     },
//! ).await?;
//! registry.submit_template(&publisher::to_json(&tree)?).await?;
//!
//! // 3. Consumers resolve, or subscribe by DID.
//! let hit = registry.resolve("acme", "invoice")?;
//! let page = registry.feed(key.did(), 0, None);
//! # let _ = (hit, page);
//! # Ok(())
//! # }
//! ```
//!
//! ## Non-goals
//!
//! No on-chain registry, no SWARM or other content-addressed transport, no trust
//! store, no plugin or WASM distribution. See the README.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod model;
pub mod name;
pub mod publisher;
pub mod registry;
pub mod store;
pub mod templates;
pub mod verify;

#[cfg(feature = "server")]
pub mod http;

pub use error::{RegistryError, Result};
pub use model::{
    AliasRecord, AliasRegistration, FeedEntry, FeedPage, Receipt, RegistrationKind,
    RegistrationPayload, Resolution, ResolutionVia, Stats, TemplateRecord, TemplateRegistration,
    VendorRecord, VendorRegistration,
};
pub use name::{NameError, NameValidator};
pub use registry::Registry;
pub use store::Store;
