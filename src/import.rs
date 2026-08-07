//! The consumer side: verify before trusting, then import.
//!
//! # What the registry proves, and what it does not
//!
//! Spec section 3.7 gives internal consistency: a vendor registration is signed
//! by the DID it names, and everything under that namespace is signed by the
//! same DID. That is a statement about a namespace being coherent. It is not a
//! statement about identity. Nothing in it stops anyone from generating a key,
//! claiming a free namespace, and publishing whatever they like, entirely
//! self-consistently.
//!
//! So a consumer needs a second, independent decision: whose templates am I
//! willing to run? That decision lives in [`crate::trust::ImportPolicy`], a
//! committed file listing publisher DIDs and pinned hashes. This module is the
//! gate that enforces it.
//!
//! # The chain
//!
//! Every one of these must pass before a template enters the local store. There
//! is no partial credit and no warn-and-continue:
//!
//! 1. The vendor registration tree verifies through `aqua-rs-sdk-core` under
//!    the strict policy, and is self-certifying (its signer DID equals the
//!    `vendor_did` it claims).
//! 2. That DID appears in `allowed_publishers`. An absent or empty list admits
//!    nothing. There is deliberately no trust on first use.
//! 3. The template registration tree verifies through core under the strict
//!    policy.
//! 4. Its signer DID equals the vendor's `vendor_did` from step 1.
//! 5. The definition body is within the size cap and carries no `verification`
//!    (WASM) section.
//! 6. The definition body, rehashed through core's `calculate_link`, equals the
//!    `template_hash` the registration claims.
//! 7. The pin check passes for the configured [`crate::trust::PinMode`].
//!
//! Step 6 is the one that is easy to leave out and fatal to leave out. A
//! registration is a signed claim that a name means a hash. It says nothing
//! about whether the bytes someone handed you are the bytes that hash to it.
//!
//! Note what is not consulted anywhere in that list: the registry's own derived
//! JSON. The chain re-derives the whole trust relationship from signed bytes
//! and content-addressed bodies, so a hostile or buggy registry cannot inject a
//! publisher, a name, or a body. See the README's trust-model section for what
//! a hostile registry can still do (withhold and reorder), which this does not
//! solve.
//!
//! # The local store is inert
//!
//! Imported templates are filed by hash, never by name: names are display data
//! chosen by the publisher, and two publishers can choose the same one. Nothing
//! activates on import. An application asks for a specific hash and gets a
//! template tree it can hand to core, which means the decision to use a
//! template is always an explicit, per-hash act in application code.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aqua_rs_sdk_core::primitives::HashType;
use aqua_rs_sdk_core::schema::template::Template;
use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AnyRevision, AquaTreeWrapper};
use aqua_rs_sdk_core::verification::Linkable;
use aqua_rs_sdk_core::Aquafier;
use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};
use crate::model::{RegistrationKind, RegistrationPayload};
use crate::trust::{ImportPolicy, PinDecision, PinMode, MAX_DEFINITION_BYTES};
use crate::verify;

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

/// Why a candidate did not make it into the store.
///
/// Every variant names the check that failed, so a caller can report precisely
/// what a publisher would have to change, and so the negative tests can assert
/// on the specific control rather than on "it errored".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportRejection {
    /// The registration tree did not verify through aqua-rs-sdk-core.
    #[error("registration does not verify: {0}")]
    NotVerified(String),

    /// The vendor registration names a different DID than the one that signed it.
    #[error("vendor registration is not self-certifying: signed by {signer}, claims {claimed}")]
    NotSelfCertifying {
        /// DID recovered from the signature.
        signer: String,
        /// DID the payload claims.
        claimed: String,
    },

    /// The publisher is not on the allow list. This is the identity gate.
    #[error("publisher {did} is not in allowed_publishers ({allowed} allowed)")]
    PublisherNotAllowed {
        /// The DID that signed.
        did: String,
        /// How many publishers the policy does allow.
        allowed: usize,
    },

    /// A template registration was signed by someone other than the namespace owner.
    #[error(
        "template in namespace {vendor:?} signed by {signer}, but the namespace belongs to {owner}"
    )]
    WrongSigner {
        /// The namespace written into.
        vendor: String,
        /// The DID that owns it.
        owner: String,
        /// The DID that signed this registration.
        signer: String,
    },

    /// The definition body does not hash to the registered `template_hash`.
    #[error(
        "definition for {qualified_name} hashes to {actual}, but the registration claims {claimed}"
    )]
    HashMismatch {
        /// Which template.
        qualified_name: String,
        /// What the registration claims.
        claimed: String,
        /// What the body actually hashes to.
        actual: String,
    },

    /// The definition body carries a `verification` (WASM) section.
    #[error("definition for {qualified_name} carries a verification (WASM) section; only data-only templates are imported")]
    CarriesWasm {
        /// Which template.
        qualified_name: String,
    },

    /// The definition body is over the size cap.
    #[error("definition for {qualified_name} is {bytes} bytes, over the {max} byte cap")]
    TooLarge {
        /// Which template.
        qualified_name: String,
        /// Size of the offered body.
        bytes: usize,
        /// The cap.
        max: usize,
    },

    /// No pin for this name, and the mode does not permit adding one.
    #[error("{qualified_name} is not pinned; re-run with ApproveNew to pin it")]
    NotPinned {
        /// Which template.
        qualified_name: String,
    },

    /// A pin exists for this name but names a different hash.
    #[error("{qualified_name} is pinned to {pinned} but the registry offered {offered}")]
    PinMismatch {
        /// Which template.
        qualified_name: String,
        /// The hash the policy pins.
        pinned: String,
        /// The hash the registry offered.
        offered: String,
    },

    /// The definition body is not a well-formed template.
    #[error("definition for {qualified_name} is not a template definition: {reason}")]
    MalformedDefinition {
        /// Which template.
        qualified_name: String,
        /// What went wrong.
        reason: String,
    },

    /// The registration was of the wrong kind for where it was used.
    #[error("expected a {expected} registration, got a {got}")]
    WrongKind {
        /// What was expected.
        expected: &'static str,
        /// What arrived.
        got: String,
    },
}

impl ImportRejection {
    /// A short stable label, for logs and CLI output.
    pub fn code(&self) -> &'static str {
        match self {
            ImportRejection::NotVerified(_) => "NOT_VERIFIED",
            ImportRejection::NotSelfCertifying { .. } => "NOT_SELF_CERTIFYING",
            ImportRejection::PublisherNotAllowed { .. } => "PUBLISHER_NOT_ALLOWED",
            ImportRejection::WrongSigner { .. } => "WRONG_SIGNER",
            ImportRejection::HashMismatch { .. } => "HASH_MISMATCH",
            ImportRejection::CarriesWasm { .. } => "CARRIES_WASM",
            ImportRejection::TooLarge { .. } => "TOO_LARGE",
            ImportRejection::NotPinned { .. } => "NOT_PINNED",
            ImportRejection::PinMismatch { .. } => "PIN_MISMATCH",
            ImportRejection::MalformedDefinition { .. } => "MALFORMED_DEFINITION",
            ImportRejection::WrongKind { .. } => "WRONG_KIND",
        }
    }
}

// ---------------------------------------------------------------------------
// Verified intermediates
// ---------------------------------------------------------------------------

/// A vendor namespace whose registration verified and whose owner is allowed.
///
/// Only obtainable from [`verify_vendor`], so a `TrustedVendor` value is itself
/// the proof that steps 1 and 2 of the chain passed. Nothing downstream has to
/// re-check, and nothing can skip ahead: [`verify_template`] takes one by
/// reference and cannot be called without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedVendor {
    /// Canonical vendor name.
    pub vendor: String,
    /// The DID that owns the namespace, recovered from the signature.
    pub vendor_did: String,
    /// The signed vendor registration, verbatim.
    pub registration: String,
}

/// A template that passed the whole chain and is ready to be stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedTemplate {
    /// Bare template hash. The store key.
    pub template_hash: String,
    /// `<vendor>/<name>`, display data only.
    pub qualified_name: String,
    /// Canonical vendor name.
    pub vendor: String,
    /// Canonical template name.
    pub name: String,
    /// The publisher DID that signed the registration.
    pub publisher_did: String,
    /// Optional display label from the registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional description from the registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tip hash of the signed registration tree.
    pub tree_tip: String,
    /// Whether the pin check newly pinned this template.
    pub newly_pinned: bool,
    /// Unix seconds at import.
    pub imported_at: u64,
}

/// A candidate that passed verification, carrying the bytes to store.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// The record to file.
    pub template: ImportedTemplate,
    /// The definition body, verbatim.
    pub definition: String,
    /// The signed registration tree, verbatim.
    pub registration: String,
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

/// Steps 1 and 2: verify a vendor registration and check the publisher is allowed.
pub async fn verify_vendor(
    aquafier: &Aquafier,
    vendor_registration_json: &str,
    policy: &ImportPolicy,
) -> std::result::Result<TrustedVendor, ImportRejection> {
    let accepted = verify::accept(
        aquafier,
        vendor_registration_json,
        Some(RegistrationKind::Vendor),
    )
    .await
    .map_err(|e| match e {
        RegistryError::WrongRegistrationKind { submitted, .. } => ImportRejection::WrongKind {
            expected: "vendor",
            got: submitted.to_string(),
        },
        other => ImportRejection::NotVerified(other.to_string()),
    })?;

    let payload = match &accepted.payload {
        RegistrationPayload::Vendor(p) => p,
        other => {
            return Err(ImportRejection::WrongKind {
                expected: "vendor",
                got: other.kind().as_str().to_string(),
            })
        }
    };

    // Step 1: self-certifying. Checked here and not merely taken from the
    // registry's vendor record, because that record is derived data the
    // registry could get wrong or lie about.
    if payload.vendor_did != accepted.publisher_did {
        return Err(ImportRejection::NotSelfCertifying {
            signer: accepted.publisher_did.clone(),
            claimed: payload.vendor_did.clone(),
        });
    }

    // Step 2: the identity gate. Fail closed: an empty allow list admits nobody.
    if !policy.allows_publisher(&accepted.publisher_did) {
        return Err(ImportRejection::PublisherNotAllowed {
            did: accepted.publisher_did.clone(),
            allowed: policy.publisher_count(),
        });
    }

    Ok(TrustedVendor {
        vendor: accepted.vendor.clone(),
        vendor_did: accepted.publisher_did.clone(),
        registration: vendor_registration_json.to_string(),
    })
}

/// Steps 3 through 7: verify a template registration against its definition body.
///
/// `policy` is taken immutably; when the decision is to pin, that is reported
/// through [`ImportedTemplate::newly_pinned`] and the caller records it. Keeping
/// the mutation out of here means the check can be run speculatively (a dry
/// run) without a chance of writing to the pin file.
pub async fn verify_template(
    aquafier: &Aquafier,
    vendor: &TrustedVendor,
    template_registration_json: &str,
    definition_body: &str,
    policy: &ImportPolicy,
    mode: PinMode,
) -> std::result::Result<Accepted, ImportRejection> {
    // Step 3.
    let accepted = verify::accept(
        aquafier,
        template_registration_json,
        Some(RegistrationKind::Template),
    )
    .await
    .map_err(|e| match e {
        RegistryError::WrongRegistrationKind { submitted, .. } => ImportRejection::WrongKind {
            expected: "template",
            got: submitted.to_string(),
        },
        other => ImportRejection::NotVerified(other.to_string()),
    })?;

    let payload = match &accepted.payload {
        RegistrationPayload::Template(p) => p.clone(),
        other => {
            return Err(ImportRejection::WrongKind {
                expected: "template",
                got: other.kind().as_str().to_string(),
            })
        }
    };

    let qualified_name = accepted.qualified_name();

    // Step 4: the namespace owner, and only the namespace owner. Note this
    // compares against the DID recovered from the vendor registration's own
    // signature, not against anything the registry reported.
    if accepted.publisher_did != vendor.vendor_did {
        return Err(ImportRejection::WrongSigner {
            vendor: accepted.vendor.clone(),
            owner: vendor.vendor_did.clone(),
            signer: accepted.publisher_did.clone(),
        });
    }
    if accepted.vendor != vendor.vendor {
        return Err(ImportRejection::WrongSigner {
            vendor: accepted.vendor.clone(),
            owner: vendor.vendor_did.clone(),
            signer: accepted.publisher_did.clone(),
        });
    }

    // Step 5: size, then executable content. Size first so a huge body is
    // rejected before it is parsed.
    if definition_body.len() > MAX_DEFINITION_BYTES {
        return Err(ImportRejection::TooLarge {
            qualified_name,
            bytes: definition_body.len(),
            max: MAX_DEFINITION_BYTES,
        });
    }
    if crate::registry::carries_wasm(definition_body) {
        return Err(ImportRejection::CarriesWasm { qualified_name });
    }

    // Step 6: the body must be the body. This is what binds the bytes in hand
    // to the signed claim.
    let actual = crate::templates::template_hash_of_definition(definition_body).map_err(|e| {
        ImportRejection::MalformedDefinition {
            qualified_name: qualified_name.clone(),
            reason: e.to_string(),
        }
    })?;
    if !actual.eq_ignore_ascii_case(&payload.template_hash) {
        return Err(ImportRejection::HashMismatch {
            qualified_name,
            claimed: payload.template_hash.clone(),
            actual,
        });
    }

    // Step 7: the pin.
    let newly_pinned = match policy.check_pin(&qualified_name, &actual, mode) {
        PinDecision::Pinned => false,
        PinDecision::ApproveAndPin => true,
        PinDecision::NotPinned => return Err(ImportRejection::NotPinned { qualified_name }),
        PinDecision::Mismatch { pinned, offered } => {
            return Err(ImportRejection::PinMismatch {
                qualified_name,
                pinned,
                offered,
            })
        }
    };

    Ok(Accepted {
        template: ImportedTemplate {
            template_hash: actual,
            qualified_name,
            vendor: accepted.vendor.clone(),
            name: accepted.name.clone(),
            publisher_did: accepted.publisher_did.clone(),
            display_name: payload.display_name.clone(),
            description: payload.description.clone(),
            tree_tip: accepted.tree_tip.clone(),
            newly_pinned,
            imported_at: now_secs(),
        },
        definition: definition_body.to_string(),
        registration: template_registration_json.to_string(),
    })
}

// ---------------------------------------------------------------------------
// The local store
// ---------------------------------------------------------------------------

/// Templates a consumer has verified and chosen to keep.
///
/// ```text
/// <root>/
///   templates/<hash>.json       the definition body, verbatim
///   records/<hash>.json         who published it, under what name, when
///   registrations/<hash>.json   the signed registration, kept so the import
///                               can be re-proved later without the registry
/// ```
///
/// Keyed by hash throughout. A name never selects anything, because a name is
/// whatever a publisher typed.
pub struct ImportStore {
    root: PathBuf,
}

impl ImportStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["templates", "records", "registrations"] {
            std::fs::create_dir_all(root.join(sub)).map_err(|e| RegistryError::Storage {
                path: root.join(sub).display().to_string(),
                source: e,
            })?;
        }
        Ok(Self { root })
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn key(hash: &str) -> Result<String> {
        let ok = hash
            .strip_prefix("0x")
            .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if ok {
            Ok(format!("{}.json", hash.to_ascii_lowercase()))
        } else {
            Err(RegistryError::InvalidHash {
                field: "template_hash",
                reason: "must be `0x` followed by exactly 64 hex digits".to_string(),
            })
        }
    }

    /// File an accepted candidate.
    ///
    /// The definition body goes down first, then the registration, then the
    /// record. The record is the commit point: a record on disk always has its
    /// body and its proof beside it.
    pub fn insert(&self, accepted: &Accepted) -> Result<()> {
        let key = Self::key(&accepted.template.template_hash)?;
        write_atomically(
            &self.root.join("templates").join(&key),
            accepted.definition.as_bytes(),
        )?;
        write_atomically(
            &self.root.join("registrations").join(&key),
            accepted.registration.as_bytes(),
        )?;
        let record = serde_json::to_string_pretty(&accepted.template)
            .map_err(|e| RegistryError::Core(e.to_string()))?;
        write_atomically(
            &self.root.join("records").join(&key),
            format!("{record}\n").as_bytes(),
        )
    }

    /// Whether this hash has already been imported.
    pub fn contains(&self, template_hash: &str) -> bool {
        Self::key(template_hash)
            .map(|k| self.root.join("records").join(k).exists())
            .unwrap_or(false)
    }

    /// The definition body for a hash, re-checked on the way out.
    ///
    /// The stored body is rehashed and compared against the key it was filed
    /// under. Anything that changed the file on disk after import (corruption,
    /// or an attacker with local write access) is caught here rather than
    /// silently handed to an application as a trusted template.
    pub fn definition(&self, template_hash: &str) -> Result<String> {
        let key = Self::key(template_hash)?;
        let path = self.root.join("templates").join(&key);
        let body = std::fs::read_to_string(&path).map_err(|e| RegistryError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;

        let actual = crate::templates::template_hash_of_definition(&body).map_err(|e| {
            RegistryError::CorruptStore {
                path: path.display().to_string(),
                reason: format!("stored definition no longer parses: {e}"),
            }
        })?;
        if !actual.eq_ignore_ascii_case(template_hash) {
            return Err(RegistryError::CorruptStore {
                path: path.display().to_string(),
                reason: format!("stored definition hashes to {actual}, not to its own key"),
            });
        }
        Ok(body)
    }

    /// The import record for a hash.
    pub fn record(&self, template_hash: &str) -> Result<ImportedTemplate> {
        let key = Self::key(template_hash)?;
        let path = self.root.join("records").join(&key);
        let text = std::fs::read_to_string(&path).map_err(|e| RegistryError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;
        serde_json::from_str(&text).map_err(|e| RegistryError::CorruptStore {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    /// The signed registration that justified this import, verbatim.
    pub fn registration(&self, template_hash: &str) -> Result<String> {
        let key = Self::key(template_hash)?;
        let path = self.root.join("registrations").join(&key);
        std::fs::read_to_string(&path).map_err(|e| RegistryError::Storage {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// Every imported hash, sorted.
    pub fn hashes(&self) -> Result<Vec<String>> {
        let dir = self.root.join("records");
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(RegistryError::Storage {
                    path: dir.display().to_string(),
                    source: e,
                })
            }
        };
        let mut out = Vec::new();
        for item in rd {
            let item = item.map_err(|e| RegistryError::Storage {
                path: dir.display().to_string(),
                source: e,
            })?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Every import record, sorted by hash.
    pub fn records(&self) -> Result<Vec<ImportedTemplate>> {
        self.hashes()?.iter().map(|h| self.record(h)).collect()
    }

    /// Name to hash, for display and for looking up what a name resolved to at
    /// import time.
    ///
    /// Deliberately not a resolver. Two publishers may use the same qualified
    /// name only if they own the same namespace, which the chain prevents, but
    /// the general point stands: pick templates by hash, and use this to show a
    /// human what that hash was called.
    pub fn names(&self) -> Result<BTreeMap<String, String>> {
        Ok(self
            .records()?
            .into_iter()
            .map(|r| (r.qualified_name, r.template_hash))
            .collect())
    }

    /// The imported template as a single-revision Aqua tree, ready to pass to
    /// `verify_aqua_tree_with_linked_trees` as a linked tree.
    ///
    /// This is the portable-template pattern, and the reason importing is worth
    /// anything: an application creates objects with `create_object(hash, ...)`
    /// and ships this tree alongside so any verifier can resolve the type
    /// without the template being built into their SDK.
    ///
    /// Goes through [`ImportStore::definition`], so the verify-on-read guard
    /// applies here too.
    pub fn template_tree(&self, template_hash: &str) -> Result<Tree> {
        let body = self.definition(template_hash)?;
        let template: Template =
            serde_json::from_str(&body).map_err(|e| RegistryError::CorruptStore {
                path: template_hash.to_string(),
                reason: e.to_string(),
            })?;
        let link = template
            .calculate_link(HashType::Sha3_256)
            .map_err(|e| RegistryError::Core(e.to_string()))?;

        let mut revisions = std::collections::BTreeMap::new();
        revisions.insert(link.clone(), AnyRevision::Template(template));
        let mut file_index = std::collections::BTreeMap::new();
        let name = self
            .record(template_hash)
            .map(|r| r.qualified_name)
            .unwrap_or_else(|_| template_hash.to_string());
        file_index.insert(link, name);

        Ok(Tree {
            revisions,
            file_index,
        })
    }

    /// Wrapped for `verify_aqua_tree_with_linked_trees`.
    pub fn linked_tree(&self, template_hash: &str) -> Result<AquaTreeWrapper> {
        Ok(AquaTreeWrapper::new(
            self.template_tree(template_hash)?,
            None,
            None,
        ))
    }
}

fn write_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let err = |p: &Path, e: std::io::Error| RegistryError::Storage {
        path: p.display().to_string(),
        source: e,
    };
    let mut f = std::fs::File::create(&tmp).map_err(|e| err(&tmp, e))?;
    f.write_all(contents).map_err(|e| err(&tmp, e))?;
    f.sync_all().map_err(|e| err(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| err(path, e))?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
