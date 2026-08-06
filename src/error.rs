//! Error type for the registry.
//!
//! Every rejection reason is a distinct variant so that the HTTP layer can map
//! it to a status code without string matching, and so that library callers can
//! react programmatically (a publisher tool wants to tell "vendor name already
//! taken" apart from "your signature did not verify").

use crate::name::NameError;

/// Everything that can go wrong accepting or serving a registration.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    // ---- submission parsing -------------------------------------------------
    /// The submitted body was not a JSON-encoded Aqua tree.
    #[error("submitted body is not a valid Aqua tree JSON: {0}")]
    MalformedTree(String),

    /// The tree has no revisions, or no tip could be determined.
    #[error("submitted tree is empty or has no resolvable tip")]
    EmptyTree,

    // ---- cryptographic acceptance ------------------------------------------
    /// aqua-rs-sdk-core did not return a verified outcome for the tree.
    #[error("tree verification failed: {0}")]
    TreeNotVerified(String),

    /// The tree verified but contains no typed object of a registration type.
    #[error("tree contains no registration object (expected exactly one object typed as vendor-registration, template-registration, or alias-registration)")]
    NotARegistration,

    /// The tree contains more than one typed object revision.
    #[error("tree contains {0} typed object revisions, expected exactly 1")]
    AmbiguousRegistration(usize),

    /// A registration of kind X was submitted to the endpoint for kind Y.
    #[error("submitted a {submitted} registration to the {expected} endpoint")]
    WrongRegistrationKind {
        /// What the tree actually contains.
        submitted: &'static str,
        /// What the endpoint accepts.
        expected: &'static str,
    },

    /// The registration object carries no signature revision.
    #[error("registration object is unsigned: a registration must be a signed Aqua tree")]
    Unsigned,

    /// Signature revisions disagree about who signed.
    #[error("registration carries signatures from multiple DIDs ({0} distinct signers); a registration must have exactly one signer")]
    MultipleSigners(usize),

    /// The registration payload did not match its template's Rust shape.
    #[error("registration payload is malformed: {0}")]
    MalformedPayload(String),

    // ---- name rules ---------------------------------------------------------
    /// A vendor, template, or alias name failed the section 3.3 rules.
    #[error("invalid name: {0}")]
    InvalidName(#[from] NameError),

    /// A hash field was not a 0x-prefixed hex string.
    #[error("invalid hash {field:?}: {reason}")]
    InvalidHash {
        /// Which payload field was bad.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    // ---- publisher-DID trust model (spec-type-registry.md section 3.7) ------
    /// A vendor registration was signed by a key other than the `vendor_did` it
    /// claims. Vendor registrations are self-certifying, so this is fatal.
    #[error("vendor registration is not self-certifying: signed by {signer} but claims vendor_did {claimed}")]
    NotSelfCertifying {
        /// DID recovered from the signature revision.
        signer: String,
        /// DID asserted in the payload.
        claimed: String,
    },

    /// A template or alias registration was signed by a key that does not own
    /// the vendor namespace it writes into.
    #[error("signer {signer} does not own vendor namespace {vendor:?} (owned by {owner})")]
    NotNamespaceOwner {
        /// Vendor namespace being written to.
        vendor: String,
        /// DID that owns it.
        owner: String,
        /// DID that tried to write.
        signer: String,
    },

    /// The vendor namespace referenced by a template or alias registration has
    /// no prior vendor registration.
    #[error("vendor {0:?} is not registered; register the vendor namespace first")]
    VendorNotRegistered(String),

    /// A different DID already owns this vendor name (first come, first served).
    #[error("vendor name {vendor:?} is already registered to {owner}")]
    VendorNameTaken {
        /// The contested vendor name.
        vendor: String,
        /// The DID that got there first.
        owner: String,
    },

    // ---- index consistency --------------------------------------------------
    /// The same template hash was registered twice.
    #[error("template hash {0} is already registered")]
    DuplicateTemplate(String),

    /// The same qualified alias name was registered twice.
    #[error("alias {0:?} is already registered")]
    DuplicateAlias(String),

    /// A qualified name is claimed by an alias and a template at once.
    #[error("name {0:?} is already in use in this namespace")]
    NameCollision(String),

    /// `supersedes` pointed at a hash that is not registered under the same
    /// qualified name.
    #[error("supersedes target {target} is not a registered version of {qualified:?}")]
    UnknownSupersedes {
        /// The qualified name the registration writes to.
        qualified: String,
        /// The hash the registration claims to supersede.
        target: String,
    },

    /// `supersedes` pointed at a hash that some other registration already
    /// superseded. Version lineage is kept linear.
    #[error("supersedes target {0} has already been superseded; version lineage must stay linear")]
    AlreadySuperseded(String),

    // ---- lookups ------------------------------------------------------------
    /// Nothing found for the requested key.
    #[error("not found: {0}")]
    NotFound(String),

    // ---- infrastructure -----------------------------------------------------
    /// The on-disk store could not be read or written.
    #[error("store I/O error at {path}: {source}")]
    Storage {
        /// Path involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },

    /// A persisted entry could not be decoded (corrupt data directory).
    #[error("corrupt store entry {path}: {reason}")]
    CorruptStore {
        /// Path involved.
        path: String,
        /// Why decoding failed.
        reason: String,
    },

    /// Something went wrong inside aqua-rs-sdk-core.
    #[error("aqua-rs-sdk-core error: {0}")]
    Core(String),
}

impl RegistryError {
    /// HTTP status code for this error.
    ///
    /// 400 for a malformed submission, 403 for a submission that is well formed
    /// but not authorised under the publisher-DID trust model, 404 for lookups,
    /// 409 for conflicts against already-accepted state, 422 for a submission
    /// that parses but fails cryptographic acceptance, 500 for our own faults.
    pub fn status(&self) -> u16 {
        match self {
            RegistryError::MalformedTree(_)
            | RegistryError::EmptyTree
            | RegistryError::NotARegistration
            | RegistryError::AmbiguousRegistration(_)
            | RegistryError::WrongRegistrationKind { .. }
            | RegistryError::MalformedPayload(_)
            | RegistryError::InvalidName(_)
            | RegistryError::InvalidHash { .. } => 400,

            RegistryError::TreeNotVerified(_)
            | RegistryError::Unsigned
            | RegistryError::MultipleSigners(_) => 422,

            RegistryError::NotSelfCertifying { .. }
            | RegistryError::NotNamespaceOwner { .. }
            | RegistryError::VendorNameTaken { .. } => 403,

            RegistryError::VendorNotRegistered(_) | RegistryError::NotFound(_) => 404,

            RegistryError::DuplicateTemplate(_)
            | RegistryError::DuplicateAlias(_)
            | RegistryError::NameCollision(_)
            | RegistryError::UnknownSupersedes { .. }
            | RegistryError::AlreadySuperseded(_) => 409,

            RegistryError::Storage { .. }
            | RegistryError::CorruptStore { .. }
            | RegistryError::Core(_) => 500,
        }
    }

    /// Stable machine-readable code, so clients do not parse the message.
    pub fn code(&self) -> &'static str {
        match self {
            RegistryError::MalformedTree(_) => "MALFORMED_TREE",
            RegistryError::EmptyTree => "EMPTY_TREE",
            RegistryError::TreeNotVerified(_) => "TREE_NOT_VERIFIED",
            RegistryError::NotARegistration => "NOT_A_REGISTRATION",
            RegistryError::AmbiguousRegistration(_) => "AMBIGUOUS_REGISTRATION",
            RegistryError::WrongRegistrationKind { .. } => "WRONG_REGISTRATION_KIND",
            RegistryError::Unsigned => "UNSIGNED",
            RegistryError::MultipleSigners(_) => "MULTIPLE_SIGNERS",
            RegistryError::MalformedPayload(_) => "MALFORMED_PAYLOAD",
            RegistryError::InvalidName(_) => "INVALID_NAME",
            RegistryError::InvalidHash { .. } => "INVALID_HASH",
            RegistryError::NotSelfCertifying { .. } => "NOT_SELF_CERTIFYING",
            RegistryError::NotNamespaceOwner { .. } => "NOT_NAMESPACE_OWNER",
            RegistryError::VendorNotRegistered(_) => "VENDOR_NOT_REGISTERED",
            RegistryError::VendorNameTaken { .. } => "VENDOR_NAME_TAKEN",
            RegistryError::DuplicateTemplate(_) => "DUPLICATE_TEMPLATE",
            RegistryError::DuplicateAlias(_) => "DUPLICATE_ALIAS",
            RegistryError::NameCollision(_) => "NAME_COLLISION",
            RegistryError::UnknownSupersedes { .. } => "UNKNOWN_SUPERSEDES",
            RegistryError::AlreadySuperseded(_) => "ALREADY_SUPERSEDED",
            RegistryError::NotFound(_) => "NOT_FOUND",
            RegistryError::Storage { .. } => "STORAGE_ERROR",
            RegistryError::CorruptStore { .. } => "CORRUPT_STORE",
            RegistryError::Core(_) => "CORE_ERROR",
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, RegistryError>;
