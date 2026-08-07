//! Wire and index data model.
//!
//! Two families of types live here:
//!
//! 1. **Registration payloads** ([`VendorRegistration`], [`TemplateRegistration`],
//!    [`AliasRegistration`]). These mirror, field for field, the JSON Schemas in
//!    the vendored template definitions under `src/templates/`. If you change
//!    one of these structs without changing the corresponding JSON, submissions
//!    stop round-tripping.
//!
//! 2. **Index records** ([`VendorRecord`], [`TemplateRecord`], [`AliasRecord`])
//!    and the append-only [`FeedEntry`]. These are the registry's derived view.
//!    They are rebuildable at any time by replaying the feed, so the feed is the
//!    only thing that has to be durable.

use serde::{Deserialize, Serialize};

/// Which of the three registration templates a submission uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationKind {
    /// Claims a vendor namespace. Self-certifying.
    Vendor,
    /// Registers a template hash under a vendor namespace.
    Template,
    /// Registers an alternate name pointing at some template hash.
    Alias,
}

impl RegistrationKind {
    /// Human-readable name, also used in error messages and the feed.
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationKind::Vendor => "vendor",
            RegistrationKind::Template => "template",
            RegistrationKind::Alias => "alias",
        }
    }
}

impl std::fmt::Display for RegistrationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Registration payloads (mirror src/templates/*.json)
// ---------------------------------------------------------------------------

/// Payload of a `vendor-registration` object.
///
/// Mirrors `src/templates/vendor_registration.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorRegistration {
    /// Short identifier used as the namespace prefix in `<vendor>/<name>`.
    pub vendor_name: String,
    /// Optional human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// DID of the vendor's signing key. MUST equal the tree's signer DID.
    pub vendor_did: String,
}

/// Declares that a template's payload commits to a file by hash.
///
/// Mirrors the `file_dependency` object in `template_registration.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDependency {
    /// Name of the payload field holding the file hash.
    pub hash_field: String,
}

/// Payload of a `template-registration` object.
///
/// Mirrors `src/templates/template_registration.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateRegistration {
    /// Vendor namespace to register into. The signer must own it.
    pub vendor: String,
    /// Template name within the namespace.
    pub name: String,
    /// Hash of the template being registered (0x-prefixed hex).
    pub template_hash: String,
    /// Optional previous version this replaces (0x-prefixed hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Optional human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional prose description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this template is access-affecting (daemon policy trigger).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_trigger: Option<bool>,
    /// Optional file-dependency declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_dependency: Option<FileDependency>,
}

/// Payload of an `alias-registration` object.
///
/// Mirrors `src/templates/alias_registration.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasRegistration {
    /// Vendor namespace the alias lives in. The signer must own it.
    /// Cross-vendor aliases are allowed: `target_hash` may belong to anyone.
    pub vendor: String,
    /// The alias name within the namespace.
    pub alias_name: String,
    /// Template hash the alias points at (0x-prefixed hex).
    pub target_hash: String,
}

/// Tagged union of the three payloads, as stored in the feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistrationPayload {
    /// A vendor registration.
    Vendor(VendorRegistration),
    /// A template registration.
    Template(TemplateRegistration),
    /// An alias registration.
    Alias(AliasRegistration),
}

impl RegistrationPayload {
    /// Which kind this payload is.
    pub fn kind(&self) -> RegistrationKind {
        match self {
            RegistrationPayload::Vendor(_) => RegistrationKind::Vendor,
            RegistrationPayload::Template(_) => RegistrationKind::Template,
            RegistrationPayload::Alias(_) => RegistrationKind::Alias,
        }
    }
}

// ---------------------------------------------------------------------------
// Feed
// ---------------------------------------------------------------------------

/// One accepted registration, as persisted in the append-only feed.
///
/// `seq` is registry-global and monotonically increasing. Consumers subscribe by
/// polling `GET /publishers/{did}/feed?since=<seq>` and remembering the highest
/// `seq` they have processed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// Registry-global monotonic sequence number, starting at 1.
    pub seq: u64,
    /// Which registration template was used.
    pub kind: RegistrationKind,
    /// DID recovered from the tree's signature revision. This is the publisher.
    pub publisher_did: String,
    /// Tip revision hash of the stored signed tree (0x-prefixed hex).
    /// Doubles as the key under which the full signed tree bytes are stored.
    pub tree_tip: String,
    /// Unix seconds at which the registry accepted this registration.
    pub received_at: u64,
    /// Canonical `<vendor>/<name>` this registration writes to, when it has one.
    /// Vendor registrations carry the bare canonical vendor name.
    pub qualified_name: String,
    /// The decoded registration payload, exactly as it appeared in the tree.
    pub payload: RegistrationPayload,
}

// ---------------------------------------------------------------------------
// Index records
// ---------------------------------------------------------------------------

/// A claimed vendor namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorRecord {
    /// Canonical (NFC-normalized, Latin case-folded) vendor name.
    pub vendor: String,
    /// The DID that owns the namespace. Everything under it must be signed by
    /// this DID.
    pub vendor_did: String,
    /// Optional display label from the most recent registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Feed sequence number of the registration that produced this record.
    pub seq: u64,
    /// Tip hash of the signed tree backing this record.
    pub tree_tip: String,
}

/// A registered template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRecord {
    /// Canonical vendor name.
    pub vendor: String,
    /// Canonical template name.
    pub name: String,
    /// `<vendor>/<name>`.
    pub qualified_name: String,
    /// Hash of the registered template (0x-prefixed hex, as submitted).
    pub template_hash: String,
    /// The version this replaced, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// The version that replaced this one, if any. Derived, not submitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// Optional display label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Access-affecting flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon_trigger: Option<bool>,
    /// File-dependency declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_dependency: Option<FileDependency>,
    /// Publisher DID (equal to the owning vendor's DID by construction).
    pub publisher_did: String,
    /// Feed sequence number.
    pub seq: u64,
    /// Tip hash of the signed registration tree.
    pub tree_tip: String,
}

/// A registered alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasRecord {
    /// Canonical vendor name owning the alias.
    pub vendor: String,
    /// Canonical alias name.
    pub alias_name: String,
    /// `<vendor>/<alias_name>`.
    pub qualified_name: String,
    /// Template hash the alias points at. May belong to another vendor.
    pub target_hash: String,
    /// Publisher DID.
    pub publisher_did: String,
    /// Feed sequence number.
    pub seq: u64,
    /// Tip hash of the signed registration tree.
    pub tree_tip: String,
}

/// Result of resolving `<vendor>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    /// The qualified name that was resolved.
    pub qualified_name: String,
    /// The template hash it resolves to.
    pub template_hash: String,
    /// How the name resolved.
    pub via: ResolutionVia,
    /// DID of the publisher who registered the target, when the registry knows
    /// it. Cross-vendor aliases can point at a hash this registry never saw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_did: Option<String>,
    /// Full version lineage of the qualified name, oldest first. Empty for
    /// alias resolutions whose target is unknown to this registry.
    pub lineage: Vec<String>,
}

/// Which index answered a resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionVia {
    /// A template registration in this namespace.
    Template,
    /// An alias registration in this namespace.
    Alias,
}

/// What the registry returns after accepting a submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Assigned feed sequence number.
    pub seq: u64,
    /// Kind of registration accepted.
    pub kind: RegistrationKind,
    /// DID that signed it.
    pub publisher_did: String,
    /// Tip hash of the stored signed tree.
    pub tree_tip: String,
    /// Canonical name this registration claims.
    pub qualified_name: String,
}

/// A page of the subscription feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedPage {
    /// The publisher DID this feed belongs to.
    pub publisher_did: String,
    /// The `since` cursor the caller supplied.
    pub since: u64,
    /// Cursor to pass as `since` on the next poll. Equal to the highest `seq`
    /// in `entries`, or to `since` when `entries` is empty.
    pub next: u64,
    /// Whether more entries exist beyond this page.
    pub has_more: bool,
    /// Entries with `seq > since`, oldest first.
    pub entries: Vec<FeedEntry>,
}

/// What the registry returns after accepting a definition body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionReceipt {
    /// The hash recomputed from the body. Its storage key.
    pub template_hash: String,
    /// Size of the accepted body in bytes.
    pub bytes: usize,
    /// False when an identical body was already on hand.
    pub stored: bool,
}

/// What the registry returns after accepting a feed head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadReceipt {
    /// The publisher who signed it.
    pub publisher_did: String,
    /// Entries covered.
    pub head_seq: u64,
    /// The signed root.
    pub merkle_root: String,
    /// Tip hash of the head tree.
    pub tree_tip: String,
    /// False when an identical head was already stored at this height.
    pub stored: bool,
}

/// Registry counters, for operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    /// Highest assigned sequence number.
    pub head_seq: u64,
    /// Number of claimed vendor namespaces.
    pub vendors: usize,
    /// Number of registered templates (all versions).
    pub templates: usize,
    /// Number of registered aliases.
    pub aliases: usize,
    /// Number of distinct publisher DIDs.
    pub publishers: usize,
}
