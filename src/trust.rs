//! Consumer-side trust policy: the committed config that answers "whose
//! templates am I willing to run".
//!
//! spec-type-registry.md section 3.7 (see [`crate::verify`] and
//! [`crate::registry`]) only proves that a registration is internally
//! consistent: a `template-registration` was signed by the same DID that
//! owns the `vendor` namespace it writes into, and a `vendor-registration`
//! is self-certifying. None of that says whether the DID that owns a
//! namespace is a DID anyone should actually trust. Namespaces are first
//! come, first served, so "the signer owns `acme`" and "the signer is
//! trustworthy" are two completely different claims, and the registry only
//! ever proves the first one.
//!
//! [`ImportPolicy`] is the gap closer. It is a file a consumer commits to
//! their own repository, next to whatever process consumes registry
//! entries, and it is the only thing in this crate that decides what gets
//! imported. Every default in this module is deny:
//!
//! - an empty policy allows no publisher and pins nothing ([`ImportPolicy::empty`]),
//! - a policy file that cannot be loaded is an error, never treated as
//!   permissive ([`ImportPolicy::load`]),
//! - omitting `allowed_publishers` or `pins` from the file yields an empty
//!   set or map, never a wildcard,
//! - a name with no pin is refused unless the mode explicitly says
//!   otherwise ([`PinMode`], [`ImportPolicy::check_pin`]), and
//! - a name with a pin for a *different* hash is always refused, in every
//!   mode. [`PinMode::ApproveNew`] can add a pin that does not exist yet;
//!   it can never replace one that does.
//!
//! There is deliberately no trust-on-first-use. Seeing a template once,
//! anywhere, is never sufficient reason to trust it: TOFU only protects
//! against a publisher who behaves consistently after the first contact,
//! and says nothing about whether the first contact itself was with someone
//! worth trusting. [`PinMode::ApproveNew`] looks similar (it accepts an
//! unpinned name) but is not TOFU in disguise, because it still requires
//! the signer to already be in `allowed_publishers`. That set is populated
//! by the consumer out of band, never by the act of importing something.
//!
//! # Why JSON, not TOML
//!
//! [`PinMode::ApproveNew`] works by machine-appending accepted pins back to
//! this file (see [`ImportPolicy::approve`] and [`ImportPolicy::save`]).
//! That rewrite serializes the whole in-memory structure and writes it back
//! out; any hand-written comments in the file would not survive it. TOML
//! and JSON5 support comments that this module would then silently destroy
//! on the next approval, which is worse than never having offered them:
//! it would look like the file just lost content. Plain JSON never
//! promises comment support in the first place, so writing it back out
//! loses nothing an operator was told they could keep.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};
use crate::name::{qualified, validate_qualified_name, NameError};

/// Hard cap on a template definition body, in bytes.
pub const MAX_DEFINITION_BYTES: usize = 256 * 1024;

/// The only `version` value this build accepts in a policy file. Bumping
/// this is a breaking change to the file format and must ship alongside a
/// migration story for existing files, not just a new number here.
const CURRENT_VERSION: u32 = 1;

/// Cap on any single provenance string, so a policy file cannot quietly
/// become a document store.
const MAX_PROVENANCE_LEN: usize = 512;

/// Tolerance for a feed head timestamped slightly in the future.
///
/// Clocks disagree. Without a tolerance a publisher whose clock runs a minute
/// fast would produce heads that every subscriber refuses; with an unbounded
/// one, a head dated far in the future would never be stale and the freshness
/// policy would be trivially defeated. Five minutes is the usual NTP-ish
/// allowance.
pub const FUTURE_HEAD_TOLERANCE_SECS: u64 = 300;

/// An allowed publisher, optionally annotated with where the DID came from.
///
/// A DID in a trust file is a bare string with no story attached, and six
/// months later nobody can tell whether it was verified in person, copied off
/// a web page, or pasted from a chat message. These annotations are that story.
/// They are advisory: nothing in the import chain reads them, and adding a
/// convincing `verified_by` to an entry does not make it more trusted. Their
/// whole job is to make a human review of the file possible.
///
/// # Wire form
///
/// Serializes as a bare JSON string when there is no provenance, and as an
/// object when there is. That keeps every trust file written before this
/// existed valid and unchanged, and keeps `save` from rewriting a plain list
/// into a verbose one for no reason.
///
/// ```json
/// "did:key:z6MkBare"
/// { "did": "did:key:z6MkAnnotated", "source": "handed over in person" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublisherEntry {
    /// The publisher DID. The only field the import chain reads.
    pub did: String,
    /// Where this DID came from (a URL, "in person at X", "signed email", ...).
    pub source: Option<String>,
    /// Who checked it, for an operator reading the file later.
    pub verified_by: Option<String>,
    /// When it was checked. Free-form; an ISO date is the obvious choice.
    pub verified_on: Option<String>,
    /// Anything else worth recording.
    pub note: Option<String>,
}

impl PublisherEntry {
    /// An entry with no provenance recorded.
    pub fn bare(did: impl Into<String>) -> Self {
        PublisherEntry {
            did: did.into(),
            source: None,
            verified_by: None,
            verified_on: None,
            note: None,
        }
    }

    /// True when nothing but the DID is recorded.
    pub fn is_bare(&self) -> bool {
        self.source.is_none()
            && self.verified_by.is_none()
            && self.verified_on.is_none()
            && self.note.is_none()
    }

    /// A one-line human summary of the provenance, or `None` when bare.
    pub fn provenance_summary(&self) -> Option<String> {
        if self.is_bare() {
            return None;
        }
        let mut parts = Vec::new();
        if let Some(s) = &self.source {
            parts.push(format!("source: {s}"));
        }
        if let Some(v) = &self.verified_by {
            parts.push(format!("verified by: {v}"));
        }
        if let Some(d) = &self.verified_on {
            parts.push(format!("on: {d}"));
        }
        if let Some(n) = &self.note {
            parts.push(format!("note: {n}"));
        }
        Some(parts.join(", "))
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if !is_valid_publisher_did(&self.did) {
            return Err(format!(
                "allowed_publishers entry {:?} is not a DID: must be non-empty and start with \"did:\"",
                self.did
            ));
        }
        for (label, value) in [
            ("source", &self.source),
            ("verified_by", &self.verified_by),
            ("verified_on", &self.verified_on),
            ("note", &self.note),
        ] {
            if let Some(v) = value {
                if v.len() > MAX_PROVENANCE_LEN {
                    return Err(format!(
                        "allowed_publishers entry {:?} has a {label} of {} bytes, over the {MAX_PROVENANCE_LEN} byte cap",
                        self.did,
                        v.len()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The object form, used only as a serde staging type.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnotatedPublisher {
    did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PublisherWire {
    Bare(String),
    Annotated(AnnotatedPublisher),
}

impl Serialize for PublisherEntry {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if self.is_bare() {
            return s.serialize_str(&self.did);
        }
        AnnotatedPublisher {
            did: self.did.clone(),
            source: self.source.clone(),
            verified_by: self.verified_by.clone(),
            verified_on: self.verified_on.clone(),
            note: self.note.clone(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublisherEntry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(match PublisherWire::deserialize(d)? {
            PublisherWire::Bare(did) => PublisherEntry::bare(did),
            PublisherWire::Annotated(a) => PublisherEntry {
                did: a.did,
                source: a.source,
                verified_by: a.verified_by,
                verified_on: a.verified_on,
                note: a.note,
            },
        })
    }
}

/// Field name reported in [`RegistryError::InvalidHash`] when the
/// `template_hash` argument to [`ImportPolicy::approve`] is malformed.
///
/// A malformed hash coming from a file loaded by [`ImportPolicy::load`] is
/// reported as [`RegistryError::CorruptStore`] instead, since there the
/// problem is with a persisted file rather than a live call's argument;
/// this constant is only used on the `approve` path.
const PIN_HASH_FIELD: &str = "template_hash";

/// Which templates a run is willing to import.
///
/// This only governs [`ImportPolicy::check_pin`]'s behavior for a name that
/// has no existing pin. A name with a pin for a *different* hash is a
/// [`PinDecision::Mismatch`] in both modes; no mode ever overrides that,
/// because that is precisely the same-name-different-hash substitution
/// attack this whole module exists to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinMode {
    /// Only templates whose qualified name AND hash match an existing pin.
    ///
    /// The strict mode: nothing new is ever accepted, so running with this
    /// mode can never itself widen what gets imported. Suitable for
    /// production and CI, where every accepted template should already have
    /// been reviewed and pinned deliberately.
    #[default]
    PinnedOnly,
    /// Additionally accept not-yet-pinned templates from allowed publishers,
    /// appending each accepted one to the pin file.
    ///
    /// This does not bypass the allow-list: [`ImportPolicy::check_pin`]
    /// itself never consults `allowed_publishers` (it only knows names and
    /// hashes), so a caller wiring this mode up is expected to check
    /// [`ImportPolicy::allows_publisher`] for the offering DID before
    /// treating a [`PinDecision::ApproveAndPin`] as accepted, and to call
    /// [`ImportPolicy::approve`] only after that check passes.
    ApproveNew,
}

/// Outcome of a pin check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinDecision {
    /// Name and hash match an existing pin.
    Pinned,
    /// Not pinned, and the mode permits importing plus recording it.
    ApproveAndPin,
    /// Not pinned and the mode forbids it.
    NotPinned,
    /// A pin exists for the name but names a DIFFERENT hash.
    Mismatch {
        /// The hash already pinned for this name, in canonical (`0x` plus
        /// lowercase hex) form.
        pinned: String,
        /// The hash that was offered, exactly as passed in.
        offered: String,
    },
}

/// A consumer's committed answer to "whose templates am I willing to run".
///
/// Every entry in `allowed_publishers` and every key in `pins` is validated
/// and canonicalized before this type will hold it, whether the value came
/// from [`ImportPolicy::load`] or from [`ImportPolicy::approve`] /
/// [`ImportPolicy::allow_publisher`]. There is no way to reach this type
/// holding an unvalidated entry, which is what lets [`ImportPolicy::pin`]
/// and [`ImportPolicy::check_pin`] compare a fresh candidate against stored
/// entries with a plain canonical-form comparison instead of re-normalizing
/// on every lookup.
///
/// `BTreeSet`/`BTreeMap` (rather than a hash-based collection) so that
/// [`ImportPolicy::save`] always emits the same byte-for-byte JSON for the
/// same logical content: a policy file lives in a consumer's own repository
/// and a stable diff on every save matters there.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportPolicy {
    /// File format version. [`ImportPolicy::load`] rejects any value other
    /// than `CURRENT_VERSION`.
    version: u32,
    /// DIDs this consumer is willing to import anything from, subject to
    /// pinning. Absent from a file, this is the empty set: no publisher is
    /// allowed. Never a wildcard.
    #[serde(default)]
    allowed_publishers: Vec<PublisherEntry>,
    /// Refuse a feed head older than this many seconds, measured against the
    /// head's signed `covered_at`. Absent means no freshness requirement,
    /// which is what every policy file written before this existed means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_head_age_secs: Option<u64>,
    /// Canonical qualified name to canonical (`0x` plus lowercase hex)
    /// pinned hash. Absent from a file, this is empty: nothing is pinned.
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

impl ImportPolicy {
    /// An empty policy. Imports nothing: no publisher is allowed.
    pub fn empty() -> Self {
        ImportPolicy {
            version: CURRENT_VERSION,
            allowed_publishers: Vec::new(),
            max_head_age_secs: None,
            pins: BTreeMap::new(),
        }
    }

    /// Load from a JSON file. A missing file is an error, never an empty
    /// allow-all.
    ///
    /// Every entry is validated, and the whole file is rejected if any
    /// entry is bad rather than the bad entry being silently skipped (a
    /// skipped entry in a trust file is a silently narrowed, then silently
    /// widened again on the next edit, security boundary; that is worse
    /// than refusing to start). Specifically, this rejects the file if:
    ///
    /// - `version` is anything other than `CURRENT_VERSION`,
    /// - any `allowed_publishers` entry is empty or does not start with
    ///   `"did:"`,
    /// - any `pins` key is not a valid `<vendor>/<name>` qualified name per
    ///   [`crate::name::validate_qualified_name`],
    /// - any `pins` value is not `0x` followed by exactly 64 hex digits, or
    /// - two `pins` keys canonicalize to the same qualified name but carry
    ///   different hashes (a conflicting pin baked into the file itself).
    ///
    /// On success, every `pins` key is stored in its canonical qualified-name
    /// form and every `pins` value is stored lowercase, regardless of how
    /// they were spelled in the file. Two raw keys that canonicalize to the
    /// same name with the *same* hash (for example differing only in case)
    /// are merged without error.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| RegistryError::Storage {
            path: path.display().to_string(),
            source: e,
        })?;

        let parsed: ImportPolicy =
            serde_json::from_slice(&bytes).map_err(|e| RegistryError::CorruptStore {
                path: path.display().to_string(),
                reason: format!("failed to parse import policy: {e}"),
            })?;

        parsed.validated(&path.display().to_string())
    }

    /// Validates and canonicalizes a freshly deserialized policy, or rejects
    /// it whole. `context` identifies the file for error messages only.
    fn validated(mut self, context: &str) -> Result<Self> {
        if self.version != CURRENT_VERSION {
            return Err(RegistryError::CorruptStore {
                path: context.to_string(),
                reason: format!(
                    "unsupported import policy version {}, this build only understands version {CURRENT_VERSION}",
                    self.version
                ),
            });
        }

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for entry in &self.allowed_publishers {
            entry
                .validate()
                .map_err(|reason| RegistryError::CorruptStore {
                    path: context.to_string(),
                    reason,
                })?;
            // A DID listed twice with different provenance is ambiguous: there
            // is no way to tell which story is the real one, and picking either
            // would be inventing an answer. Refuse the file instead.
            if !seen.insert(entry.did.as_str()) {
                return Err(RegistryError::CorruptStore {
                    path: context.to_string(),
                    reason: format!("allowed_publishers lists {:?} more than once", entry.did),
                });
            }
        }
        // Deterministic order so `save` emits a stable diff regardless of how
        // the file was written by hand.
        self.allowed_publishers.sort_by(|a, b| a.did.cmp(&b.did));

        let mut canonical_pins: BTreeMap<String, String> = BTreeMap::new();
        for (raw_key, raw_hash) in &self.pins {
            let canonical_key =
                canonical_pin_key(raw_key).map_err(|e| RegistryError::CorruptStore {
                    path: context.to_string(),
                    reason: format!("pin key {raw_key:?} is not a valid qualified name: {e}"),
                })?;
            let canonical_hash =
                normalize_hex_hash(raw_hash).ok_or_else(|| RegistryError::CorruptStore {
                    path: context.to_string(),
                    reason: format!(
                        "pin for {raw_key:?} has hash {raw_hash:?}, expected \"0x\" followed by exactly 64 hex digits"
                    ),
                })?;

            match canonical_pins.get(&canonical_key) {
                Some(existing) if existing == &canonical_hash => {
                    // Same name, same hash, just spelled differently before
                    // canonicalization. Not a conflict, nothing to do.
                }
                Some(existing) => {
                    return Err(RegistryError::CorruptStore {
                        path: context.to_string(),
                        reason: format!(
                            "conflicting pins for {canonical_key:?}: {existing} and {canonical_hash}"
                        ),
                    });
                }
                None => {
                    canonical_pins.insert(canonical_key, canonical_hash);
                }
            }
        }

        self.pins = canonical_pins;
        Ok(self)
    }

    /// Write atomically (tmp + sync_all + rename), pretty printed, trailing
    /// newline.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        // No floats and no non-string map keys anywhere in this type, so
        // serialization cannot fail in practice; there is no meaningful
        // error to report if it somehow did, since that would be a bug in
        // this crate rather than bad input or bad disk state.
        let mut json =
            serde_json::to_string_pretty(self).expect("ImportPolicy serialization is infallible");
        json.push('\n');
        write_atomically(path, json.as_bytes())
    }

    /// True when this DID is explicitly listed.
    pub fn allows_publisher(&self, did: &str) -> bool {
        self.allowed_publishers.iter().any(|e| e.did == did)
    }

    /// The full entry for a DID, including any provenance annotations.
    pub fn publisher(&self, did: &str) -> Option<&PublisherEntry> {
        self.allowed_publishers.iter().find(|e| e.did == did)
    }

    /// Every allowed publisher, sorted by DID.
    pub fn publishers(&self) -> &[PublisherEntry] {
        &self.allowed_publishers
    }

    /// Refuse a feed head whose signed `covered_at` is older than this.
    ///
    /// `None` means no freshness requirement, which is what a policy file that
    /// predates this setting means and what it keeps meaning.
    pub fn max_head_age_secs(&self) -> Option<u64> {
        self.max_head_age_secs
    }

    /// Set or clear the freshness requirement.
    pub fn set_max_head_age_secs(&mut self, seconds: Option<u64>) {
        self.max_head_age_secs = seconds;
    }

    /// Number of allowed publishers.
    pub fn publisher_count(&self) -> usize {
        self.allowed_publishers.len()
    }

    /// The pinned hash for a qualified name, if any.
    ///
    /// `qualified_name` is canonicalized before the lookup, so a query
    /// spelled with different case or NFC form than the stored pin still
    /// finds it. A query that is not a valid qualified name at all simply
    /// cannot have a pin, so this returns `None` rather than propagating
    /// the name error.
    pub fn pin(&self, qualified_name: &str) -> Option<&str> {
        let key = canonical_pin_key(qualified_name).ok()?;
        self.pins.get(&key).map(String::as_str)
    }

    /// Number of pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Every pinned qualified name, sorted.
    ///
    /// Sorted for free: `pins` is a `BTreeMap`, whose keys already iterate
    /// in ascending order.
    pub fn pinned_names(&self) -> Vec<&str> {
        self.pins.keys().map(String::as_str).collect()
    }

    /// Decide a single candidate against the pins.
    ///
    /// This never consults `allowed_publishers`; it only knows names and
    /// hashes. A caller combining [`PinMode::ApproveNew`] with an
    /// allow-list check is expected to check [`ImportPolicy::allows_publisher`]
    /// separately before treating [`PinDecision::ApproveAndPin`] as
    /// accepted. `template_hash` is compared case-insensitively against the
    /// stored pin, so capitalization can never be used to dodge a pin or a
    /// mismatch.
    pub fn check_pin(
        &self,
        qualified_name: &str,
        template_hash: &str,
        mode: PinMode,
    ) -> PinDecision {
        match self.pin(qualified_name) {
            Some(pinned) if pinned.eq_ignore_ascii_case(template_hash) => PinDecision::Pinned,
            Some(pinned) => PinDecision::Mismatch {
                pinned: pinned.to_string(),
                offered: template_hash.to_string(),
            },
            None => match mode {
                PinMode::PinnedOnly => PinDecision::NotPinned,
                PinMode::ApproveNew => PinDecision::ApproveAndPin,
            },
        }
    }

    /// Record a newly approved template. Returns true when it was added,
    /// false when an identical pin already existed. Errors on a CONFLICTING
    /// pin (same name, different hash): approving must never silently
    /// rewrite an existing pin, that is exactly the attack it defends
    /// against.
    ///
    /// `qualified_name` and `template_hash` are canonicalized the same way
    /// [`ImportPolicy::load`] canonicalizes a file, so a pin added here and
    /// one loaded from disk are stored identically and compare equal.
    pub fn approve(&mut self, qualified_name: &str, template_hash: &str) -> Result<bool> {
        let key = canonical_pin_key(qualified_name)?;
        let normalized_hash =
            normalize_hex_hash(template_hash).ok_or_else(|| RegistryError::InvalidHash {
                field: PIN_HASH_FIELD,
                reason: "expected \"0x\" followed by exactly 64 hex digits".to_string(),
            })?;

        match self.pins.get(&key) {
            Some(existing) if existing == &normalized_hash => Ok(false),
            Some(existing) => Err(RegistryError::CorruptStore {
                path: key.clone(),
                reason: format!(
                    "refusing to overwrite existing pin for {key:?}: pinned to {existing}, offered {normalized_hash}"
                ),
            }),
            None => {
                self.pins.insert(key, normalized_hash);
                Ok(true)
            }
        }
    }

    /// Add an allowed publisher DID. Returns true when newly added.
    ///
    /// A `did` that is empty or does not start with `"did:"` is never
    /// added; this returns `false` for it exactly as it would for an
    /// already-present entry, since either way nothing changed. This keeps
    /// the same invariant [`ImportPolicy::load`] enforces on file content
    /// (every entry in `allowed_publishers` is a non-empty `"did:"`-prefixed
    /// string) enforced on the in-memory API too, so there is no way to
    /// build an [`ImportPolicy`] in memory that [`ImportPolicy::load`] would
    /// then refuse to read back after a [`ImportPolicy::save`].
    pub fn allow_publisher(&mut self, did: &str) -> bool {
        self.allow_publisher_entry(PublisherEntry::bare(did))
    }

    /// Add an allowed publisher with provenance. Returns true when newly added.
    ///
    /// An existing DID is left alone rather than having its provenance
    /// overwritten: silently rewriting where a consumer recorded that a key
    /// came from would destroy the only audit trail the file has. Edit the
    /// file, or remove and re-add, to change it deliberately.
    pub fn allow_publisher_entry(&mut self, entry: PublisherEntry) -> bool {
        if entry.validate().is_err() {
            return false;
        }
        if self.allows_publisher(&entry.did) {
            return false;
        }
        self.allowed_publishers.push(entry);
        self.allowed_publishers.sort_by(|a, b| a.did.cmp(&b.did));
        true
    }
}

/// Canonicalizes a qualified name for use as a pin key: validates each half
/// per `crate::name` (spec-type-registry.md 3.3) and rejoins them, so the
/// same logical name always yields the same key regardless of case or NFC
/// form.
fn canonical_pin_key(qualified_name: &str) -> std::result::Result<String, NameError> {
    let (vendor, name) = validate_qualified_name(qualified_name)?;
    Ok(qualified(&vendor, &name))
}

/// True for a non-empty string starting with `"did:"`.
fn is_valid_publisher_did(did: &str) -> bool {
    !did.is_empty() && did.starts_with("did:")
}

/// Normalizes a pin hash: strips the `0x` prefix, requires exactly 64 hex
/// digits (32 bytes), and lowercases them so a pin cannot be dodged or
/// duplicated by capitalization alone. Returns `None` if `hash` does not
/// have that shape.
fn normalize_hex_hash(hash: &str) -> Option<String> {
    let body = hash.strip_prefix("0x")?;
    if body.len() == 64 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(format!("0x{}", body.to_ascii_lowercase()))
    } else {
        None
    }
}

/// Writes `contents` to `path` atomically.
///
/// Same approach as `crate::store`'s `write_atomically`: write to a sibling
/// `<path>.tmp`, `sync_all` it to force the bytes to durable storage, and
/// only then `rename` it onto `path`. A same-filesystem rename is atomic, so
/// a reader either sees the old contents or the complete new contents,
/// never a partial mix, and a crash before the rename leaves `path`
/// untouched with only an inert `.tmp` file behind. Duplicated here rather
/// than shared because that helper is private to `crate::store`.
fn write_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);

    let mut file = fs::File::create(&tmp_path).map_err(|e| storage_err(&tmp_path, e))?;
    file.write_all(contents)
        .map_err(|e| storage_err(&tmp_path, e))?;
    file.sync_all().map_err(|e| storage_err(&tmp_path, e))?;
    drop(file);

    fs::rename(&tmp_path, path).map_err(|e| storage_err(path, e))?;
    Ok(())
}

/// Wraps an I/O error with the path it happened on.
fn storage_err(path: &Path, source: io::Error) -> RegistryError {
    RegistryError::Storage {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A unique, self-cleaning directory under the OS temp dir for a single
    /// test to use. Uniqueness comes from the current process id plus a
    /// per-process atomic counter, so parallel test threads (and parallel
    /// test binaries) never collide on the same path.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aqua-template-registry-trust-test-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).expect("create temp dir for test");
            TempDir { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn hash_of(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    // ---- MAX_DEFINITION_BYTES --------------------------------------------

    #[test]
    fn max_definition_bytes_is_256_kib() {
        // Pins the exact cap: 256 * 1024 bytes, not an approximation.
        assert_eq!(MAX_DEFINITION_BYTES, 262_144);
    }

    // ---- empty() ----------------------------------------------------------

    #[test]
    fn empty_allows_no_publisher_and_pins_nothing() {
        // Rule 7: empty() is allow-nothing, not merely "unconfigured".
        let policy = ImportPolicy::empty();
        assert!(!policy.allows_publisher("did:key:z6MkAnything"));
        assert_eq!(policy.publisher_count(), 0);
        assert_eq!(policy.pin_count(), 0);
    }

    // ---- load(): missing file ----------------------------------------------

    #[test]
    fn load_missing_file_errors_not_allow_all() {
        // Rule 1: a missing file is an error, never a default-constructed
        // allow-nothing that could be mistaken for a successful load.
        let dir = TempDir::new();
        let err = ImportPolicy::load(dir.file("does-not-exist.json")).unwrap_err();
        assert!(matches!(err, RegistryError::Storage { .. }));
    }

    // ---- load(): version -----------------------------------------------------

    #[test]
    fn load_rejects_wrong_version() {
        // Rule 2: any version other than 1 is rejected with a clear error.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(&path, r#"{"version":2,"allowed_publishers":[],"pins":{}}"#).unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_accepts_version_1() {
        // The one version this build understands loads cleanly.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(&path, r#"{"version":1,"allowed_publishers":[],"pins":{}}"#).unwrap();
        assert!(ImportPolicy::load(&path).is_ok());
    }

    // ---- load(): allowed_publishers default and validation -----------------

    #[test]
    fn load_omitted_allowed_publishers_is_empty_not_wildcard() {
        // Rule 9: omitting allowed_publishers must yield an empty set, never
        // a default-allow-all.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(&path, r#"{"version":1}"#).unwrap();
        let policy = ImportPolicy::load(&path).unwrap();
        assert_eq!(policy.publisher_count(), 0);
        assert!(!policy.allows_publisher("did:key:z6MkAnything"));
        assert_eq!(policy.pin_count(), 0);
    }

    #[test]
    fn load_rejects_publisher_not_starting_with_did() {
        // Rule 3: every allowed publisher must start with "did:".
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":["not-a-did"],"pins":{}}"#,
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_rejects_empty_publisher_entry() {
        // Rule 3: an empty string is not a DID either.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":[""],"pins":{}}"#,
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    // ---- load(): pin key validation and canonicalization --------------------

    #[test]
    fn load_rejects_invalid_qualified_name_pin_key() {
        // Rule 3: a pin key that is not a valid qualified name rejects the
        // whole file, it is not skipped.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":[],"pins":{"not-qualified":"0xab"}}"#,
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_canonicalizes_pin_key_case() {
        // Rule 3: "InBlockIO/Audit_Artifact" must be stored/compared as
        // "inblockio/audit_artifact".
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        let hash = hash_of(0xAB);
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"allowed_publishers":[],"pins":{{"InBlockIO/Audit_Artifact":"{hash}"}}}}"#
            ),
        )
        .unwrap();
        let policy = ImportPolicy::load(&path).unwrap();
        assert_eq!(
            policy.pin("inblockio/audit_artifact"),
            Some(hash.to_lowercase().as_str())
        );
        assert_eq!(policy.pinned_names(), vec!["inblockio/audit_artifact"]);
    }

    #[test]
    fn load_merges_duplicate_canonical_keys_with_matching_hash() {
        // Two raw keys that canonicalize to the same name, with the SAME
        // hash (differing only in hash letter case), are not a conflict.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":[],"pins":{
                "acme/widget":"0xAAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999",
                "ACME/Widget":"0xaaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
            }}"#,
        )
        .unwrap();
        let policy = ImportPolicy::load(&path).unwrap();
        assert_eq!(policy.pin_count(), 1);
    }

    #[test]
    fn load_rejects_conflicting_duplicate_canonical_keys() {
        // Two raw keys that canonicalize to the same name with DIFFERENT
        // hashes are a conflict baked into the file: reject the whole file.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        let hash_a = hash_of(0x01);
        let hash_b = hash_of(0x02);
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"allowed_publishers":[],"pins":{{"acme/widget":"{hash_a}","ACME/Widget":"{hash_b}"}}}}"#
            ),
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    // ---- load(): pin hash validation and normalization -----------------------

    #[test]
    fn load_rejects_pin_hash_without_0x_prefix() {
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"allowed_publishers":[],"pins":{{"acme/widget":"{}"}}}}"#,
                "ab".repeat(32)
            ),
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_rejects_pin_hash_of_wrong_length() {
        // Exactly 64 hex digits are required, not "at least" or "even".
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":[],"pins":{"acme/widget":"0xabcd"}}"#,
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_rejects_pin_hash_with_non_hex_characters() {
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"allowed_publishers":[],"pins":{{"acme/widget":"0x{}"}}}}"#,
                "zz".repeat(32)
            ),
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    #[test]
    fn load_normalizes_pin_hash_to_lowercase() {
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        let hash_upper = hash_of(0xAB).to_uppercase().replace("0X", "0x");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"allowed_publishers":[],"pins":{{"acme/widget":"{hash_upper}"}}}}"#
            ),
        )
        .unwrap();
        let policy = ImportPolicy::load(&path).unwrap();
        let stored = policy.pin("acme/widget").unwrap();
        assert_eq!(stored, stored.to_lowercase());
        assert!(stored.eq_ignore_ascii_case(&hash_upper));
    }

    // ---- deny_unknown_fields --------------------------------------------------

    #[test]
    fn load_rejects_unknown_top_level_key() {
        // Rule 8: a typo'd key is an error, never a silently ignored setting.
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        fs::write(
            &path,
            r#"{"version":1,"allowed_publishers":[],"pins":{},"allowed_publisher":["oops"]}"#,
        )
        .unwrap();
        let err = ImportPolicy::load(&path).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
    }

    // ---- save() / load() round trip -------------------------------------------

    #[test]
    fn save_then_load_round_trips_exactly() {
        // Rule 6: full equality of allowed_publishers and pins after a
        // save/load round trip.
        let dir = TempDir::new();
        let path = dir.file("policy.json");

        let mut original = ImportPolicy::empty();
        assert!(original.allow_publisher("did:key:z6MkPublisherOne"));
        assert!(original.allow_publisher("did:key:z6MkPublisherTwo"));
        original.approve("acme/widget", &hash_of(0x11)).unwrap();
        original
            .approve("inblockio/audit_artifact", &hash_of(0x22))
            .unwrap();

        original.save(&path).unwrap();
        let loaded = ImportPolicy::load(&path).unwrap();

        assert_eq!(loaded.allowed_publishers, original.allowed_publishers);
        assert_eq!(loaded.pins, original.pins);
    }

    #[test]
    fn save_writes_pretty_json_with_trailing_newline() {
        let dir = TempDir::new();
        let path = dir.file("policy.json");
        ImportPolicy::empty().save(&path).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        assert!(
            contents.contains('\n'),
            "pretty printing should be multi-line"
        );
    }

    // ---- check_pin() truth table --------------------------------------------

    fn policy_with_one_pin() -> ImportPolicy {
        let mut policy = ImportPolicy::empty();
        policy.approve("acme/widget", &hash_of(0x11)).unwrap();
        policy
    }

    #[test]
    fn check_pin_matching_hash_is_pinned_in_pinned_only_mode() {
        let policy = policy_with_one_pin();
        let decision = policy.check_pin("acme/widget", &hash_of(0x11), PinMode::PinnedOnly);
        assert_eq!(decision, PinDecision::Pinned);
    }

    #[test]
    fn check_pin_matching_hash_is_pinned_in_approve_new_mode() {
        let policy = policy_with_one_pin();
        let decision = policy.check_pin("acme/widget", &hash_of(0x11), PinMode::ApproveNew);
        assert_eq!(decision, PinDecision::Pinned);
    }

    #[test]
    fn check_pin_matching_hash_case_insensitive() {
        // Capitalization must never defeat a pin match. Uses 0xAB (has
        // alphabetic hex digits) rather than 0x11, so uppercasing actually
        // changes the string and the test exercises real case-folding.
        let mut policy = ImportPolicy::empty();
        policy.approve("acme/widget", &hash_of(0xAB)).unwrap();
        let offered = hash_of(0xAB).to_uppercase().replace("0X", "0x");
        let decision = policy.check_pin("acme/widget", &offered, PinMode::PinnedOnly);
        assert_eq!(decision, PinDecision::Pinned);
    }

    #[test]
    fn check_pin_different_hash_is_mismatch_in_pinned_only_mode() {
        let policy = policy_with_one_pin();
        let decision = policy.check_pin("acme/widget", &hash_of(0x99), PinMode::PinnedOnly);
        assert!(matches!(decision, PinDecision::Mismatch { .. }));
    }

    #[test]
    fn check_pin_different_hash_is_mismatch_in_approve_new_mode() {
        // ApproveNew must NOT override a mismatch: same-name-different-hash
        // is the attack this module exists to stop, in every mode.
        let policy = policy_with_one_pin();
        let decision = policy.check_pin("acme/widget", &hash_of(0x99), PinMode::ApproveNew);
        assert!(matches!(decision, PinDecision::Mismatch { .. }));
    }

    #[test]
    fn check_pin_mismatch_carries_both_hashes() {
        let policy = policy_with_one_pin();
        let offered = hash_of(0x99);
        let decision = policy.check_pin("acme/widget", &offered, PinMode::PinnedOnly);
        assert_eq!(
            decision,
            PinDecision::Mismatch {
                pinned: hash_of(0x11),
                offered,
            }
        );
    }

    #[test]
    fn check_pin_unpinned_name_is_not_pinned_in_pinned_only_mode() {
        let policy = ImportPolicy::empty();
        let decision = policy.check_pin("acme/widget", &hash_of(0x11), PinMode::PinnedOnly);
        assert_eq!(decision, PinDecision::NotPinned);
    }

    #[test]
    fn check_pin_unpinned_name_is_approve_and_pin_in_approve_new_mode() {
        let policy = ImportPolicy::empty();
        let decision = policy.check_pin("acme/widget", &hash_of(0x11), PinMode::ApproveNew);
        assert_eq!(decision, PinDecision::ApproveAndPin);
    }

    #[test]
    fn pin_mode_default_is_pinned_only() {
        // The fail-closed default: absence of an explicit mode means the
        // strict one, not the one that can grow the pin set.
        assert_eq!(PinMode::default(), PinMode::PinnedOnly);
    }

    // ---- approve() ----------------------------------------------------------

    #[test]
    fn approve_new_name_returns_true() {
        let mut policy = ImportPolicy::empty();
        let added = policy.approve("acme/widget", &hash_of(0x11)).unwrap();
        assert!(added);
        assert_eq!(policy.pin("acme/widget"), Some(hash_of(0x11).as_str()));
    }

    #[test]
    fn approve_identical_existing_pin_returns_false() {
        let mut policy = ImportPolicy::empty();
        assert!(policy.approve("acme/widget", &hash_of(0x11)).unwrap());
        let added_again = policy.approve("acme/widget", &hash_of(0x11)).unwrap();
        assert!(!added_again);
        assert_eq!(policy.pin_count(), 1);
    }

    #[test]
    fn approve_conflicting_pin_errors_and_does_not_overwrite() {
        let mut policy = ImportPolicy::empty();
        assert!(policy.approve("acme/widget", &hash_of(0x11)).unwrap());
        let err = policy.approve("acme/widget", &hash_of(0x22)).unwrap_err();
        assert!(matches!(err, RegistryError::CorruptStore { .. }));
        // The original pin must survive untouched.
        assert_eq!(policy.pin("acme/widget"), Some(hash_of(0x11).as_str()));
        assert_eq!(policy.pin_count(), 1);
    }

    #[test]
    fn approve_canonicalizes_name_and_hash() {
        let mut policy = ImportPolicy::empty();
        let mixed_hash = hash_of(0xAB).to_uppercase().replace("0X", "0x");
        assert!(policy
            .approve("InBlockIO/Audit_Artifact", &mixed_hash)
            .unwrap());
        assert_eq!(
            policy.pin("inblockio/audit_artifact"),
            Some(hash_of(0xAB).as_str())
        );
    }

    #[test]
    fn approve_rejects_invalid_qualified_name() {
        let mut policy = ImportPolicy::empty();
        let err = policy.approve("not-qualified", &hash_of(0x11)).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidName(_)));
    }

    #[test]
    fn approve_rejects_malformed_hash() {
        let mut policy = ImportPolicy::empty();
        let err = policy.approve("acme/widget", "0xnothex").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidHash { .. }));
    }

    // ---- allow_publisher() / allows_publisher() ------------------------------

    #[test]
    fn allow_publisher_new_did_returns_true() {
        let mut policy = ImportPolicy::empty();
        assert!(policy.allow_publisher("did:key:z6MkNew"));
        assert!(policy.allows_publisher("did:key:z6MkNew"));
        assert_eq!(policy.publisher_count(), 1);
    }

    #[test]
    fn allow_publisher_already_present_returns_false() {
        let mut policy = ImportPolicy::empty();
        assert!(policy.allow_publisher("did:key:z6MkNew"));
        assert!(!policy.allow_publisher("did:key:z6MkNew"));
        assert_eq!(policy.publisher_count(), 1);
    }

    #[test]
    fn allow_publisher_rejects_non_did_string() {
        // The in-memory API enforces the same invariant load() enforces on
        // disk: never lets an obviously-invalid entry in.
        let mut policy = ImportPolicy::empty();
        assert!(!policy.allow_publisher("not-a-did"));
        assert!(!policy.allow_publisher(""));
        assert_eq!(policy.publisher_count(), 0);
    }

    // ---- pinned_names() ordering -----------------------------------------------

    #[test]
    fn pinned_names_are_sorted() {
        let mut policy = ImportPolicy::empty();
        policy.approve("zebra/z", &hash_of(0x01)).unwrap();
        policy.approve("acme/a", &hash_of(0x02)).unwrap();
        policy.approve("mid/m", &hash_of(0x03)).unwrap();
        assert_eq!(policy.pinned_names(), vec!["acme/a", "mid/m", "zebra/z"]);
    }
}
