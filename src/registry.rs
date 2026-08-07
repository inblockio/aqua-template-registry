//! The registry: acceptance rules, indexes, and lookups.
//!
//! # Trust model (spec-type-registry.md section 3.7)
//!
//! There is exactly one authority in this registry, and it is the publisher's
//! signing key. The registry never decides who someone is; it reads the signer
//! DID off the tree and enforces three rules:
//!
//! 1. **Vendor registrations are self-certifying.** A `vendor-registration` for
//!    namespace `V` is accepted only if the tree's signer DID equals the
//!    `vendor_did` in its own payload. A key can only claim a namespace for
//!    itself.
//! 2. **Namespaces are first come, first served.** Once `V` is claimed by DID
//!    `D`, another DID cannot claim `V`. `D` may re-register `V` to update the
//!    display name.
//! 3. **Only the namespace owner writes into it.** A `template-registration` or
//!    `alias-registration` naming vendor `V` is accepted only if its signer DID
//!    equals the `vendor_did` recorded by `V`'s prior vendor registration.
//!
//! What this registry deliberately does NOT do: decide whether `D` is *trusted*.
//! The spec's section 4 adds a domain-scoped trust store on top ("is this DID
//! trusted for the `registry` domain?"). That is a consumer-side policy
//! question, and wiring it in here would make the registry an authority rather
//! than an index. Consumers subscribe to the publisher DIDs they already trust.
//!
//! # Indexes
//!
//! The durable state is the append-only feed. Everything below is derived and
//! rebuilt by replaying it at startup:
//!
//! | Index | Answers |
//! |---|---|
//! | `vendors` | vendor name to owning DID |
//! | `vendors_by_did` | DID to the namespaces it owns |
//! | `templates` | template hash to its registration record |
//! | `by_qualified` | `<vendor>/<name>` to every version ever registered |
//! | `aliases` | `<vendor>/<alias>` to a target hash |
//! | `superseded` | which hashes some later version replaced |
//! | `feed_by_did` | DID to its sequence numbers (the subscription index) |
//!
//! `vendors_by_did` and `feed_by_did` are the reverse indexes that make
//! publisher-DID subscription possible, and are the reason this project exists
//! separately from the SDK.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::RwLock;

use aqua_rs_sdk_core::Aquafier;

use crate::error::{RegistryError, Result};
use crate::model::{
    AliasRecord, DefinitionReceipt, FeedEntry, FeedPage, HeadReceipt, Receipt, RegistrationKind,
    RegistrationPayload, Resolution, ResolutionVia, Stats, TemplateRecord, VendorRecord,
};
use crate::name::{self, NameValidator};
use crate::store::Store;
use crate::verify::{self, Accepted};

/// Default page size for the subscription feed.
pub const DEFAULT_FEED_LIMIT: usize = 100;
/// Hard cap on the feed page size, so a consumer cannot ask for everything.
pub const MAX_FEED_LIMIT: usize = 1000;

#[derive(Default)]
struct Index {
    vendors: BTreeMap<String, VendorRecord>,
    vendors_by_did: BTreeMap<String, BTreeSet<String>>,
    templates: BTreeMap<String, TemplateRecord>,
    by_qualified: BTreeMap<String, Vec<String>>,
    aliases: BTreeMap<String, AliasRecord>,
    superseded: BTreeSet<String>,
    feed_by_did: BTreeMap<String, Vec<u64>>,
    entries: Vec<FeedEntry>,
    head_seq: u64,
}

/// A template registry instance.
///
/// Cheap to share: put it in an `Arc` and hand it to as many request handlers as
/// you like. Writes take a short write lock on the index; reads take a read lock.
pub struct Registry {
    store: Store,
    aquafier: Aquafier,
    index: RwLock<Index>,
}

impl Registry {
    /// Open a registry rooted at `dir`, replaying any persisted feed.
    ///
    /// Replay is a full re-application of the acceptance rules against the
    /// in-memory index, but it does NOT re-verify signatures: those were
    /// verified when the entry was first accepted, and the tree bytes are
    /// stored verbatim so anyone can re-verify them out of band. Rejecting a
    /// previously accepted entry at replay would mean the registry silently
    /// forgot a registration, so replay conflicts are surfaced as
    /// `CorruptStore` instead.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let store = Store::open(dir)?;
        let entries = store.load_all()?;

        let mut index = Index::default();
        for entry in entries {
            apply(&mut index, entry).map_err(|e| RegistryError::CorruptStore {
                path: store.root().display().to_string(),
                reason: format!("replaying the feed hit a conflict: {e}"),
            })?;
        }

        Ok(Self {
            store,
            aquafier: Aquafier::new(),
            index: RwLock::new(index),
        })
    }

    /// The `Aquafier` this registry verifies with. Exposed so tests and
    /// publisher tooling can build trees with matching settings.
    pub fn aquafier(&self) -> &Aquafier {
        &self.aquafier
    }

    // ---- submission ---------------------------------------------------------

    /// Accept a signed vendor-registration tree.
    pub async fn submit_vendor(&self, body: &str) -> Result<Receipt> {
        self.submit(body, Some(RegistrationKind::Vendor)).await
    }

    /// Accept a signed template-registration tree.
    pub async fn submit_template(&self, body: &str) -> Result<Receipt> {
        self.submit(body, Some(RegistrationKind::Template)).await
    }

    /// Accept a signed alias-registration tree.
    pub async fn submit_alias(&self, body: &str) -> Result<Receipt> {
        self.submit(body, Some(RegistrationKind::Alias)).await
    }

    /// Accept a signed registration tree of any kind.
    pub async fn submit(&self, body: &str, expected: Option<RegistrationKind>) -> Result<Receipt> {
        // Cryptographic acceptance happens outside the lock: it is the slow part
        // and it needs no index state.
        let accepted = verify::accept(&self.aquafier, body, expected).await?;

        let mut index = self.index.write().expect("index lock poisoned");

        // Trust rules that need the index.
        check_trust(&index, &accepted)?;

        let seq = index.head_seq + 1;
        let entry = FeedEntry {
            seq,
            kind: accepted.kind,
            publisher_did: accepted.publisher_did.clone(),
            tree_tip: accepted.tree_tip.clone(),
            received_at: now_secs(),
            qualified_name: accepted.qualified_name(),
            payload: accepted.payload.clone(),
        };

        // Persist before mutating the index. If the write fails the registry has
        // not changed, and the caller sees the storage error.
        self.store.append(&entry, &accepted.raw)?;

        let receipt = Receipt {
            seq,
            kind: entry.kind,
            publisher_did: entry.publisher_did.clone(),
            tree_tip: entry.tree_tip.clone(),
            qualified_name: entry.qualified_name.clone(),
        };

        apply(&mut index, entry)?;
        Ok(receipt)
    }

    // ---- definition bodies --------------------------------------------------

    /// Accept a template definition body.
    ///
    /// A definition body needs no signature of its own, because it is content
    /// addressed and its address is already covered by a signature. The
    /// registry recomputes the hash from the body through core, and accepts it
    /// only if some publisher already registered exactly that hash in a signed
    /// `template-registration`. So the body is bound to a signed claim without
    /// the uploader having to be anyone in particular: a mirror, a CI job, or
    /// a third party can supply it, and a wrong body simply hashes to
    /// something nobody registered.
    ///
    /// Idempotent: re-uploading the identical body is a no-op. It cannot be
    /// anything else, since a different body is a different hash.
    ///
    /// Bodies carrying a `verification` (WASM) section are refused. Core has
    /// no WASM runtime, and a registry that will not host executable template
    /// bodies cannot become a distribution channel for them toward full-SDK
    /// consumers. This mirrors the same refusal on the import side, which is
    /// the one that actually protects a given consumer; both are cheap.
    pub fn submit_definition(&self, body: &str) -> Result<DefinitionReceipt> {
        if body.len() > crate::trust::MAX_DEFINITION_BYTES {
            return Err(RegistryError::DefinitionTooLarge {
                bytes: body.len(),
                max: crate::trust::MAX_DEFINITION_BYTES,
            });
        }

        // Parsing goes through core's Template, so a body that is not a
        // template is refused here rather than stored under a meaningless key.
        let template_hash = crate::templates::template_hash_of_definition(body)?;

        if carries_wasm(body) {
            return Err(RegistryError::DefinitionCarriesWasm(template_hash));
        }

        let known = {
            let index = self.index.read().expect("index lock poisoned");
            index.templates.contains_key(&template_hash)
        };
        if !known {
            return Err(RegistryError::DefinitionNotRegistered(template_hash));
        }

        let existed = self.store.read_definition(&template_hash)?.is_some();
        if !existed {
            self.store.write_definition(&template_hash, body)?;
        }

        Ok(DefinitionReceipt {
            template_hash,
            bytes: body.len(),
            stored: !existed,
        })
    }

    /// A stored definition body, verbatim, after a recompute-on-read check.
    ///
    /// The stored body is hashed again and compared against the key it was
    /// filed under before it is handed out. On-disk corruption or tampering
    /// therefore surfaces as an error at the moment of serving instead of
    /// being passed on to a consumer who trusts this registry. A consumer who
    /// does not trust it re-checks anyway, which is the supported posture, but
    /// serving something known-bad would still be wrong.
    pub fn definition(&self, template_hash: &str) -> Result<String> {
        let body = self
            .store
            .read_definition(template_hash)?
            .ok_or_else(|| RegistryError::NotFound(format!("definition {template_hash}")))?;

        let recomputed = crate::templates::template_hash_of_definition(&body).map_err(|e| {
            RegistryError::CorruptStore {
                path: format!("definitions/{template_hash}"),
                reason: format!("stored body no longer parses as a template: {e}"),
            }
        })?;
        if !recomputed.eq_ignore_ascii_case(template_hash) {
            return Err(RegistryError::CorruptStore {
                path: format!("definitions/{template_hash}"),
                reason: format!("stored body hashes to {recomputed}, not to its own key"),
            });
        }
        Ok(body)
    }

    /// Every template hash that has a definition body on hand.
    pub fn definition_hashes(&self) -> Result<Vec<String>> {
        self.store.definition_hashes()
    }

    /// Whether a definition body is on hand for this template hash.
    pub fn has_definition(&self, template_hash: &str) -> bool {
        self.store
            .read_definition(template_hash)
            .ok()
            .flatten()
            .is_some()
    }

    // ---- feed heads ---------------------------------------------------------

    /// Accept a publisher's signed commitment to their own feed.
    ///
    /// Verified like any other submission: the tree must verify through core,
    /// carry exactly one `feed_head` object, and be signed by exactly one DID
    /// which must equal the `signer_did` it names. On top of that the registry
    /// checks the head against its OWN view of that publisher's feed and
    /// refuses one whose root does not match.
    ///
    /// That last check is a courtesy to the publisher, not a security control.
    /// A subscriber recomputes the root itself and does not rely on the
    /// registry having done so, precisely because the registry is the party a
    /// feed head exists to constrain. What it does buy is that a publisher who
    /// builds a head from the wrong entry order finds out at submit time rather
    /// than through a subscriber failing closed days later.
    pub async fn submit_head(&self, body: &str) -> Result<HeadReceipt> {
        let head = crate::feedhead::verify_head(&self.aquafier, body, None)
            .await
            .map_err(|e| RegistryError::HeadRejected(e.to_string()))?;

        let tips = self.publisher_entry_tips(&head.publisher_did);
        if tips.is_empty() {
            return Err(RegistryError::HeadRejected(format!(
                "publisher {} has no feed entries here to commit to",
                head.publisher_did
            )));
        }
        crate::feedhead::check_against_entries(&head, &tips)
            .map_err(|e| RegistryError::HeadRejected(e.to_string()))?;

        // A head may not go backwards, and two heads at one height must agree.
        if let Some((prev_seq, prev_tree)) = self.store.read_latest_head(&head.publisher_did)? {
            let previous = crate::feedhead::verify_head(&self.aquafier, &prev_tree, None)
                .await
                .map_err(|e| RegistryError::CorruptStore {
                    path: format!("heads/{}/{prev_seq}", head.publisher_did),
                    reason: e.to_string(),
                })?;
            crate::feedhead::check_against_previous(
                &head,
                Some(previous.head_seq),
                Some(&previous.merkle_root),
            )
            .map_err(|e| RegistryError::HeadRejected(e.to_string()))?;
        }

        let stored = self
            .store
            .read_head(&head.publisher_did, head.head_seq)?
            .is_none();
        if stored {
            self.store
                .write_head(&head.publisher_did, head.head_seq, body)?;
        }

        Ok(HeadReceipt {
            publisher_did: head.publisher_did,
            head_seq: head.head_seq,
            merkle_root: head.merkle_root,
            tree_tip: head.tree_tip,
            stored,
        })
    }

    /// The publisher's highest stored feed head, verbatim.
    pub fn latest_head(&self, publisher_did: &str) -> Result<Option<String>> {
        Ok(self
            .store
            .read_latest_head(publisher_did)?
            .map(|(_, tree)| tree))
    }

    /// A publisher's head at a specific height, verbatim.
    pub fn head_at(&self, publisher_did: &str, head_seq: u64) -> Result<Option<String>> {
        self.store.read_head(publisher_did, head_seq)
    }

    /// Every height at which this publisher has a stored head, ascending.
    pub fn head_seqs(&self, publisher_did: &str) -> Result<Vec<u64>> {
        self.store.head_seqs(publisher_did)
    }

    /// A publisher's own entry tips, in feed order.
    ///
    /// This is the sequence a feed head commits to: ordinal 1 is the first
    /// element. Registry-global `seq` gaps caused by other publishers are
    /// closed here, which is what makes a head portable to a mirror that
    /// assigned different global numbers.
    pub fn publisher_entry_tips(&self, publisher_did: &str) -> Vec<String> {
        let index = self.index.read().expect("index lock poisoned");
        index
            .feed_by_did
            .get(publisher_did)
            .map(|seqs| {
                seqs.iter()
                    .filter_map(|s| index.entries.get((*s - 1) as usize))
                    .map(|e| e.tree_tip.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    // ---- lookups ------------------------------------------------------------

    /// Resolve a vendor namespace to its record.
    pub fn vendor(&self, vendor: &str) -> Result<VendorRecord> {
        let canonical = NameValidator::validate_vendor_name(vendor)?;
        let index = self.index.read().expect("index lock poisoned");
        index
            .vendors
            .get(&canonical)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(format!("vendor {canonical:?}")))
    }

    /// Every vendor namespace owned by a publisher DID.
    pub fn publisher_vendors(&self, did: &str) -> Vec<VendorRecord> {
        let index = self.index.read().expect("index lock poisoned");
        index
            .vendors_by_did
            .get(did)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| index.vendors.get(n).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every template registered by a publisher DID, newest registration first.
    ///
    /// This is the reverse index the SDK has no equivalent of: it answers "what
    /// does this publisher offer?" without knowing any of their names in
    /// advance, which is what a subscribing consumer actually needs.
    pub fn publisher_templates(&self, did: &str) -> Vec<TemplateRecord> {
        let index = self.index.read().expect("index lock poisoned");
        let mut out: Vec<TemplateRecord> = index
            .templates
            .values()
            .filter(|t| t.publisher_did == did)
            .cloned()
            .collect();
        // Newest registration first.
        out.sort_by_key(|t| std::cmp::Reverse(t.seq));
        out
    }

    /// Every alias registered by a publisher DID.
    pub fn publisher_aliases(&self, did: &str) -> Vec<AliasRecord> {
        let index = self.index.read().expect("index lock poisoned");
        let mut out: Vec<AliasRecord> = index
            .aliases
            .values()
            .filter(|a| a.publisher_did == did)
            .cloned()
            .collect();
        // Newest registration first.
        out.sort_by_key(|a| std::cmp::Reverse(a.seq));
        out
    }

    /// The registration record for a template hash.
    pub fn template(&self, template_hash: &str) -> Result<TemplateRecord> {
        let index = self.index.read().expect("index lock poisoned");
        index
            .templates
            .get(template_hash)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(format!("template {template_hash}")))
    }

    /// The full signed registration tree for a template hash, verbatim.
    ///
    /// Returned exactly as submitted, signatures intact, so the caller can
    /// re-verify it with `aqua-rs-sdk-core` and never has to trust this registry.
    pub fn template_tree(&self, template_hash: &str) -> Result<String> {
        let tip = {
            let index = self.index.read().expect("index lock poisoned");
            index
                .templates
                .get(template_hash)
                .map(|t| t.tree_tip.clone())
                .ok_or_else(|| RegistryError::NotFound(format!("template {template_hash}")))?
        };
        self.tree_by_tip(&tip)
    }

    /// The full signed tree stored under a tip hash, verbatim.
    pub fn tree_by_tip(&self, tree_tip: &str) -> Result<String> {
        self.store
            .read_tree(tree_tip)?
            .ok_or_else(|| RegistryError::NotFound(format!("tree {tree_tip}")))
    }

    /// Resolve `<vendor>/<name>` to a template hash.
    ///
    /// Templates win over aliases when both exist (they cannot both exist: the
    /// acceptance rules reject the collision), and the newest non-superseded
    /// version wins within a name. The full lineage is returned alongside, so a
    /// caller pinning an older version can see where it sits.
    pub fn resolve(&self, vendor: &str, name: &str) -> Result<Resolution> {
        let vendor = NameValidator::validate_vendor_name(vendor)?;
        let name = NameValidator::validate_template_name(name)?;
        let qualified = name::qualified(&vendor, &name);

        let index = self.index.read().expect("index lock poisoned");

        if let Some(versions) = index.by_qualified.get(&qualified) {
            if let Some(current) = current_version(&index, versions) {
                let record = index.templates.get(&current).expect("indexed");
                return Ok(Resolution {
                    qualified_name: qualified,
                    template_hash: current,
                    via: ResolutionVia::Template,
                    publisher_did: Some(record.publisher_did.clone()),
                    lineage: versions.clone(),
                });
            }
        }

        if let Some(alias) = index.aliases.get(&qualified) {
            let publisher_did = index
                .templates
                .get(&alias.target_hash)
                .map(|t| t.publisher_did.clone());
            let lineage = index
                .templates
                .get(&alias.target_hash)
                .and_then(|t| index.by_qualified.get(&t.qualified_name).cloned())
                .unwrap_or_default();
            return Ok(Resolution {
                qualified_name: qualified,
                template_hash: alias.target_hash.clone(),
                via: ResolutionVia::Alias,
                publisher_did,
                lineage,
            });
        }

        Err(RegistryError::NotFound(format!("name {qualified:?}")))
    }

    /// One page of a publisher's subscription feed.
    ///
    /// Returns entries with `seq > since`, oldest first. A consumer polls with
    /// the `next` cursor from the previous response. Sequence numbers are
    /// registry-global and persisted, so a restart does not rewind or replay a
    /// consumer's cursor.
    pub fn feed(&self, did: &str, since: u64, limit: Option<usize>) -> FeedPage {
        let limit = limit.unwrap_or(DEFAULT_FEED_LIMIT).clamp(1, MAX_FEED_LIMIT);
        let index = self.index.read().expect("index lock poisoned");

        let seqs = index.feed_by_did.get(did);
        let matching: Vec<u64> = seqs
            .map(|s| s.iter().copied().filter(|s| *s > since).collect())
            .unwrap_or_default();

        let has_more = matching.len() > limit;
        let entries: Vec<FeedEntry> = matching
            .iter()
            .take(limit)
            .filter_map(|seq| index.entries.get((*seq - 1) as usize).cloned())
            .collect();

        let next = entries.last().map(|e| e.seq).unwrap_or(since);

        FeedPage {
            publisher_did: did.to_string(),
            since,
            next,
            has_more,
            entries,
        }
    }

    /// Counters for operators.
    pub fn stats(&self) -> Stats {
        let index = self.index.read().expect("index lock poisoned");
        Stats {
            head_seq: index.head_seq,
            vendors: index.vendors.len(),
            templates: index.templates.len(),
            aliases: index.aliases.len(),
            publishers: index.feed_by_did.len(),
        }
    }

    /// Every claimed vendor namespace, alphabetically.
    pub fn vendors(&self) -> Vec<VendorRecord> {
        let index = self.index.read().expect("index lock poisoned");
        index.vendors.values().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Trust rules
// ---------------------------------------------------------------------------

/// Apply the section 3.7 publisher-DID rules plus index-level conflict checks.
fn check_trust(index: &Index, accepted: &Accepted) -> Result<()> {
    match &accepted.payload {
        RegistrationPayload::Vendor(p) => {
            // Rule 1: self-certifying. The signer must be the DID it claims.
            if p.vendor_did != accepted.publisher_did {
                return Err(RegistryError::NotSelfCertifying {
                    signer: accepted.publisher_did.clone(),
                    claimed: p.vendor_did.clone(),
                });
            }
            // Rule 2: first come, first served.
            if let Some(existing) = index.vendors.get(&accepted.vendor) {
                if existing.vendor_did != accepted.publisher_did {
                    return Err(RegistryError::VendorNameTaken {
                        vendor: accepted.vendor.clone(),
                        owner: existing.vendor_did.clone(),
                    });
                }
            }
            Ok(())
        }

        RegistrationPayload::Template(p) => {
            // Rule 3: only the namespace owner writes into it.
            owner_check(index, &accepted.vendor, &accepted.publisher_did)?;

            let qualified = accepted.qualified_name();

            if index.templates.contains_key(&p.template_hash) {
                return Err(RegistryError::DuplicateTemplate(p.template_hash.clone()));
            }
            if index.aliases.contains_key(&qualified) {
                return Err(RegistryError::NameCollision(qualified));
            }

            // Version lineage (spec section 3.5 and spec-module-ecosystem section 11):
            // a supersedes target must be a known version of this same name, and
            // must not already have been superseded, so the chain stays linear.
            if let Some(target) = &p.supersedes {
                let known = index
                    .by_qualified
                    .get(&qualified)
                    .is_some_and(|v| v.contains(target));
                if !known {
                    return Err(RegistryError::UnknownSupersedes {
                        qualified,
                        target: target.clone(),
                    });
                }
                if index.superseded.contains(target) {
                    return Err(RegistryError::AlreadySuperseded(target.clone()));
                }
            }
            Ok(())
        }

        RegistrationPayload::Alias(_) => {
            owner_check(index, &accepted.vendor, &accepted.publisher_did)?;
            let qualified = accepted.qualified_name();
            if index.aliases.contains_key(&qualified) {
                return Err(RegistryError::DuplicateAlias(qualified));
            }
            if index.by_qualified.contains_key(&qualified) {
                return Err(RegistryError::NameCollision(qualified));
            }
            Ok(())
        }
    }
}

fn owner_check(index: &Index, vendor: &str, signer: &str) -> Result<()> {
    let record = index
        .vendors
        .get(vendor)
        .ok_or_else(|| RegistryError::VendorNotRegistered(vendor.to_string()))?;
    if record.vendor_did != signer {
        return Err(RegistryError::NotNamespaceOwner {
            vendor: vendor.to_string(),
            owner: record.vendor_did.clone(),
            signer: signer.to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Index maintenance
// ---------------------------------------------------------------------------

/// Fold one feed entry into the index. Used both on submit and on replay, so
/// the two paths cannot drift apart.
fn apply(index: &mut Index, entry: FeedEntry) -> Result<()> {
    let seq = entry.seq;
    if seq != index.head_seq + 1 {
        return Err(RegistryError::CorruptStore {
            path: format!("feed entry {seq}"),
            reason: format!("expected seq {}, found {seq}", index.head_seq + 1),
        });
    }

    match &entry.payload {
        RegistrationPayload::Vendor(p) => {
            let vendor = NameValidator::validate_vendor_name(&p.vendor_name)?;
            index.vendors.insert(
                vendor.clone(),
                VendorRecord {
                    vendor: vendor.clone(),
                    vendor_did: p.vendor_did.clone(),
                    display_name: p.display_name.clone(),
                    seq,
                    tree_tip: entry.tree_tip.clone(),
                },
            );
            index
                .vendors_by_did
                .entry(p.vendor_did.clone())
                .or_default()
                .insert(vendor);
        }

        RegistrationPayload::Template(p) => {
            let vendor = NameValidator::validate_vendor_name(&p.vendor)?;
            let name = NameValidator::validate_template_name(&p.name)?;
            let qualified = name::qualified(&vendor, &name);

            index.templates.insert(
                p.template_hash.clone(),
                TemplateRecord {
                    vendor,
                    name,
                    qualified_name: qualified.clone(),
                    template_hash: p.template_hash.clone(),
                    supersedes: p.supersedes.clone(),
                    superseded_by: None,
                    display_name: p.display_name.clone(),
                    description: p.description.clone(),
                    daemon_trigger: p.daemon_trigger,
                    file_dependency: p.file_dependency.clone(),
                    publisher_did: entry.publisher_did.clone(),
                    seq,
                    tree_tip: entry.tree_tip.clone(),
                },
            );
            index
                .by_qualified
                .entry(qualified)
                .or_default()
                .push(p.template_hash.clone());

            if let Some(target) = &p.supersedes {
                index.superseded.insert(target.clone());
                if let Some(old) = index.templates.get_mut(target) {
                    old.superseded_by = Some(p.template_hash.clone());
                }
            }
        }

        RegistrationPayload::Alias(p) => {
            let vendor = NameValidator::validate_vendor_name(&p.vendor)?;
            let alias_name = NameValidator::validate_template_name(&p.alias_name)?;
            let qualified = name::qualified(&vendor, &alias_name);
            index.aliases.insert(
                qualified.clone(),
                AliasRecord {
                    vendor,
                    alias_name,
                    qualified_name: qualified,
                    target_hash: p.target_hash.clone(),
                    publisher_did: entry.publisher_did.clone(),
                    seq,
                    tree_tip: entry.tree_tip.clone(),
                },
            );
        }
    }

    index
        .feed_by_did
        .entry(entry.publisher_did.clone())
        .or_default()
        .push(seq);
    index.head_seq = seq;
    index.entries.push(entry);
    Ok(())
}

/// The current version of a qualified name: the newest registered hash that
/// nothing else supersedes.
fn current_version(index: &Index, versions: &[String]) -> Option<String> {
    versions
        .iter()
        .rev()
        .find(|h| !index.superseded.contains(*h))
        .cloned()
}

/// True when a template definition declares a `verification` (WASM) section.
///
/// Checked on the raw JSON rather than through core's `Template`, because the
/// question is "does this body claim to carry executable content", and the
/// answer must not depend on how faithfully a struct round-trips it.
pub(crate) fn carries_wasm(definition_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(definition_json)
        .ok()
        .and_then(|v| v.get("verification").cloned())
        .is_some_and(|v| !v.is_null())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
