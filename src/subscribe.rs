//! Subscribing to a publisher: poll the feed, verify, import.
//!
//! A subscription is a cursor and a policy. The cursor is one integer persisted
//! to disk, so a restarted subscriber resumes where it stopped instead of
//! reprocessing history or skipping it. The policy is
//! [`crate::trust::ImportPolicy`], and every candidate goes through the full
//! chain in [`crate::import`] before anything touches the local store.
//!
//! # The cursor only advances over accepted work
//!
//! An entry that is rejected does not move the cursor past itself. If the
//! rejection is a policy decision the operator can act on (an unpinned template
//! in `PinnedOnly` mode, say), the next poll offers it again, and it is
//! imported once the pin exists. The cost is that a permanently rejected entry
//! is retried on every poll. That is the correct trade: silently stepping over
//! something that failed verification would turn a security decision into a
//! one-time event nobody sees again.
//!
//! Rejections are reported per entry, so the caller decides whether one bad
//! entry stops the sync. [`Subscriber::sync`] keeps going and reports them all,
//! because stopping at the first would let a publisher block a subscriber by
//! publishing one thing it will not accept.

use std::path::{Path, PathBuf};

use aqua_rs_sdk_core::Aquafier;
use serde::{Deserialize, Serialize};

use crate::error::{RegistryError, Result};
use crate::feedhead::{self, HeadRejection, VerifiedHead};
use crate::httpclient::RegistryClient;
use crate::import::{self, ImportRejection, ImportStore, ImportedTemplate, TrustedVendor};
use crate::model::{FeedPage, RegistrationKind};
use crate::trust::{ImportPolicy, PinMode};

/// The persisted position of a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionState {
    /// Format version.
    pub version: u32,
    /// Registry base URL this cursor belongs to.
    pub registry_url: String,
    /// Publisher DID being followed.
    pub publisher_did: String,
    /// Highest feed `seq` fully processed. The next poll asks for `seq > cursor`.
    pub cursor: u64,
    /// Unix seconds of the last successful poll.
    pub last_polled_at: u64,
    /// Highest `head_seq` of a feed head verified from this publisher.
    ///
    /// `None` means none has ever been seen, which is the bootstrapping state.
    /// Once this is `Some`, a registry that stops serving a head is failing,
    /// not bootstrapping, so this field is what makes head disappearance
    /// detectable at all. Defaulted on load so cursor files written before feed
    /// heads existed still parse, and correctly start out bootstrapping.
    #[serde(default)]
    pub head_seq: Option<u64>,
    /// Merkle root of the head at `head_seq`, for equivocation detection.
    #[serde(default)]
    pub head_root: Option<String>,
}

impl SubscriptionState {
    /// A fresh subscription starting from the beginning of the feed.
    pub fn new(registry_url: &str, publisher_did: &str) -> Self {
        Self {
            version: 1,
            registry_url: registry_url.trim_end_matches('/').to_string(),
            publisher_did: publisher_did.to_string(),
            cursor: 0,
            last_polled_at: 0,
            head_seq: None,
            head_root: None,
        }
    }

    /// Load from disk, or start fresh when the file does not exist.
    ///
    /// A missing cursor file is genuinely a new subscription, so unlike the
    /// trust policy (where a missing file must never mean "allow"), defaulting
    /// is right here: the safe default for a cursor is to start at zero and
    /// re-verify everything.
    pub fn load_or_new(path: &Path, registry_url: &str, publisher_did: &str) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let state: SubscriptionState =
                    serde_json::from_str(&text).map_err(|e| RegistryError::CorruptStore {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    })?;
                if state.version != 1 {
                    return Err(RegistryError::CorruptStore {
                        path: path.display().to_string(),
                        reason: format!("unsupported cursor version {}", state.version),
                    });
                }
                // A cursor belongs to one (registry, publisher) pair. Reusing it
                // across a different pair would skip entries that were never
                // seen, so this refuses rather than guessing.
                if state.publisher_did != publisher_did {
                    return Err(RegistryError::CorruptStore {
                        path: path.display().to_string(),
                        reason: format!(
                            "cursor belongs to publisher {}, not {publisher_did}",
                            state.publisher_did
                        ),
                    });
                }
                Ok(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self::new(registry_url, publisher_did))
            }
            Err(e) => Err(RegistryError::Storage {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    /// Persist atomically.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RegistryError::Storage {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|e| RegistryError::Core(e.to_string()))?;
        write_atomically(path, format!("{text}\n").as_bytes())
    }
}

/// Why a sync stopped.
///
/// Head failures are their own variant because they are categorically
/// different from an entry that would not import. A rejected entry is one
/// template the subscriber declined; a failed head means the whole view the
/// registry just served cannot be trusted, so nothing is imported and the
/// cursor does not move.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The publisher's signed feed head did not check out.
    #[error("feed head check failed: {0}")]
    Head(#[from] HeadRejection),
    /// Transport, storage, or policy error.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

impl SyncError {
    /// Short stable label for logs and CLI output.
    pub fn code(&self) -> &'static str {
        match self {
            SyncError::Head(h) => h.code(),
            SyncError::Registry(_) => "SYNC_ERROR",
        }
    }
}

/// What the feed head said about this sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadStatus {
    /// The publisher has never signed a head, and none was ever seen before.
    ///
    /// Tolerated so a publisher can be followed before they adopt feed heads,
    /// but reported on every sync: until a head exists, withholding and
    /// reordering are undetectable and the subscriber is back to trusting the
    /// registry's word about what was published.
    Bootstrapping,
    /// A head verified and the entries on hand reproduce its root.
    Verified(VerifiedHead),
}

impl HeadStatus {
    /// The verified head, if there was one.
    pub fn verified(&self) -> Option<&VerifiedHead> {
        match self {
            HeadStatus::Verified(h) => Some(h),
            HeadStatus::Bootstrapping => None,
        }
    }

    /// True when this sync ran without a signed commitment to check against.
    pub fn is_bootstrapping(&self) -> bool {
        matches!(self, HeadStatus::Bootstrapping)
    }
}

/// One entry that did not import, and why.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Feed sequence number.
    pub seq: u64,
    /// The qualified name the entry claimed.
    pub qualified_name: String,
    /// The failed check.
    pub rejection: ImportRejection,
}

/// What one call to [`Subscriber::sync`] did.
#[derive(Debug, Default)]
pub struct SyncReport {
    /// Feed entries examined.
    pub examined: usize,
    /// Templates newly imported.
    pub imported: Vec<ImportedTemplate>,
    /// Templates already present, skipped without re-importing.
    pub already_present: usize,
    /// Entries that failed a check.
    pub rejected: Vec<Rejected>,
    /// Qualified names newly written to the pin file.
    pub newly_pinned: Vec<String>,
    /// Cursor after the sync.
    pub cursor: u64,
    /// What the publisher's signed feed head said.
    pub head: Option<HeadStatus>,
}

impl SyncReport {
    /// True when nothing was imported and nothing was rejected.
    pub fn is_empty(&self) -> bool {
        self.imported.is_empty() && self.rejected.is_empty()
    }
}

/// A subscriber: one registry, one publisher, one local store, one policy.
pub struct Subscriber {
    client: RegistryClient,
    store: ImportStore,
    policy: ImportPolicy,
    policy_path: Option<PathBuf>,
    state: SubscriptionState,
    state_path: PathBuf,
    aquafier: Aquafier,
}

impl Subscriber {
    /// Build a subscriber.
    ///
    /// `policy_path` is where newly approved pins are written back in
    /// [`PinMode::ApproveNew`]. Passing `None` makes approval in-memory only,
    /// which is useful for a dry run and wrong for anything durable.
    pub fn new(
        registry_url: &str,
        publisher_did: &str,
        store: ImportStore,
        policy: ImportPolicy,
        policy_path: Option<PathBuf>,
        state_path: PathBuf,
    ) -> Result<Self> {
        let client = RegistryClient::new(registry_url)?;
        let state = SubscriptionState::load_or_new(&state_path, registry_url, publisher_did)?;
        Ok(Self {
            client,
            store,
            policy,
            policy_path,
            state,
            state_path,
            aquafier: Aquafier::new(),
        })
    }

    /// The local template store.
    pub fn store(&self) -> &ImportStore {
        &self.store
    }

    /// The current cursor.
    pub fn cursor(&self) -> u64 {
        self.state.cursor
    }

    /// The policy in force.
    pub fn policy(&self) -> &ImportPolicy {
        &self.policy
    }

    /// Poll the feed once and import whatever passes.
    ///
    /// The vendor registration for each namespace is fetched and verified
    /// independently, from the registry's `/vendors/{name}/tree` endpoint, so
    /// the namespace-owner check is made against a DID recovered from a
    /// signature rather than against the registry's derived vendor record.
    pub async fn sync(&mut self, mode: PinMode) -> std::result::Result<SyncReport, SyncError> {
        // ---- 1. collect the publisher's whole feed, in order ---------------
        //
        // The full feed is walked from the beginning rather than from the
        // cursor, because a feed head commits to entries 1..head_seq and those
        // are usually behind the cursor. Fetching only the tail would leave
        // nothing to recompute the root over.
        //
        // The cost is one full walk per poll instead of an incremental one. For
        // a template registry that is a few hundred small entries at worst, and
        // paying it buys the ability to detect that the registry has quietly
        // changed something it already served. An incremental walk would have
        // to trust its own cached history, which is the assumption under attack.
        let all_entries = self.collect_feed().await?;

        // ---- 2. the head gates everything ----------------------------------
        let head_status = self.check_head(&all_entries).await?;

        let mut report = SyncReport {
            cursor: self.state.cursor,
            head: Some(head_status.clone()),
            ..Default::default()
        };

        // Vendor registrations are verified once per namespace per sync and
        // cached here. Re-verifying the same tree for eleven templates is pure
        // waste, and caching within a single sync cannot go stale.
        let mut vendors: std::collections::BTreeMap<String, TrustedVendor> =
            std::collections::BTreeMap::new();

        {
            for entry in all_entries.iter().filter(|e| e.seq > self.state.cursor) {
                report.examined += 1;

                // Vendor claims carry no template to import, but they do
                // establish the namespace, so they advance the cursor.
                if entry.kind != RegistrationKind::Template {
                    report.cursor = entry.seq;
                    continue;
                }

                let vendor_name = entry
                    .qualified_name
                    .split('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();

                // Resolve and verify the namespace owner.
                let vendor = match vendors.get(&vendor_name) {
                    Some(v) => v.clone(),
                    None => {
                        let tree = self
                            .client
                            .get_raw(&format!("/vendors/{vendor_name}/tree"))
                            .await?;
                        match import::verify_vendor(&self.aquafier, &tree, &self.policy).await {
                            Ok(v) => {
                                vendors.insert(vendor_name.clone(), v.clone());
                                v
                            }
                            Err(rejection) => {
                                report.rejected.push(Rejected {
                                    seq: entry.seq,
                                    qualified_name: entry.qualified_name.clone(),
                                    rejection,
                                });
                                continue;
                            }
                        }
                    }
                };

                match self
                    .import_one(entry, &vendor, mode)
                    .await
                    .map_err(SyncError::Registry)?
                {
                    Outcome::Imported(t) => {
                        if t.newly_pinned {
                            self.policy.approve(&t.qualified_name, &t.template_hash)?;
                            report.newly_pinned.push(t.qualified_name.clone());
                            if let Some(p) = &self.policy_path {
                                self.policy.save(p)?;
                            }
                        }
                        report.imported.push(t);
                        report.cursor = entry.seq;
                    }
                    Outcome::AlreadyPresent => {
                        report.already_present += 1;
                        report.cursor = entry.seq;
                    }
                    Outcome::Rejected(rejection) => {
                        report.rejected.push(Rejected {
                            seq: entry.seq,
                            qualified_name: entry.qualified_name.clone(),
                            rejection,
                        });
                        // Cursor deliberately not advanced past a rejection.
                    }
                }
            }
        }

        // Only now is it safe to remember progress: the head verified, so the
        // entries just processed are the ones the publisher signed for.
        self.state.cursor = report.cursor;
        if let Some(head) = head_status.verified() {
            self.state.head_seq = Some(head.head_seq);
            self.state.head_root = Some(head.merkle_root.clone());
        }
        self.state.last_polled_at = now_secs();
        self.state.save(&self.state_path)?;
        Ok(report)
    }

    /// Walk the publisher's whole feed from the beginning, in order.
    async fn collect_feed(&self) -> std::result::Result<Vec<crate::model::FeedEntry>, SyncError> {
        let mut all: Vec<crate::model::FeedEntry> = Vec::new();
        let mut since = 0u64;
        loop {
            let path = format!(
                "/publishers/{}/feed?since={since}",
                self.state.publisher_did
            );
            let page: FeedPage = self.client.get_json(&path).await?;
            if page.entries.is_empty() {
                break;
            }
            let highest = page.entries.iter().map(|e| e.seq).max().unwrap_or(since);
            all.extend(page.entries);
            if !page.has_more {
                break;
            }
            // Guard against a registry that reports has_more but returns
            // nothing new: without this, a buggy or hostile server could spin
            // this loop forever.
            if highest <= since {
                break;
            }
            since = highest;
        }

        // The registry controls this ordering, so it is normalised here rather
        // than trusted. Sorting means a reordered page cannot change which
        // ordinal an entry gets, which in turn means a root mismatch reports
        // the real problem (a substituted or missing entry) instead of noise.
        all.sort_by_key(|e| e.seq);
        all.dedup_by_key(|e| e.seq);
        Ok(all)
    }

    /// Fetch and check the publisher's signed feed head. Fails closed.
    async fn check_head(
        &self,
        all_entries: &[crate::model::FeedEntry],
    ) -> std::result::Result<HeadStatus, SyncError> {
        let path = format!("/publishers/{}/head", self.state.publisher_did);
        let response = self.client.get(&path).await?;

        if response.status == 404 {
            // Never seen one: the publisher has not adopted feed heads yet.
            // Seen one before: it did not stop existing on its own.
            return match self.state.head_seq {
                None => Ok(HeadStatus::Bootstrapping),
                Some(previous) => Err(HeadRejection::Disappeared { previous }.into()),
            };
        }
        let body = response.ok_body(&path)?;

        let head =
            feedhead::verify_head(&self.aquafier, &body, Some(&self.state.publisher_did)).await?;

        // Rollback and equivocation, against what this subscriber already saw.
        feedhead::check_against_previous(
            &head,
            self.state.head_seq,
            self.state.head_root.as_deref(),
        )?;

        // Freshness, against the head's own signed timestamp. Placed before
        // the entry comparison so a stale head is reported as stale rather
        // than as whatever the stale entry set happens to look like.
        feedhead::check_freshness(&head, self.policy.max_head_age_secs(), now_secs())?;

        // Withholding and reordering, against what the registry just served.
        let tips: Vec<String> = all_entries.iter().map(|e| e.tree_tip.clone()).collect();
        feedhead::check_against_entries(&head, &tips)?;

        Ok(HeadStatus::Verified(head))
    }

    async fn import_one(
        &self,
        entry: &crate::model::FeedEntry,
        vendor: &TrustedVendor,
        mode: PinMode,
    ) -> Result<Outcome> {
        let template_hash = match &entry.payload {
            crate::model::RegistrationPayload::Template(t) => t.template_hash.clone(),
            _ => {
                return Ok(Outcome::Rejected(ImportRejection::WrongKind {
                    expected: "template",
                    got: entry.kind.as_str().to_string(),
                }))
            }
        };

        if self.store.contains(&template_hash) {
            return Ok(Outcome::AlreadyPresent);
        }

        // Both fetched verbatim: the registration because its signature covers
        // exact bytes, the definition because its hash does.
        let registration = self
            .client
            .get_raw(&format!("/templates/{template_hash}"))
            .await?;
        let definition = match self
            .client
            .get_raw(&format!("/definitions/{template_hash}"))
            .await
        {
            Ok(d) => d,
            Err(e) => {
                // A registration with no body to go with it is not a security
                // failure, it is an incomplete publication. Report it as a
                // rejection so the cursor holds and a later poll picks it up.
                return Ok(Outcome::Rejected(ImportRejection::MalformedDefinition {
                    qualified_name: entry.qualified_name.clone(),
                    reason: format!("no definition body available: {e}"),
                }));
            }
        };

        match import::verify_template(
            &self.aquafier,
            vendor,
            &registration,
            &definition,
            &self.policy,
            mode,
        )
        .await
        {
            Ok(accepted) => {
                self.store.insert(&accepted)?;
                Ok(Outcome::Imported(accepted.template))
            }
            Err(rejection) => Ok(Outcome::Rejected(rejection)),
        }
    }
}

enum Outcome {
    Imported(ImportedTemplate),
    AlreadyPresent,
    Rejected(ImportRejection),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_refuses_to_be_reused_across_publishers() {
        // Reusing a cursor for a different publisher would skip every entry
        // below it that this publisher never had examined.
        let dir = std::env::temp_dir().join(format!("atr-sub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cursor.json");

        let mut state = SubscriptionState::new("http://x", "did:key:zAlice");
        state.cursor = 7;
        state.save(&path).unwrap();

        assert!(SubscriptionState::load_or_new(&path, "http://x", "did:key:zBob").is_err());
        let same = SubscriptionState::load_or_new(&path, "http://x", "did:key:zAlice").unwrap();
        assert_eq!(same.cursor, 7);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_cursor_file_starts_at_zero() {
        // Unlike the trust policy, defaulting is correct for a cursor: starting
        // over re-verifies everything, it does not skip checks.
        let path = std::env::temp_dir().join(format!("atr-nope-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let state = SubscriptionState::load_or_new(&path, "http://x", "did:key:zAlice").unwrap();
        assert_eq!(state.cursor, 0);
    }
}
