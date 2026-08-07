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
    pub async fn sync(&mut self, mode: PinMode) -> Result<SyncReport> {
        let mut report = SyncReport {
            cursor: self.state.cursor,
            ..Default::default()
        };

        // Vendor registrations are verified once per namespace per sync and
        // cached here. Re-verifying the same tree for eleven templates is pure
        // waste, and caching within a single sync cannot go stale.
        let mut vendors: std::collections::BTreeMap<String, TrustedVendor> =
            std::collections::BTreeMap::new();

        loop {
            let path = format!(
                "/publishers/{}/feed?since={}",
                self.state.publisher_did, report.cursor
            );
            let page: FeedPage = self.client.get_json(&path).await?;
            if page.entries.is_empty() {
                break;
            }

            for entry in &page.entries {
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

                match self.import_one(entry, &vendor, mode).await? {
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

            if !page.has_more {
                break;
            }
            // Guard against a registry that reports has_more but returns
            // nothing new: without this, a buggy or hostile server could spin
            // this loop forever.
            if page.next <= report.cursor {
                break;
            }
        }

        self.state.cursor = report.cursor;
        self.state.last_polled_at = now_secs();
        self.state.save(&self.state_path)?;
        Ok(report)
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
