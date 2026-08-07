//! Comparing a publisher's feed heads across several registries.
//!
//! # The gap this narrows
//!
//! A signed feed head stops a registry inventing history, but a subscriber
//! checks it against its own memory, so it can only catch a registry going
//! backwards relative to what that subscriber has already seen. On first
//! contact there is nothing to compare against: a registry can serve a genuine
//! but months-old head, and a fresh subscriber has no way to know.
//!
//! Two registries serving the same publisher do have something to compare. If
//! they disagree about the root at a height, one of them is serving something
//! the publisher did not sign at that height, or the publisher equivocated.
//! Either way the answer is not to pick a side, it is to stop.
//!
//! This is corroboration, not consensus. It does not vote, it does not pick a
//! majority, and it does not decide which mirror is honest. It reports what
//! disagrees and leaves the decision with the operator, because a majority of
//! mirrors run by one party is not evidence of anything.
//!
//! # What is and is not a problem
//!
//! **Equivocation** (two heads at one height with different roots) is always a
//! problem. Every head is signed by the publisher, so two conflicting signed
//! heads at one height means either a compromised key or a registry serving a
//! forgery that somehow verified, and neither has an innocent reading.
//!
//! **Lag** (one mirror behind another) is normal. Mirrors sync on their own
//! schedule and a publisher does not push everywhere at once. It is reported
//! because a mirror that is permanently far behind is worth knowing about, but
//! it is not by itself evidence of anything.
//!
//! **Unreachable** is not evidence either. It is reported so a caller can tell
//! "two mirrors agreed" from "one mirror answered and the other timed out",
//! which are very different levels of assurance.
//!
//! # What this still does not fix
//!
//! Mirrors that collude, or that are all fed by the same upstream, agree with
//! each other perfectly while all being stale. Corroboration is only worth what
//! the independence of the mirrors is worth, and nothing here can measure that.

use aqua_rs_sdk_core::Aquafier;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::feedhead::{self, VerifiedHead};
use crate::httpclient::RegistryClient;

/// What one registry said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorStatus {
    /// Base URL that was asked.
    pub url: String,
    /// The head it served, if it served a valid one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<VerifiedHead>,
    /// Why there is no head: unreachable, none published, or it did not verify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl MirrorStatus {
    /// The height this mirror is at, or 0 when it has no usable head.
    pub fn height(&self) -> u64 {
        self.head.as_ref().map(|h| h.head_seq).unwrap_or(0)
    }
}

/// Two mirrors disagreeing about the root at one height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    /// The height at which they disagree.
    pub head_seq: u64,
    /// One mirror.
    pub url_a: String,
    /// What it says the root is.
    pub root_a: String,
    /// The other mirror.
    pub url_b: String,
    /// What it says the root is.
    pub root_b: String,
}

/// A mirror behind the furthest one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lag {
    /// The mirror that is behind.
    pub url: String,
    /// Its height.
    pub head_seq: u64,
    /// How many entries behind the furthest mirror it is.
    pub behind: u64,
}

/// The result of comparing a publisher across mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorroborationReport {
    /// The publisher that was compared.
    pub publisher_did: String,
    /// One entry per mirror asked, in the order given.
    pub mirrors: Vec<MirrorStatus>,
    /// The highest height any mirror served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_head_seq: Option<u64>,
    /// Mirrors disagreeing about a root at the same height.
    pub equivocations: Vec<Equivocation>,
    /// Mirrors behind the furthest one.
    pub lagging: Vec<Lag>,
    /// Mirrors that could not be asked or had nothing usable.
    pub unreachable: Vec<String>,
}

impl CorroborationReport {
    /// True when no two mirrors contradict each other.
    ///
    /// Lag and unreachability do not make a report inconsistent. Only a genuine
    /// disagreement about a signed root does.
    pub fn is_consistent(&self) -> bool {
        self.equivocations.is_empty()
    }

    /// How many mirrors served a head that verified.
    pub fn corroborating(&self) -> usize {
        self.mirrors.iter().filter(|m| m.head.is_some()).count()
    }

    /// A human-readable summary line.
    pub fn summary(&self) -> String {
        let agreeing = self.corroborating();
        let total = self.mirrors.len();
        if !self.equivocations.is_empty() {
            return format!(
                "INCONSISTENT: {} equivocation(s) across {total} mirror(s)",
                self.equivocations.len()
            );
        }
        if agreeing == 0 {
            return format!("no usable head from any of {total} mirror(s)");
        }
        let mut s = format!("{agreeing} of {total} mirror(s) agree");
        if let Some(best) = self.best_head_seq {
            s.push_str(&format!(", best height {best}"));
        }
        if !self.lagging.is_empty() {
            s.push_str(&format!(", {} lagging", self.lagging.len()));
        }
        s
    }
}

/// Ask every mirror for a publisher's head and compare them.
///
/// Every head is verified in full ([`feedhead::verify_head`] with the expected
/// publisher), so a mirror serving a forged or misattributed head is recorded
/// as an error rather than compared as if it were real. Comparing unverified
/// roots would turn one hostile mirror into an equivocation report against an
/// honest one.
pub async fn corroborate(publisher_did: &str, urls: &[String]) -> Result<CorroborationReport> {
    let aquafier = Aquafier::new();
    let mut mirrors: Vec<MirrorStatus> = Vec::new();

    for url in urls {
        mirrors.push(fetch_head(&aquafier, url, publisher_did).await);
    }

    let best_head_seq = mirrors
        .iter()
        .filter_map(|m| m.head.as_ref())
        .map(|h| h.head_seq)
        .max();

    let unreachable: Vec<String> = mirrors
        .iter()
        .filter(|m| m.head.is_none())
        .map(|m| m.url.clone())
        .collect();

    let lagging: Vec<Lag> = match best_head_seq {
        Some(best) => mirrors
            .iter()
            .filter_map(|m| m.head.as_ref().map(|h| (m.url.clone(), h.head_seq)))
            .filter(|(_, seq)| *seq < best)
            .map(|(url, head_seq)| Lag {
                url,
                head_seq,
                behind: best - head_seq,
            })
            .collect(),
        None => Vec::new(),
    };

    let mut equivocations = compare_at_equal_heights(&mirrors);
    equivocations.extend(compare_at_common_height(&aquafier, publisher_did, &mirrors).await);
    equivocations
        .sort_by(|a, b| (a.head_seq, &a.url_a, &a.url_b).cmp(&(b.head_seq, &b.url_a, &b.url_b)));
    equivocations.dedup();

    Ok(CorroborationReport {
        publisher_did: publisher_did.to_string(),
        mirrors,
        best_head_seq,
        equivocations,
        lagging,
        unreachable,
    })
}

async fn fetch_head(aquafier: &Aquafier, url: &str, publisher_did: &str) -> MirrorStatus {
    let client = match RegistryClient::new(url) {
        Ok(c) => c,
        Err(e) => {
            return MirrorStatus {
                url: url.to_string(),
                head: None,
                error: Some(e.to_string()),
            }
        }
    };

    let path = format!("/publishers/{publisher_did}/head");
    let body = match client.get(&path).await {
        Ok(r) if r.status == 404 => {
            return MirrorStatus {
                url: url.to_string(),
                head: None,
                error: Some("no feed head published here".to_string()),
            }
        }
        Ok(r) => match r.ok_body(&path) {
            Ok(b) => b,
            Err(e) => {
                return MirrorStatus {
                    url: url.to_string(),
                    head: None,
                    error: Some(e.to_string()),
                }
            }
        },
        Err(e) => {
            return MirrorStatus {
                url: url.to_string(),
                head: None,
                error: Some(e.to_string()),
            }
        }
    };

    match feedhead::verify_head(aquafier, &body, Some(publisher_did)).await {
        Ok(head) => MirrorStatus {
            url: url.to_string(),
            head: Some(head),
            error: None,
        },
        Err(e) => MirrorStatus {
            url: url.to_string(),
            head: None,
            error: Some(format!("head did not verify: {e}")),
        },
    }
}

/// Mirrors at the same height must agree about the root.
fn compare_at_equal_heights(mirrors: &[MirrorStatus]) -> Vec<Equivocation> {
    let mut out = Vec::new();
    for (i, a) in mirrors.iter().enumerate() {
        let Some(ha) = a.head.as_ref() else { continue };
        for b in mirrors.iter().skip(i + 1) {
            let Some(hb) = b.head.as_ref() else { continue };
            if ha.head_seq == hb.head_seq && !ha.merkle_root.eq_ignore_ascii_case(&hb.merkle_root) {
                out.push(Equivocation {
                    head_seq: ha.head_seq,
                    url_a: a.url.clone(),
                    root_a: ha.merkle_root.clone(),
                    url_b: b.url.clone(),
                    root_b: hb.merkle_root.clone(),
                });
            }
        }
    }
    out
}

/// Mirrors at different heights are compared at the lowest height they share.
///
/// A mirror that forked from the real feed early will still be at some height,
/// and comparing only latest-against-latest would miss it whenever the two
/// happen to be at different heights. Asking each for its head at the common
/// height turns "these are just at different points" into a real comparison.
async fn compare_at_common_height(
    aquafier: &Aquafier,
    publisher_did: &str,
    mirrors: &[MirrorStatus],
) -> Vec<Equivocation> {
    let heights: Vec<u64> = mirrors
        .iter()
        .filter_map(|m| m.head.as_ref())
        .map(|h| h.head_seq)
        .collect();
    let (Some(min), Some(max)) = (heights.iter().min().copied(), heights.iter().max().copied())
    else {
        return Vec::new();
    };
    if min == max {
        // Every mirror is at the same height; compare_at_equal_heights covered it.
        return Vec::new();
    }

    let mut roots: Vec<(String, String)> = Vec::new();
    for m in mirrors.iter().filter(|m| m.head.is_some()) {
        let Ok(client) = RegistryClient::new(&m.url) else {
            continue;
        };
        let path = format!("/publishers/{publisher_did}/heads/{min}");
        let Ok(body) = client.get_raw(&path).await else {
            // A mirror that cannot produce the common height is not evidence of
            // equivocation. It may simply not retain history.
            continue;
        };
        if let Ok(head) = feedhead::verify_head(aquafier, &body, Some(publisher_did)).await {
            if head.head_seq == min {
                roots.push((m.url.clone(), head.merkle_root));
            }
        }
    }

    let mut out = Vec::new();
    for (i, (url_a, root_a)) in roots.iter().enumerate() {
        for (url_b, root_b) in roots.iter().skip(i + 1) {
            if !root_a.eq_ignore_ascii_case(root_b) {
                out.push(Equivocation {
                    head_seq: min,
                    url_a: url_a.clone(),
                    root_a: root_a.clone(),
                    url_b: url_b.clone(),
                    root_b: root_b.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seq: u64, root: &str) -> VerifiedHead {
        VerifiedHead {
            publisher_did: "did:key:z6Mk".into(),
            head_seq: seq,
            merkle_root: root.into(),
            leaf_version: 1,
            covered_at: 0,
            tree_tip: "0x00".into(),
        }
    }

    fn mirror(url: &str, h: Option<VerifiedHead>) -> MirrorStatus {
        MirrorStatus {
            url: url.into(),
            head: h,
            error: None,
        }
    }

    #[test]
    fn equal_heights_with_equal_roots_agree() {
        let m = vec![
            mirror("http://a", Some(head(5, "0xaa"))),
            mirror("http://b", Some(head(5, "0xaa"))),
        ];
        assert!(compare_at_equal_heights(&m).is_empty());
    }

    #[test]
    fn equal_heights_with_different_roots_equivocate() {
        // The whole point: two signed heads at one height cannot both be right.
        let m = vec![
            mirror("http://a", Some(head(5, "0xaa"))),
            mirror("http://b", Some(head(5, "0xbb"))),
        ];
        let e = compare_at_equal_heights(&m);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].head_seq, 5);
        assert_eq!(e[0].root_a, "0xaa");
        assert_eq!(e[0].root_b, "0xbb");
    }

    #[test]
    fn root_comparison_is_case_insensitive() {
        // Hex case must not read as a disagreement.
        let m = vec![
            mirror("http://a", Some(head(5, "0xAA"))),
            mirror("http://b", Some(head(5, "0xaa"))),
        ];
        assert!(compare_at_equal_heights(&m).is_empty());
    }

    #[test]
    fn different_heights_are_not_equivocation_by_themselves() {
        // Lag is normal. Only a disagreement at a shared height is a problem.
        let m = vec![
            mirror("http://a", Some(head(5, "0xaa"))),
            mirror("http://b", Some(head(3, "0xbb"))),
        ];
        assert!(compare_at_equal_heights(&m).is_empty());
    }

    #[test]
    fn a_report_with_only_lag_is_still_consistent() {
        let r = CorroborationReport {
            publisher_did: "did:key:z6Mk".into(),
            mirrors: vec![
                mirror("http://a", Some(head(5, "0xaa"))),
                mirror("http://b", Some(head(3, "0xbb"))),
            ],
            best_head_seq: Some(5),
            equivocations: vec![],
            lagging: vec![Lag {
                url: "http://b".into(),
                head_seq: 3,
                behind: 2,
            }],
            unreachable: vec![],
        };
        assert!(r.is_consistent());
        assert_eq!(r.corroborating(), 2);
        assert!(r.summary().contains("lagging"));
    }

    #[test]
    fn a_report_with_equivocation_is_not_consistent() {
        let r = CorroborationReport {
            publisher_did: "did:key:z6Mk".into(),
            mirrors: vec![],
            best_head_seq: Some(5),
            equivocations: vec![Equivocation {
                head_seq: 5,
                url_a: "http://a".into(),
                root_a: "0xaa".into(),
                url_b: "http://b".into(),
                root_b: "0xbb".into(),
            }],
            lagging: vec![],
            unreachable: vec![],
        };
        assert!(!r.is_consistent());
        assert!(r.summary().starts_with("INCONSISTENT"));
    }

    #[test]
    fn an_unreachable_mirror_does_not_corroborate_or_contradict() {
        let m = vec![
            mirror("http://a", Some(head(5, "0xaa"))),
            MirrorStatus {
                url: "http://b".into(),
                head: None,
                error: Some("connection refused".into()),
            },
        ];
        assert!(compare_at_equal_heights(&m).is_empty());
        assert_eq!(m[1].height(), 0);
    }
}
