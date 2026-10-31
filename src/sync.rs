use std::collections::BTreeMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::WotError;
use crate::identity::{canonicalize_did, Did};
use crate::register::TrustRegister;
use crate::sd_jwt::parse_and_verify_sd_jwt;

/// Format of a synchronization gossip package containing SD-JWT trust lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WotSyncPackage {
    #[serde(alias = "version")]
    pub format_version: u8,
    pub lists: Vec<String>,
}

/// An entry in a synchronization receipt confirming prepared transmission of a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReceiptEntry {
    pub issuer_did: Did,
    pub version: u64,
    pub disclosure_fingerprint: u64,
}

/// Receipt returned by `prepare_sync_package` to be committed to `sent_log` after send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReceipt {
    pub recipient_did: Option<Did>,
    pub entries: Vec<SyncReceiptEntry>,
}

/// Statistics detailing the outcome of importing a synchronization package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportStats {
    /// Newly imported lists that were not present in raw_list_store.
    #[serde(alias = "accepted_new")]
    pub imported: usize,
    /// Existing lists updated to a strictly newer version.
    pub updated: usize,
    /// Newly merged disclosures for an existing list version.
    #[serde(alias = "merged_disclosures")]
    pub merged: usize,
    /// Lists skipped because version is already stored and unchanged or older.
    #[serde(alias = "skipped_stale_or_unchanged")]
    pub skipped_unchanged: usize,
    /// Lists rejected by topological spam filter (unreachable).
    #[serde(alias = "rejected_unreachable")]
    pub rejected_spam: usize,
    /// Lists rejected due to signature or crypto validation failure.
    #[serde(alias = "rejected_invalid")]
    pub rejected_crypto: usize,
    /// Lists rejected due to timestamps too far in future.
    pub rejected_timestamp: usize,
    /// Unreachable lists pruned during garbage collection.
    pub pruned_orphans: usize,
}

impl ImportStats {
    /// Backward-compatible alias for newly imported lists.
    pub fn accepted_new(&self) -> usize {
        self.imported
    }

    /// Total count of accepted lists (both new and updated).
    pub fn accepted_total(&self) -> usize {
        self.imported + self.updated
    }

    /// Backward-compatible alias for merged disclosures.
    pub fn merged_disclosures(&self) -> usize {
        self.merged
    }

    /// Backward-compatible alias for skipped lists.
    pub fn skipped_stale_or_unchanged(&self) -> usize {
        self.skipped_unchanged
    }

    /// Backward-compatible alias for rejected unreachable spam.
    pub fn rejected_unreachable(&self) -> usize {
        self.rejected_spam
    }

    /// Backward-compatible alias for rejected invalid lists (crypto + timestamp).
    pub fn rejected_invalid(&self) -> usize {
        self.rejected_crypto + self.rejected_timestamp
    }
}

/// Helper to quickly inspect the unverified issuer DID from an SD-JWT payload.
pub fn peek_unverified_issuer(raw_sd_jwt: &str) -> Option<Did> {
    let jws = raw_sd_jwt.split('~').next()?;
    let payload_b64 = jws.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let val: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let iss = val.get("iss")?.as_str()?;
    canonicalize_did(iss).ok()
}

impl TrustRegister {
    /// Prepares a synchronization package prioritized by hop distance without modifying `sent_log`.
    ///
    /// - Includes own signed list (d = 0, target_dist = 1) and reachable third-party lists.
    /// - Redacts disclosures whose `contact_max_hops` is smaller than `d_ziel`.
    /// - Drops lists where `list.max_hops < d_ziel`.
    /// - Filters out unchanged versions using `sent_log` unless `force_full` is true.
    /// - Respects `max_bytes` package size limit if provided.
    pub fn prepare_sync_package(
        &self,
        recipient_did: Option<&str>,
        max_bytes: Option<usize>,
        force_full: bool,
    ) -> Result<(WotSyncPackage, SyncReceipt), WotError> {
        let canonical_recipient = recipient_did.map(canonicalize_did).transpose()?;

        let graph = self.get_or_build_graph_cache();
        let distances = graph.shortest_distances_from_self();

        struct CandidateList {
            dist: u8,
            issuer: Did,
            version: u64,
            wire_string: String,
            fingerprint: u64,
        }

        let mut candidates: Vec<CandidateList> = Vec::new();

        // 1. Own signed list (dist = 0, target_dist = 1)
        if let Some(own_list) = &self.own_signed_list {
            let target_dist = 1;
            if own_list.max_hops >= target_dist
                && let Some(wire) = own_list.to_redacted_wire_string(target_dist)
            {
                let fp = own_list.disclosure_fingerprint(target_dist);
                let already_sent = !force_full
                    && canonical_recipient
                        .as_ref()
                        .and_then(|rcpt| self.sent_log.get(rcpt))
                        .and_then(|log| log.get(&self.self_did))
                        .is_some_and(|sent| {
                            sent.version > own_list.v
                                || (sent.version == own_list.v && sent.disclosure_fingerprint == fp)
                        });

                if !already_sent {
                    candidates.push(CandidateList {
                        dist: 0,
                        issuer: self.self_did.clone(),
                        version: own_list.v,
                        wire_string: wire,
                        fingerprint: fp,
                    });
                }
            }
        }

        // 2. Reachable third-party lists
        let allow_third_party = match &canonical_recipient {
            Some(rcpt) => self.own_contacts.get(rcpt).is_some_and(|e| e.level >= 1),
            None => true,
        };

        if allow_third_party {
            for (iss, stored) in &self.raw_list_store {
                if iss == &self.self_did {
                    continue;
                }

                let iss_node_id = match graph.did_to_id.get(iss) {
                    Some(&id) => id,
                    None => continue,
                };

                let dist = match distances.get(&iss_node_id) {
                    Some(&d) => d,
                    None => continue,
                };

                let target_dist = dist.saturating_add(1);
                if stored.max_hops < target_dist {
                    continue;
                }

                if let Some(wire) = stored.to_redacted_wire_string(target_dist) {
                    let fp = stored.disclosure_fingerprint(target_dist);
                    let already_sent = !force_full
                        && canonical_recipient
                            .as_ref()
                            .and_then(|rcpt| self.sent_log.get(rcpt))
                            .and_then(|log| log.get(iss))
                            .is_some_and(|sent| {
                                sent.version > stored.v
                                    || (sent.version == stored.v && sent.disclosure_fingerprint == fp)
                            });

                    if !already_sent {
                        candidates.push(CandidateList {
                            dist,
                            issuer: iss.clone(),
                            version: stored.v,
                            wire_string: wire,
                            fingerprint: fp,
                        });
                    }
                }
            }
        }

        drop(graph);

        // Sort candidates ascending by (dist, issuer)
        candidates.sort_by(|a, b| a.dist.cmp(&b.dist).then_with(|| a.issuer.cmp(&b.issuer)));

        // Assemble package respecting max_bytes
        let mut included_lists = Vec::new();
        let mut receipt_entries = Vec::new();

        for cand in candidates {
            let mut test_lists = included_lists.clone();
            test_lists.push(cand.wire_string.clone());

            let test_pkg = WotSyncPackage {
                format_version: 1,
                lists: test_lists,
            };

            if let Some(limit) = max_bytes {
                let encoded_len = match serde_json::to_vec(&test_pkg) {
                    Ok(bytes) => bytes.len(),
                    Err(_) => continue,
                };
                if encoded_len > limit {
                    // Stop assembling package if size limit is reached
                    break;
                }
            }

            included_lists.push(cand.wire_string);
            receipt_entries.push(SyncReceiptEntry {
                issuer_did: cand.issuer,
                version: cand.version,
                disclosure_fingerprint: cand.fingerprint,
            });
        }

        let package = WotSyncPackage {
            format_version: 1,
            lists: included_lists,
        };

        let receipt = SyncReceipt {
            recipient_did: canonical_recipient,
            entries: receipt_entries,
        };

        Ok((package, receipt))
    }

    /// Commits a synchronization receipt to `sent_log` after successful delivery.
    pub fn commit_sync_receipt(&mut self, receipt: SyncReceipt, now_secs: u64) {
        if let Some(rcpt) = receipt.recipient_did {
            let log = self.sent_log.entry(rcpt).or_default();
            for entry in receipt.entries {
                log.insert(
                    entry.issuer_did,
                    crate::register::SentRecord {
                        version: entry.version,
                        disclosure_fingerprint: entry.disclosure_fingerprint,
                        sent_at: now_secs,
                    },
                );
            }
        }
    }

    /// Imports a synchronization package using multi-pass topological reachability filtering.
    pub fn import_sync_package(
        &mut self,
        package: &WotSyncPackage,
        direct_sender_did: Option<&str>,
        now_secs: u64,
    ) -> Result<ImportStats, WotError> {
        if package.format_version != 1 {
            return Err(WotError::MalformedSdJwt(
                "Unsupported package format version".to_string(),
            ));
        }

        if package.lists.len() > 512 {
            return Err(WotError::LimitExceeded(
                "Too many lists in sync package (max 512)".to_string(),
            ));
        }

        // Snapshot current effective hops to detect reciprocity changes
        let prev_effective_hops: BTreeMap<Did, Option<u8>> = self
            .own_contacts
            .keys()
            .map(|k| (k.clone(), self.effective_hops_for_contact(k)))
            .collect();

        let direct_sender_canonical = direct_sender_did.map(canonicalize_did).transpose()?;

        let mut remaining: Vec<&str> = package.lists.iter().map(|s| s.as_str()).collect();
        let mut stats = ImportStats::default();

        loop {
            let mut progress = false;

            // 1. Admission check phase using graph cache
            let (admitted, next_remaining) = {
                let graph = self.get_or_build_graph_cache();
                let distances = graph.shortest_distances_from_self();
                let mut adm = Vec::new();
                let mut rem = Vec::new();

                for raw in remaining {
                    let candidate_iss = match peek_unverified_issuer(raw) {
                        Some(iss) => iss,
                        None => {
                            stats.rejected_crypto += 1;
                            continue;
                        }
                    };

                    if candidate_iss == self.self_did {
                        // Ignore own list received from peers
                        continue;
                    }

                    // Admission check:
                    // a) Direct handshake peer (before set_contact_trust)
                    let is_direct_peer = direct_sender_canonical.as_deref() == Some(&candidate_iss);
                    // b) In direct own_contacts (even level 0)
                    let is_direct_contact = self.own_contacts.contains_key(&candidate_iss);
                    // c) Reachable in graph with level >= 1 within policy.max_import_depth
                    let is_reachable = graph
                        .did_to_id
                        .get(&candidate_iss)
                        .and_then(|id| distances.get(id))
                        .map(|&d| d < self.policy.max_import_depth)
                        .unwrap_or(false);

                    if is_direct_peer || is_direct_contact || is_reachable {
                        adm.push(raw);
                    } else {
                        rem.push(raw);
                    }
                }
                (adm, rem)
            };

            // 2. Cryptographic verification & storage phase (graph cache is released)
            for raw in admitted {
                match parse_and_verify_sd_jwt(raw, now_secs) {
                    Err(WotError::FutureTimestamp { .. }) => {
                        stats.rejected_timestamp += 1;
                    }
                    Err(_) => {
                        stats.rejected_crypto += 1;
                    }
                    Ok((iss, new_stored)) => {
                        if let Some(existing) = self.raw_list_store.get_mut(&iss) {
                            if existing.v == new_stored.v && existing.jws_compact != new_stored.jws_compact {
                                // Conflicting JWS bodies for identical version -> Equivocation detected!
                                stats.rejected_crypto += 1;
                            } else if new_stored.v > existing.v {
                                *existing = new_stored;
                                stats.updated += 1;
                                progress = true;
                            } else if new_stored.v == existing.v {
                                // Same JWS body: union-merge disclosures
                                let mut merged = 0;
                                for (digest, record) in new_stored.disclosures {
                                    if let std::collections::btree_map::Entry::Vacant(e) = existing.disclosures.entry(digest) {
                                        e.insert(record);
                                        merged += 1;
                                    }
                                }
                                if merged > 0 {
                                    stats.merged += merged;
                                    progress = true;
                                } else {
                                    stats.skipped_unchanged += 1;
                                }
                            } else {
                                // Stale version
                                stats.skipped_unchanged += 1;
                            }
                        } else {
                            // New list accepted
                            self.raw_list_store.insert(iss, new_stored);
                            stats.imported += 1;
                            progress = true;
                        }
                    }
                }
            }

            if progress {
                self.invalidate_graph_cache();
            }

            remaining = next_remaining;
            if !progress || remaining.is_empty() {
                break;
            }
        }

        // Remaining lists are disconnected islands or too deep
        stats.rejected_spam += remaining.len();

        // Prune any lists that might have been orphaned
        stats.pruned_orphans = self.prune_unreachable_lists_preserving(direct_sender_canonical.as_deref());

        // Check if effective hops changed for any direct contact
        for (did, old_eff) in prev_effective_hops {
            let new_eff = self.effective_hops_for_contact(&did);
            if new_eff != old_eff {
                self.own_list_dirty = true;
            }
        }

        self.invalidate_graph_cache();
        Ok(stats)
    }
}
