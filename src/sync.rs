use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::WotError;
use crate::identity::{Did, canonicalize_did};
use crate::register::TrustRegister;
use crate::sd_jwt::parse_and_verify_sd_jwt;

/// Format of a synchronization gossip package containing SD-JWT trust lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotSyncPackage {
    pub format_version: u8,
    pub lists: Vec<String>,
}

/// An entry in a synchronization receipt confirming prepared transmission of a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReceiptEntry {
    pub issuer_did: Did,
    pub version: u64,
    pub disclosure_fingerprint: u64,
}

/// Receipt returned by `prepare_sync_package` to be committed to `sent_log` after send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReceipt {
    pub recipient_did: Option<Did>,
    pub entries: Vec<SyncReceiptEntry>,
}

/// A prepared subpackage tailored for a specific reader distance class before encryption (ADR-05).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropClassSubpackage {
    /// Reader distance class in 1..=3 (1 = direct level>=1 contacts, 2 = hop-2, 3 = hop-3).
    pub distance_class: u8,
    /// Canonical DIDs of readers belonging to this distance class.
    pub reader_dids: Vec<Did>,
    /// Redacted WoT sync package specifically tailored for `distance_class` BEFORE encryption (ADR-05).
    pub package: WotSyncPackage,
}

/// Receipt confirming prepared transmission of a distance class subpackage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropClassReceipt {
    pub distance_class: u8,
    pub readers_fingerprint: u64,
    pub entries: Vec<SyncReceiptEntry>,
}

/// Receipt returned by `prepare_drop_sync_subpackages` to be committed to `drop_sent_log`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropSyncReceipt {
    pub transport_id: String,
    pub readers_fingerprint: u64,
    pub classes: Vec<DropClassReceipt>,
}

/// Transport-bound record of a drop sync upload committed to `drop_sent_log`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropSentRecord {
    pub readers_fingerprint: u64,
    pub classes: Vec<DropClassReceipt>,
    pub committed_at: u64,
}

/// Statistics detailing the outcome of importing a synchronization package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportStats {
    /// Newly imported lists that were not present in raw_list_store.
    pub imported: usize,
    /// Existing lists updated to a strictly newer version.
    pub updated: usize,
    /// Newly merged disclosures for an existing list version.
    pub merged: usize,
    /// Lists skipped because version is already stored and unchanged or older.
    pub skipped_unchanged: usize,
    /// Lists rejected by topological spam filter (unreachable).
    pub rejected_spam: usize,
    /// Lists rejected due to signature or crypto validation failure.
    pub rejected_crypto: usize,
    /// Lists rejected due to timestamps too far in future.
    pub rejected_timestamp: usize,
    /// Unreachable lists pruned during garbage collection.
    pub pruned_orphans: usize,
}

impl ImportStats {
    /// Total count of accepted lists (both new and updated).
    pub fn accepted_total(&self) -> usize {
        self.imported + self.updated
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

/// Computes a deterministic 64-bit truncated SHA-256 fingerprint over sorted (canonical_did, distance_class) pairs.
pub fn compute_readers_fingerprint(classified_readers: &[(Did, u8)]) -> u64 {
    if classified_readers.is_empty() {
        return 0;
    }
    let mut sorted: Vec<(&Did, u8)> = classified_readers.iter().map(|(d, c)| (d, *c)).collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    for (did, class) in sorted {
        hasher.update(did.as_bytes());
        hasher.update(b":");
        hasher.update([class]);
        hasher.update(b"\n");
    }
    let hash = hasher.finalize();
    u64::from_be_bytes(hash[0..8].try_into().expect("Slice of 8 bytes"))
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
                if stored.max_hops.min(3) < target_dist {
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
                                    || (sent.version == stored.v
                                        && sent.disclosure_fingerprint == fp)
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

        // Sort candidates ascending by dist, then descending by version (newest first), then issuer
        candidates.sort_by(|a, b| {
            a.dist
                .cmp(&b.dist)
                .then_with(|| b.version.cmp(&a.version))
                .then_with(|| a.issuer.cmp(&b.issuer))
        });

        // Assemble package respecting max_bytes with O(N) byte tracking
        let mut included_lists = Vec::new();
        let mut receipt_entries = Vec::new();
        // Base framing: {"format_version":1,"lists":[]} is 31 bytes
        let mut current_bytes = 31usize;

        for cand in candidates {
            let added_bytes = if included_lists.is_empty() {
                cand.wire_string.len() + 2
            } else {
                cand.wire_string.len() + 3
            };

            if let Some(limit) = max_bytes
                && current_bytes.saturating_add(added_bytes) > limit
            {
                // Skip this candidate and continue trying subsequent smaller candidates
                continue;
            }

            current_bytes = current_bytes.saturating_add(added_bytes);
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

    /// Computes the local user's authorized `wot` readers according to `policy.own_list_max_hops`
    /// (capped at `1..=3`) and trust level >= 1.
    ///
    /// - Direct contacts in `own_contacts` with `entry.level >= 1` have distance class `1`.
    /// - If `max_hops >= 2`, reachable graph nodes (over `level >= 1` edges via `shortest_distances_from_self()`)
    ///   at shortest distance `d` where `2 <= d <= max_hops.min(3)` get distance class `d` (`2` or `3`),
    ///   excluding `self_did`.
    /// - Direct contacts with `level == 0` are strictly excluded from reading WoT lists.
    /// - Sorted deterministically by `(distance_class, did)`.
    pub fn authorized_drop_readers(&self) -> Vec<(Did, u8)> {
        let max_hops = self.policy.own_list_max_hops.clamp(1, 3);
        let graph = self.get_or_build_graph_cache();
        let distances = graph.shortest_distances_from_self();

        let mut readers = Vec::new();
        for (did, &id) in &graph.did_to_id {
            if did == &self.self_did {
                continue;
            }
            if self.own_contacts.get(did).is_some_and(|e| e.level == 0) {
                continue;
            }
            if let Some(&dist) = distances.get(&id)
                && dist >= 1
                && dist <= max_hops
            {
                readers.push((did.clone(), dist));
            }
        }
        readers.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        readers
    }

    /// Prepares transport-bound distance-class subpackages for multi-recipient drop slots.
    ///
    /// - Uses `custom_readers` (canonicalizing DIDs, filtering `distance_class` in `1..=3`,
    ///   deduplicating keeping minimum distance class per DID) if `Some`, otherwise `self.authorized_drop_readers()`.
    /// - Groups readers into at most 3 classes (`c = 1`, `c = 2`, `c = 3` — omitting empty classes).
    /// - For each non-empty class `c`:
    ///   - Builds redacted `WotSyncPackage` + `Vec<SyncReceiptEntry>` before encryption (ADR-05):
    ///     - Own signed list (`dist = 0`): `target_dist = c`. Included if `own_list.max_hops >= target_dist`
    ///       and `to_redacted_wire_string(target_dist)` is `Some`.
    ///     - Reachable third-party lists (`dist >= 1` in `shortest_distances_from_self()`):
    ///       `target_dist = dist.saturating_add(c)`. Included if `stored.max_hops >= target_dist`
    ///       and `to_redacted_wire_string(target_dist)` is `Some`.
    ///     - Sorted ascending by `(dist, issuer)` (Hop-1 prioritized!) and capped at `max_class_package_bytes` if `Some`.
    /// - Computes overall `readers_fingerprint` and per-class `DropClassReceipt`.
    /// - Delta-check against `self.drop_sent_log.get(transport_id)`:
    ///   - If `!force_full` and `existing.readers_fingerprint == readers_fingerprint && existing.classes == class_receipts`,
    ///     returns `Ok(None)` (slot on `transport_id` is already 100% up-to-date!).
    /// - Otherwise returns `Ok(Some((subpackages, receipt)))`.
    pub fn prepare_drop_sync_subpackages(
        &self,
        transport_id: &str,
        custom_readers: Option<&[(&str, u8)]>,
        max_class_package_bytes: Option<usize>,
        force_full: bool,
    ) -> Result<Option<(Vec<DropClassSubpackage>, DropSyncReceipt)>, WotError> {
        let readers: Vec<(Did, u8)> = if let Some(custom) = custom_readers {
            let mut map = BTreeMap::new();
            for &(raw_did, class) in custom {
                if !(1..=3).contains(&class) {
                    continue;
                }
                let canonical = canonicalize_did(raw_did)?;
                if canonical == self.self_did {
                    continue;
                }
                map.entry(canonical)
                    .and_modify(|existing: &mut u8| *existing = (*existing).min(class))
                    .or_insert(class);
            }
            let mut r: Vec<(Did, u8)> = map.into_iter().collect();
            r.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            r
        } else {
            self.authorized_drop_readers()
        };

        let overall_readers_fp = compute_readers_fingerprint(&readers);

        let graph = self.get_or_build_graph_cache();
        let distances = graph.shortest_distances_from_self();

        struct CandidateList {
            dist: u8,
            issuer: Did,
            version: u64,
            wire_string: String,
            fingerprint: u64,
        }

        let mut subpackages = Vec::new();
        let mut class_receipts = Vec::new();

        for c in 1..=3 {
            let mut class_reader_dids: Vec<Did> = readers
                .iter()
                .filter(|(_, class)| *class == c)
                .map(|(did, _)| did.clone())
                .collect();

            if class_reader_dids.is_empty() {
                continue;
            }
            class_reader_dids.sort();

            let class_reader_pairs: Vec<(Did, u8)> =
                class_reader_dids.iter().map(|d| (d.clone(), c)).collect();
            let class_readers_fp = compute_readers_fingerprint(&class_reader_pairs);

            let mut class_candidates = Vec::new();

            // 1. Own signed list (dist = 0, target_dist = c)
            if let Some(own_list) = &self.own_signed_list {
                let target_dist = c;
                if own_list.max_hops >= target_dist
                    && let Some(wire) = own_list.to_redacted_wire_string(target_dist)
                {
                    let fp = own_list.disclosure_fingerprint(target_dist);
                    class_candidates.push(CandidateList {
                        dist: 0,
                        issuer: self.self_did.clone(),
                        version: own_list.v,
                        wire_string: wire,
                        fingerprint: fp,
                    });
                }
            }

            // 2. Reachable third-party lists
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

                let target_dist = dist.saturating_add(c);
                if stored.max_hops.min(3) < target_dist {
                    continue;
                }

                if let Some(wire) = stored.to_redacted_wire_string(target_dist) {
                    let fp = stored.disclosure_fingerprint(target_dist);
                    class_candidates.push(CandidateList {
                        dist,
                        issuer: iss.clone(),
                        version: stored.v,
                        wire_string: wire,
                        fingerprint: fp,
                    });
                }
            }

            // Sort ascending by dist, then descending by version (newest first), then issuer (Hop-1 prioritized!)
            class_candidates.sort_by(|a, b| {
                a.dist
                    .cmp(&b.dist)
                    .then_with(|| b.version.cmp(&a.version))
                    .then_with(|| a.issuer.cmp(&b.issuer))
            });

            let mut included_lists = Vec::new();
            let mut receipt_entries = Vec::new();
            let mut current_bytes = 31usize;

            for cand in class_candidates {
                let added_bytes = if included_lists.is_empty() {
                    cand.wire_string.len() + 2
                } else {
                    cand.wire_string.len() + 3
                };

                if let Some(limit) = max_class_package_bytes
                    && current_bytes.saturating_add(added_bytes) > limit
                {
                    continue;
                }

                current_bytes = current_bytes.saturating_add(added_bytes);
                included_lists.push(cand.wire_string);
                receipt_entries.push(SyncReceiptEntry {
                    issuer_did: cand.issuer,
                    version: cand.version,
                    disclosure_fingerprint: cand.fingerprint,
                });
            }

            subpackages.push(DropClassSubpackage {
                distance_class: c,
                reader_dids: class_reader_dids,
                package: WotSyncPackage {
                    format_version: 1,
                    lists: included_lists,
                },
            });

            class_receipts.push(DropClassReceipt {
                distance_class: c,
                readers_fingerprint: class_readers_fp,
                entries: receipt_entries,
            });
        }

        drop(graph);

        let overall_receipt = DropSyncReceipt {
            transport_id: transport_id.to_string(),
            readers_fingerprint: overall_readers_fp,
            classes: class_receipts,
        };

        if !force_full
            && let Some(existing) = self.drop_sent_log.get(transport_id)
            && existing.readers_fingerprint == overall_receipt.readers_fingerprint
            && existing.classes == overall_receipt.classes
        {
            return Ok(None);
        }

        Ok(Some((subpackages, overall_receipt)))
    }

    /// Commits a drop synchronization receipt to `drop_sent_log`.
    pub fn commit_drop_sync_receipt(&mut self, receipt: DropSyncReceipt, now_secs: u64) {
        self.drop_sent_log.insert(
            receipt.transport_id,
            DropSentRecord {
                readers_fingerprint: receipt.readers_fingerprint,
                classes: receipt.classes,
                committed_at: now_secs,
            },
        );
    }

    /// Clears either a specific transport entry or all entries from `drop_sent_log`.
    pub fn clear_drop_sent_log(&mut self, transport_id: Option<&str>) {
        if let Some(tid) = transport_id {
            self.drop_sent_log.remove(tid);
        } else {
            self.drop_sent_log.clear();
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

                    // Admission check & hop distance calculation:
                    // a) Direct handshake peer (before set_contact_trust) -> hop_dist = 1
                    let is_direct_peer = direct_sender_canonical.as_deref() == Some(&candidate_iss);
                    // b) In direct own_contacts (even level 0) -> hop_dist = 1
                    let is_direct_contact = self.own_contacts.contains_key(&candidate_iss);
                    // c) Reachable in graph with level >= 1 within policy.max_import_depth
                    let graph_dist = graph
                        .did_to_id
                        .get(&candidate_iss)
                        .and_then(|id| distances.get(id))
                        .copied();

                    let hop_dist = if is_direct_peer || is_direct_contact {
                        Some(1)
                    } else {
                        graph_dist.filter(|&d| d < self.policy.max_import_depth)
                    };

                    if let Some(hd) = hop_dist {
                        adm.push((raw, hd));
                    } else {
                        rem.push(raw);
                    }
                }
                (adm, rem)
            };

            // 2. Cryptographic verification & storage phase (graph cache is released)
            for (raw, hop_dist) in admitted {
                match parse_and_verify_sd_jwt(raw, now_secs) {
                    Err(WotError::FutureTimestamp { .. }) => {
                        stats.rejected_timestamp += 1;
                    }
                    Err(_) => {
                        stats.rejected_crypto += 1;
                    }
                    Ok((iss, mut new_stored)) => {
                        // Discard under-redacted disclosures whose contact_max_hops is smaller than issuer's hop distance
                        new_stored
                            .disclosures
                            .retain(|_, record| record.contact_max_hops >= hop_dist);

                        if let Some(existing) = self.raw_list_store.get_mut(&iss) {
                            if existing.v == new_stored.v
                                && existing.jws_compact != new_stored.jws_compact
                            {
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
                                    if let std::collections::btree_map::Entry::Vacant(e) =
                                        existing.disclosures.entry(digest)
                                    {
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
        stats.pruned_orphans =
            self.prune_unreachable_lists_preserving(direct_sender_canonical.as_deref());

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
