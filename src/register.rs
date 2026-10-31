use std::cell::{Ref, RefCell};
use std::collections::{BTreeMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::error::WotError;
use crate::graph::EgoGraphCache;
use crate::identity::{canonicalize_did, Did, WotSigner};
use crate::scorer::{evaluate_trust, evaluate_trust_from_observer, TrustEvaluation};
use crate::sd_jwt::{create_and_sign_sd_jwt, StoredSdJwt};

/// Local Web of Trust configuration policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WotPolicy {
    /// Default hop limit for contacts who haven't provided a trust list yet.
    pub unreciprocated_hops: u8,
    /// Global hop limit when creating own trust list.
    pub own_list_max_hops: u8,
    /// Maximum graph depth allowed when importing third-party lists.
    pub max_import_depth: u8,
    /// Maximum evaluation depth for path traversal.
    pub max_eval_depth: u8,
    /// Weight factor for voucher guarantors (default: 0.85).
    pub guarantor_weight: f64,
    /// Optional freshness half-life in seconds for list decay.
    pub freshness_half_life_secs: Option<u64>,
}

impl Default for WotPolicy {
    fn default() -> Self {
        Self {
            unreciprocated_hops: 1,
            own_list_max_hops: 4,
            max_import_depth: 5,
            max_eval_depth: 4,
            guarantor_weight: 0.85,
            freshness_half_life_secs: None,
        }
    }
}

/// A direct trust relationship configured by the user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnTrustEntry {
    /// Trust level: 0 (existence), 1 (30%), 2 (60%), 3 (85%).
    pub level: u8,
    /// User's desired hop forwarding limit for this contact (1..8).
    pub desired_hops: u8,
    /// Timestamp of last modification in unix seconds.
    pub updated_at: u64,
}

/// Record of trust lists previously transmitted to a recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentRecord {
    /// List version that was sent.
    pub version: u64,
    /// Fingerprint of disclosures included at transmission time.
    pub disclosure_fingerprint: u64,
    /// Timestamp of transmission in unix seconds.
    pub sent_at: u64,
}

/// Primary persistent state repository for the user's Web of Trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegister {
    /// Canonical DID of the local identity.
    pub self_did: Did,
    /// User's directly configured trust contacts.
    pub own_contacts: BTreeMap<Did, OwnTrustEntry>,
    /// Latest signed version of own trust list.
    pub own_signed_list: Option<StoredSdJwt>,
    /// True if contacts changed and own list needs re-signing.
    pub own_list_dirty: bool,
    /// Verified raw SD-JWT lists received from peers.
    pub raw_list_store: BTreeMap<Did, StoredSdJwt>,
    /// Log of lists sent to contacts: recipient_did -> issuer_did -> SentRecord.
    pub sent_log: BTreeMap<Did, BTreeMap<Did, SentRecord>>,
    /// Local evaluation and synchronisation policy.
    pub policy: WotPolicy,
    /// Ephemeral runtime graph cache for fast reachability and scoring.
    #[serde(skip)]
    pub(crate) graph_cache: RefCell<Option<EgoGraphCache>>,
}

impl TrustRegister {
    /// Creates a new `TrustRegister` for the given identity.
    pub fn new(self_did: &str, policy: WotPolicy) -> Result<Self, WotError> {
        let canonical_self = canonicalize_did(self_did)?;
        Ok(Self {
            self_did: canonical_self,
            own_contacts: BTreeMap::new(),
            own_signed_list: None,
            own_list_dirty: false,
            raw_list_store: BTreeMap::new(),
            sent_log: BTreeMap::new(),
            policy,
            graph_cache: RefCell::new(None),
        })
    }

    /// Borrows or lazily builds the in-memory `EgoGraphCache`.
    pub fn get_or_build_graph_cache(&self) -> Ref<'_, EgoGraphCache> {
        if self.graph_cache.borrow().is_none() {
            let graph = EgoGraphCache::build(&self.self_did, &self.own_contacts, &self.raw_list_store);
            *self.graph_cache.borrow_mut() = Some(graph);
        }
        Ref::map(self.graph_cache.borrow(), |opt| opt.as_ref().unwrap())
    }

    /// Invalidates the runtime graph cache so it will be rebuilt on next access.
    pub fn invalidate_graph_cache(&self) {
        *self.graph_cache.borrow_mut() = None;
    }

    /// Calculates effective hop limit for a contact based on Tit-for-Tat reciprocal routing.
    ///
    /// - If `target_did` is not in `own_contacts`: returns `None`.
    /// - If peer has not provided a forwardable list (level >= 1 and contact_max_hops >= 1):
    ///   capped by `policy.unreciprocated_hops`.
    /// - If peer has provided a valid list: capped by peer's `max_hops` (or peer's specific entry for self).
    pub fn effective_hops_for_contact(&self, target_did: &str) -> Option<u8> {
        let canonical_target = canonicalize_did(target_did).ok()?;
        let entry = self.own_contacts.get(&canonical_target)?;
        let desired = entry.desired_hops;

        let peer_list = match self.raw_list_store.get(&canonical_target) {
            Some(list) => list,
            None => return Some(desired.min(self.policy.unreciprocated_hops)),
        };

        let has_forwardable = peer_list
            .disclosures
            .values()
            .any(|d| d.level >= 1 && d.contact_max_hops >= 1);

        if !has_forwardable {
            return Some(desired.min(self.policy.unreciprocated_hops));
        }

        let entry_for_self = peer_list
            .disclosures
            .values()
            .find(|d| d.target_did == self.self_did);

        let peer_cap = if let Some(e) = entry_for_self {
            peer_list.max_hops.min(e.contact_max_hops)
        } else {
            peer_list.max_hops
        };

        Some(desired.min(peer_cap))
    }

    /// Adds or updates a direct contact trust assignment.
    pub fn set_contact_trust(
        &mut self,
        target_did: &str,
        level: u8,
        desired_hops: u8,
        now_secs: u64,
    ) -> Result<(), WotError> {
        let canonical = canonicalize_did(target_did)?;
        if canonical == self.self_did {
            return Err(WotError::SelfTrustForbidden);
        }
        if level > 3 {
            return Err(WotError::InvalidTrustLevel(level));
        }
        if desired_hops > 8 {
            return Err(WotError::InvalidHopLimit(desired_hops));
        }

        self.own_contacts.insert(
            canonical,
            OwnTrustEntry {
                level,
                desired_hops,
                updated_at: now_secs,
            },
        );
        self.own_list_dirty = true;
        self.invalidate_graph_cache();

        if level == 0 {
            self.prune_unreachable_lists();
        }

        Ok(())
    }

    /// Removes a direct contact from `own_contacts`.
    pub fn remove_contact_trust(&mut self, target_did: &str) -> Result<bool, WotError> {
        let canonical = canonicalize_did(target_did)?;
        let removed = self.own_contacts.remove(&canonical).is_some();
        if removed {
            self.own_list_dirty = true;
            self.invalidate_graph_cache();
            self.prune_unreachable_lists();
        }
        Ok(removed)
    }

    /// Signs the user's current trust list and returns the full SD-JWT wire string.
    pub fn sign_own_list<S: WotSigner>(&mut self, signer: &S, now_secs: u64) -> Result<String, WotError> {
        let signer_did = canonicalize_did(signer.did())?;
        if signer_did != self.self_did {
            return Err(WotError::SignerMismatch {
                expected: self.self_did.clone(),
                actual: signer_did,
            });
        }

        let last_v = self.own_signed_list.as_ref().map(|l| l.v).unwrap_or(0);
        let v = std::cmp::max(last_v.saturating_add(1), now_secs);

        let mut contacts = Vec::new();
        for (did, entry) in &self.own_contacts {
            let eff_hops = self.effective_hops_for_contact(did).unwrap_or(entry.desired_hops);
            contacts.push((did.clone(), entry.level, eff_hops));
        }

        let (wire_str, stored) = create_and_sign_sd_jwt(
            signer,
            v,
            now_secs,
            self.policy.own_list_max_hops,
            &contacts,
        )?;

        self.own_signed_list = Some(stored);
        self.own_list_dirty = false;
        Ok(wire_str)
    }

    /// Ensures that own list is signed, re-signing only if dirty or missing.
    pub fn ensure_own_list_signed<S: WotSigner>(
        &mut self,
        signer: &S,
        now_secs: u64,
    ) -> Result<bool, WotError> {
        if self.own_signed_list.is_none() || self.own_list_dirty {
            self.sign_own_list(signer, now_secs)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Prunes any third-party lists in `raw_list_store` that are no longer reachable.
    pub fn prune_unreachable_lists(&mut self) -> usize {
        self.prune_unreachable_lists_preserving(None)
    }

    /// Prunes unreachable third-party lists while preserving an optional direct contact.
    pub fn prune_unreachable_lists_preserving(&mut self, preserve_did: Option<&str>) -> usize {
        let distances = self.get_or_build_graph_cache().shortest_distances_from_self();

        let mut keep_dids = HashSet::new();
        // Direct contacts are always kept (even level 0)
        for did in self.own_contacts.keys() {
            keep_dids.insert(did.clone());
        }
        if let Some(Ok(c)) = preserve_did.map(canonicalize_did) {
            keep_dids.insert(c);
        }

        // Keep lists reachable within max_import_depth
        let graph = self.get_or_build_graph_cache();
        for (did, id) in &graph.did_to_id {
            if distances.get(id).is_some_and(|&dist| dist < self.policy.max_import_depth) {
                keep_dids.insert(did.clone());
            }
        }
        drop(graph);

        let initial_count = self.raw_list_store.len();
        self.raw_list_store.retain(|iss, _| keep_dids.contains(iss));
        let pruned = initial_count.saturating_sub(self.raw_list_store.len());

        if pruned > 0 {
            self.invalidate_graph_cache();
        }

        pruned
    }

    /// Evaluates network trust towards a single target DID.
    pub fn evaluate_did(
        &self,
        target_did: &str,
        now_secs: Option<u64>,
    ) -> Result<TrustEvaluation, WotError> {
        self.evaluate_voucher(target_did, &[], false, now_secs)
    }

    /// Evaluates network trust for a voucher given its creator and guarantors.
    pub fn evaluate_voucher(
        &self,
        creator_id: &str,
        guarantor_ids: &[&str],
        is_known_offender: bool,
        now_secs: Option<u64>,
    ) -> Result<TrustEvaluation, WotError> {
        let graph = self.get_or_build_graph_cache();
        evaluate_trust(
            &graph,
            &self.policy,
            creator_id,
            guarantor_ids,
            is_known_offender,
            now_secs,
        )
    }

    /// Evaluates network trust for a voucher from an observer's perspective given its creator and guarantors.
    pub fn evaluate_voucher_for_observer(
        &self,
        observer_did: &str,
        creator_id: &str,
        guarantor_ids: &[&str],
        is_known_offender: bool,
        now_secs: Option<u64>,
    ) -> Result<TrustEvaluation, WotError> {
        let graph = self.get_or_build_graph_cache();
        evaluate_trust_from_observer(
            &graph,
            &self.policy,
            observer_did,
            creator_id,
            guarantor_ids,
            is_known_offender,
            now_secs,
        )
    }
}
