use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::WotError;
use crate::identity::{Did, WotSigner, canonicalize_did, extract_verifying_key};
use crate::provider_filter::BinaryFuse64;
use crate::sd_jwt::MAX_CLOCK_SKEW_SECS;

/// Domain-separation prefix for dual-signed `KeySuccessorAttestation` payloads (ADR-09).
pub const KEY_SUCCESSOR_DOMAIN: &[u8] = b"HUMOCO_KEY_SUCCESSOR_V1";

/// Hard upper bound on followable successor hops during CardStore / DID resolution (ADR-09).
pub const MAX_SUCCESSOR_CHAIN_LEN: usize = 8;

/// Domain-separation tag matching `humoco-proto`'s canonical 257-byte `LockReceipt` preimage (ADR-10).
pub const LOCK_RECEIPT_DOMAIN: &[u8] = b"HUMOCO_LOCK_RECEIPT_V1";

/// Canonical message prefix matching `humoco-sync` operator delegation signatures (`PUT ?lock_delegate`, ADR-10).
pub const LOCK_DELEGATE_PREFIX: &str = "HUMOCO-LOCK-DELEGATE-V1";

/// Domain-separation tag for hashing revoked server pubkeys into `BinaryFuse64` denylists (ADR-10).
pub const SERVER_OFFENDER_FILTER_DOMAIN: &[u8] = b"HUMOCO_SERVER_OFFENDER_V1";

/// Type tag for signed Hub-distributed server offender bundles (ADR-10).
pub const SERVER_OFFENDERS_TYP: &str = "wot-server-offenders+v1";

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    if s.len() != N * 2 {
        return Err("invalid hex length");
    }
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("hex must be lowercase");
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for i in 0..N {
        let hi = match bytes[2 * i] {
            b'0'..=b'9' => bytes[2 * i] - b'0',
            b'a'..=b'f' => bytes[2 * i] - b'a' + 10,
            _ => return Err("invalid hex character"),
        };
        let lo = match bytes[2 * i + 1] {
            b'0'..=b'9' => bytes[2 * i + 1] - b'0',
            b'a'..=b'f' => bytes[2 * i + 1] - b'a' + 10,
            _ => return Err("invalid hex character"),
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

mod serde_hex_32 {
    use super::{decode_hex_fixed, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&encode_hex(bytes))
        } else {
            serde::Serialize::serialize(bytes, serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            decode_hex_fixed::<32>(&s).map_err(D::Error::custom)
        } else {
            <[u8; 32]>::deserialize(deserializer)
        }
    }
}

mod serde_hex_opt_32 {
    use super::{decode_hex_fixed, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(arr) => {
                if serializer.is_human_readable() {
                    serializer.serialize_some(&encode_hex(arr))
                } else {
                    serializer.serialize_some(arr)
                }
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) => decode_hex_fixed::<32>(&s)
                    .map(Some)
                    .map_err(D::Error::custom),
                None => Ok(None),
            }
        } else {
            Option::<[u8; 32]>::deserialize(deserializer)
        }
    }
}

mod serde_hex_64 {
    use super::{decode_hex_fixed, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&encode_hex(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            decode_hex_fixed::<64>(&s).map_err(D::Error::custom)
        } else {
            let v: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            v.try_into()
                .map_err(|_| D::Error::custom("expected 64 bytes"))
        }
    }
}

/// Reason recorded inside a [`KeySuccessorAttestation`] (ADR-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationReason {
    /// Routine key hygiene rotation.
    Routine,
    /// Suspected compromise of `old_did`.
    Compromise,
    /// Hardware / device migration.
    DeviceMigration,
}

impl KeyRotationReason {
    fn tag_byte(self) -> u8 {
        match self {
            Self::Routine => 0x01,
            Self::Compromise => 0x02,
            Self::DeviceMigration => 0x03,
        }
    }
}

/// Dual-signed `old_did -> new_did` attestation preventing vampire attacks and enabling
/// cryptographic DID discovery continuity (ADR-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySuccessorAttestation {
    /// Previous identity being succeeded (`did:key:z...`).
    pub old_did: Did,
    /// New successor identity (`did:key:z...`).
    pub new_did: Did,
    /// Reason for rotating to `new_did`.
    pub reason: KeyRotationReason,
    /// Optional replacement Layer-2 voucher creator migration public key.
    #[serde(with = "serde_hex_opt_32")]
    pub new_creator_mig_pub: Option<[u8; 32]>,
    /// Rotation timestamp in UTC Unix seconds.
    pub rotated_at: u64,
    /// Ed25519 signature by `old_did` over [`Self::signing_digest`].
    #[serde(with = "serde_hex_64")]
    pub old_key_signature: [u8; 64],
    /// Ed25519 signature by `new_did` over [`Self::signing_digest`].
    #[serde(with = "serde_hex_64")]
    pub new_key_signature: [u8; 64],
}

impl KeySuccessorAttestation {
    /// Computes the canonical `HUMOCO_KEY_SUCCESSOR_V1` SHA-256 digest covered by both keys.
    pub fn signing_digest(
        old_did: &str,
        new_did: &str,
        reason: KeyRotationReason,
        new_creator_mig_pub: Option<[u8; 32]>,
        rotated_at: u64,
    ) -> Result<[u8; 32], WotError> {
        let can_old = canonicalize_did(old_did)?;
        let can_new = canonicalize_did(new_did)?;
        if can_old == can_new {
            return Err(WotError::SelfTrustForbidden);
        }
        if rotated_at == 0 {
            return Err(WotError::MalformedSdJwt(
                "KeySuccessorAttestation rotated_at must be positive".to_string(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(KEY_SUCCESSOR_DOMAIN);
        let old_b = can_old.as_bytes();
        let new_b = can_new.as_bytes();
        hasher.update((old_b.len() as u32).to_le_bytes());
        hasher.update(old_b);
        hasher.update((new_b.len() as u32).to_le_bytes());
        hasher.update(new_b);
        hasher.update([reason.tag_byte()]);
        match new_creator_mig_pub {
            Some(pk) => {
                hasher.update([1u8]);
                hasher.update(pk);
            }
            None => hasher.update([0u8]),
        }
        hasher.update(rotated_at.to_le_bytes());
        Ok(hasher.finalize().into())
    }

    /// Creates and dual-signs a [`KeySuccessorAttestation`] using both old and new signers.
    pub fn sign_dual(
        old_signer: &dyn WotSigner,
        new_signer: &dyn WotSigner,
        reason: KeyRotationReason,
        new_creator_mig_pub: Option<[u8; 32]>,
        rotated_at: u64,
    ) -> Result<Self, WotError> {
        let can_old = canonicalize_did(old_signer.did())?;
        let can_new = canonicalize_did(new_signer.did())?;
        if let Some(pk) = new_creator_mig_pub {
            let vk = VerifyingKey::from_bytes(&pk).map_err(|_| WotError::WeakPublicKey)?;
            if vk.is_weak() {
                return Err(WotError::WeakPublicKey);
            }
        }
        let digest =
            Self::signing_digest(&can_old, &can_new, reason, new_creator_mig_pub, rotated_at)?;
        let old_key_signature = old_signer.sign(&digest);
        let new_key_signature = new_signer.sign(&digest);
        Ok(Self {
            old_did: can_old,
            new_did: can_new,
            reason,
            new_creator_mig_pub,
            rotated_at,
            old_key_signature,
            new_key_signature,
        })
    }

    /// Strictly verifies DIDs, clock skew, non-weak keys, and BOTH Ed25519 signatures.
    pub fn verify(&self, now_secs: u64) -> Result<(), WotError> {
        if self.rotated_at > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(WotError::FutureTimestamp {
                claim_secs: self.rotated_at,
                now_secs,
            });
        }
        if let Some(pk) = self.new_creator_mig_pub {
            let vk = VerifyingKey::from_bytes(&pk).map_err(|_| WotError::WeakPublicKey)?;
            if vk.is_weak() {
                return Err(WotError::WeakPublicKey);
            }
        }
        let digest = Self::signing_digest(
            &self.old_did,
            &self.new_did,
            self.reason,
            self.new_creator_mig_pub,
            self.rotated_at,
        )?;
        let old_vk = extract_verifying_key(&self.old_did)?;
        let new_vk = extract_verifying_key(&self.new_did)?;
        let old_sig = Signature::from_bytes(&self.old_key_signature);
        let new_sig = Signature::from_bytes(&self.new_key_signature);
        old_vk
            .verify_strict(&digest, &old_sig)
            .map_err(|_| WotError::InvalidSignature)?;
        new_vk
            .verify_strict(&digest, &new_sig)
            .map_err(|_| WotError::InvalidSignature)?;
        Ok(())
    }
}

/// Resolves an acyclic successor chain from `start_did` up to [`MAX_SUCCESSOR_CHAIN_LEN`] hops.
///
/// Only cryptographically verified attestations are traversed; invalid entries are ignored.
/// Returns `Err(WotError::LimitExceeded)` on cycles or chains exceeding 8 hops.
pub fn resolve_successor_chain(
    start_did: &str,
    attestations: &[KeySuccessorAttestation],
    now_secs: u64,
) -> Result<Did, WotError> {
    let mut current = canonicalize_did(start_did)?;
    let mut visited = BTreeSet::new();
    visited.insert(current.clone());

    let mut verified_edges: Vec<&KeySuccessorAttestation> = Vec::new();
    for att in attestations {
        if att.verify(now_secs).is_ok() {
            verified_edges.push(att);
        }
    }

    let mut hops = 0usize;
    loop {
        let mut candidates: Vec<&KeySuccessorAttestation> = verified_edges
            .iter()
            .copied()
            .filter(|a| canonicalize_did(&a.old_did).ok().as_deref() == Some(current.as_str()))
            .collect();
        if candidates.is_empty() {
            return Ok(current);
        }
        candidates.sort_by(|a, b| {
            b.rotated_at
                .cmp(&a.rotated_at)
                .then_with(|| b.new_did.cmp(&a.new_did))
        });
        let next = canonicalize_did(&candidates[0].new_did)?;
        hops += 1;
        if hops > MAX_SUCCESSOR_CHAIN_LEN {
            return Err(WotError::LimitExceeded(format!(
                "KeySuccessorAttestation chain exceeded maximum depth of {MAX_SUCCESSOR_CHAIN_LEN}"
            )));
        }
        if !visited.insert(next.clone()) {
            return Err(WotError::LimitExceeded(
                "Cycle detected in KeySuccessorAttestation chain".to_string(),
            ));
        }
        current = next;
    }
}

/// Sync-Lock receipt kind matching `humoco_proto::LockReceiptKind` wire encoding (ADR-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WotLockReceiptKind {
    FirstWrite,
    ConflictSeen,
}

impl WotLockReceiptKind {
    fn as_byte(self) -> u8 {
        match self {
            Self::FirstWrite => 0,
            Self::ConflictSeen => 1,
        }
    }
}

/// Sync-Lock server receipt verified independently inside `humoco-wot` (ADR-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotLockReceipt {
    pub kind: WotLockReceiptKind,
    #[serde(with = "serde_hex_32")]
    pub lock_pub: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub bucket: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub slot: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub child_lock: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub entry_hash: [u8; 32],
    pub retain_until_quarter: u16,
    pub write_seq: u64,
    #[serde(with = "serde_hex_32")]
    pub bucket_head: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub recipient_nonce: [u8; 32],
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl WotLockReceipt {
    /// Computes the exact 257-byte preimage SHA-256 digest (`HUMOCO_LOCK_RECEIPT_V1`).
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LOCK_RECEIPT_DOMAIN);
        hasher.update([self.kind.as_byte()]);
        hasher.update(self.lock_pub);
        hasher.update(self.bucket);
        hasher.update(self.slot);
        hasher.update(self.child_lock);
        hasher.update(self.entry_hash);
        hasher.update(self.retain_until_quarter.to_le_bytes());
        hasher.update(self.write_seq.to_le_bytes());
        hasher.update(self.bucket_head);
        hasher.update(self.recipient_nonce);
        hasher.finalize().into()
    }

    /// Strictly verifies non-weak `lock_pub` and Ed25519 signature over `self.digest()`.
    pub fn verify_signature(&self) -> Result<(), WotError> {
        let vk = VerifyingKey::from_bytes(&self.lock_pub).map_err(|_| WotError::WeakPublicKey)?;
        if vk.is_weak() {
            return Err(WotError::WeakPublicKey);
        }
        let sig = Signature::from_bytes(&self.sig);
        let digest = self.digest();
        vk.verify_strict(&digest, &sig)
            .map_err(|_| WotError::InvalidSignature)
    }
}

/// Cryptographic proof of server equivocation (two conflicting `FirstWrite` receipts on one slot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotEquivocationProof {
    pub receipt_a: WotLockReceipt,
    pub receipt_b: WotLockReceipt,
}

impl WotEquivocationProof {
    /// Verifies both conflicting `FirstWrite` signatures and returns the offending `lock_pub`.
    pub fn verify(&self) -> Result<[u8; 32], WotError> {
        if self.receipt_a.kind != WotLockReceiptKind::FirstWrite
            || self.receipt_b.kind != WotLockReceiptKind::FirstWrite
        {
            return Err(WotError::InvalidSignature);
        }
        if self.receipt_a.lock_pub != self.receipt_b.lock_pub {
            return Err(WotError::SignerMismatch {
                expected: encode_hex(&self.receipt_a.lock_pub),
                actual: encode_hex(&self.receipt_b.lock_pub),
            });
        }
        if self.receipt_a.slot != self.receipt_b.slot
            || self.receipt_a.child_lock == self.receipt_b.child_lock
        {
            return Err(WotError::InvalidSignature);
        }
        self.receipt_a.verify_signature()?;
        self.receipt_b.verify_signature()?;
        Ok(self.receipt_a.lock_pub)
    }
}

/// Signed operator delegation binding `admin_pub` -> `lock_pub` (`HUMOCO-LOCK-DELEGATE-V1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WotLockDelegation {
    #[serde(with = "serde_hex_32")]
    pub admin_pub: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub lock_pub: [u8; 32],
    pub issued_at: u64,
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl WotLockDelegation {
    /// Canonical signing message matching `humoco-sync` `PUT ?lock_delegate`.
    pub fn canonical_message(&self) -> String {
        format!(
            "{LOCK_DELEGATE_PREFIX}\n{}\n{}\n{}",
            encode_hex(&self.admin_pub),
            encode_hex(&self.lock_pub),
            self.issued_at
        )
    }

    /// Strictly verifies non-weak keys, positive timestamp, and `admin_pub` Ed25519 signature.
    pub fn verify(&self) -> Result<(), WotError> {
        if self.issued_at == 0 {
            return Err(WotError::InvalidSignature);
        }
        let admin_vk =
            VerifyingKey::from_bytes(&self.admin_pub).map_err(|_| WotError::WeakPublicKey)?;
        let lock_vk =
            VerifyingKey::from_bytes(&self.lock_pub).map_err(|_| WotError::WeakPublicKey)?;
        if admin_vk.is_weak() || lock_vk.is_weak() {
            return Err(WotError::WeakPublicKey);
        }
        let sig = Signature::from_bytes(&self.sig);
        let msg = self.canonical_message();
        admin_vk
            .verify_strict(msg.as_bytes(), &sig)
            .map_err(|_| WotError::InvalidSignature)
    }
}

/// Self-verifiable offender entry burning a server's `lock_pub` and optionally its operator `admin_pub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOffenderRecord {
    pub proof: WotEquivocationProof,
    pub delegation: Option<WotLockDelegation>,
    pub recorded_at: u64,
}

/// Permanent local & Hub-distributable revocation list for Byzantine Lock servers (ADR-10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOffenderList {
    pub records: Vec<ServerOffenderRecord>,
    pub revoked_lock_pubs: BTreeSet<[u8; 32]>,
    pub revoked_admin_pubs: BTreeSet<[u8; 32]>,
}

impl ServerOffenderList {
    /// Creates an empty `ServerOffenderList`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cryptographically verifies `record` before inserting `lock_pub` (and verified `admin_pub`).
    pub fn insert_verified(
        &mut self,
        record: ServerOffenderRecord,
        now_secs: u64,
    ) -> Result<(), WotError> {
        if record.recorded_at == 0 {
            return Err(WotError::InvalidSignature);
        }
        if record.recorded_at > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(WotError::FutureTimestamp {
                claim_secs: record.recorded_at,
                now_secs,
            });
        }
        let offending_lock = record.proof.verify()?;
        let mut offending_admin = None;
        if let Some(ref del) = record.delegation {
            if del.lock_pub != offending_lock {
                return Err(WotError::SignerMismatch {
                    expected: encode_hex(&offending_lock),
                    actual: encode_hex(&del.lock_pub),
                });
            }
            del.verify()?;
            offending_admin = Some(del.admin_pub);
        }

        self.revoked_lock_pubs.insert(offending_lock);
        if let Some(admin_pub) = offending_admin {
            self.revoked_admin_pubs.insert(admin_pub);
        }
        self.records.push(record);
        Ok(())
    }

    /// Returns `true` if `lock_pub` is permanently revoked due to verified equivocation.
    pub fn is_lock_pub_revoked(&self, lock_pub: &[u8; 32]) -> bool {
        self.revoked_lock_pubs.contains(lock_pub)
    }

    /// Returns `true` if operator `admin_pub` is permanently revoked via linked `LockDelegation`.
    pub fn is_admin_pub_revoked(&self, admin_pub: &[u8; 32]) -> bool {
        self.revoked_admin_pubs.contains(admin_pub)
    }

    /// Builds a compact `BinaryFuse64` denylist filter over all revoked `lock_pub` & `admin_pub` keys.
    pub fn build_denylist_filter(&self) -> Result<BinaryFuse64, WotError> {
        let mut keys =
            Vec::with_capacity(self.revoked_lock_pubs.len() + self.revoked_admin_pubs.len());
        for pk in self
            .revoked_lock_pubs
            .iter()
            .chain(self.revoked_admin_pubs.iter())
        {
            keys.push(hash_offender_pubkey(pk));
        }
        BinaryFuse64::build(&keys)
    }

    /// Queries a [`BinaryFuse64`] offender denylist filter built via [`Self::build_denylist_filter`].
    pub fn filter_contains_pubkey(filter: &BinaryFuse64, pubkey: &[u8; 32]) -> bool {
        filter.contains(hash_offender_pubkey(pubkey))
    }
}

fn hash_offender_pubkey(pubkey: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(SERVER_OFFENDER_FILTER_DOMAIN);
    hasher.update(pubkey);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}
