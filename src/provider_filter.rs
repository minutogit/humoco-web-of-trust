use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::WotError;
use crate::identity::{Did, WotSigner, canonicalize_did, extract_verifying_key};
use crate::sd_jwt::{MAX_CLOCK_SKEW_SECS, MAX_VERSION_AHEAD_SECS};

/// The standard type identifier for HuMoCo provider filters.
pub const PROVIDER_FILTER_TYP: &str = "wot-provider-filter+v1";

/// Maximum raw payload size allowed for provider filters (8 MB).
pub const MAX_PROVIDER_FILTER_RAW_LEN: usize = 8 * 1024 * 1024;

/// Maximum number of keys accepted by [`BinaryFuse64::build`].
const MAX_BINARY_FUSE_KEYS: usize = 10_000_000;

fn is_valid_fuse_params(
    segment_length: u32,
    segment_length_mask: u32,
    segment_count_length: u32,
    fingerprints_len: usize,
) -> bool {
    if fingerprints_len == 0 {
        return segment_length == 0 && segment_length_mask == 0 && segment_count_length == 0;
    }
    if !segment_length.is_power_of_two() || segment_length_mask != segment_length - 1 {
        return false;
    }
    if segment_count_length == 0 || !segment_count_length.is_multiple_of(segment_length) {
        return false;
    }
    segment_length
        .checked_mul(2)
        .and_then(|two| segment_count_length.checked_add(two))
        .is_some_and(|expected| expected as usize == fingerprints_len)
}

/// MurmurHash3 64-bit finalizer / mixer.
#[inline]
pub fn mix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    h
}

/// Derives the 3 slot indices for a key in the binary fuse filter.
#[inline]
fn get_hashes(
    key: u64,
    seed: u64,
    segment_count_length: u32,
    segment_length: u32,
    segment_length_mask: u32,
) -> (u32, u32, u32) {
    let hash = mix64(key.wrapping_add(seed));
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u32;
    let h0 = hi;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;
    (h0, h1, h2)
}

/// Hashes a member DID into a 64-bit domain-separated key for the provider filter.
pub fn hash_member_did(
    issuer_did: &str,
    version: u64,
    level: u8,
    target_did: &str,
) -> Result<u64, WotError> {
    let can_iss = canonicalize_did(issuer_did)?;
    let can_target = canonicalize_did(target_did)?;
    let mut hasher = Sha256::new();
    hasher.update(b"HUMOCO_PROVIDER_FILTER_V1\0");
    hasher.update(can_iss.as_bytes());
    hasher.update(version.to_be_bytes());
    hasher.update([level]);
    hasher.update(can_target.as_bytes());
    let digest = hasher.finalize();
    let key_bytes: [u8; 8] = digest[0..8].try_into().unwrap();
    Ok(u64::from_le_bytes(key_bytes))
}

/// In-memory 64-bit Binary Fuse Filter using 3-wise XOR peeling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryFuse64 {
    pub seed: u64,
    pub segment_length: u32,
    pub segment_length_mask: u32,
    pub segment_count_length: u32,
    pub fingerprints: Vec<u64>,
}

impl BinaryFuse64 {
    /// Builds a 64-bit binary fuse filter for the provided key slice.
    /// Handles 0 keys (empty), tiny sets (1..64), and large sets (up to 10,000,000).
    pub fn build(keys: &[u64]) -> Result<Self, WotError> {
        let mut unique_keys = keys.to_vec();
        unique_keys.sort_unstable();
        unique_keys.dedup();

        let size = unique_keys.len();
        if size > MAX_BINARY_FUSE_KEYS {
            return Err(WotError::LimitExceeded(format!(
                "BinaryFuse64 key count {} exceeds maximum {}",
                size, MAX_BINARY_FUSE_KEYS
            )));
        }
        if size == 0 {
            return Ok(Self {
                seed: 0,
                segment_length: 0,
                segment_length_mask: 0,
                segment_count_length: 0,
                fingerprints: Vec::new(),
            });
        }

        let (segment_length, segment_count) = if size <= 64 {
            (32u32, 2u32)
        } else {
            let arity = 3u32;
            let exp = (((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as u32).clamp(5, 18);
            let mut seg_len = 1u32 << exp;
            let size_factor =
                (0.875 + 0.25 * (1_000_000.0_f64.ln()) / (size as f64).ln()).max(1.125);
            let capacity = ((size as f64) * size_factor).ceil() as u32;
            let mut init_segment_count = capacity.div_ceil(seg_len).max(arity);
            while seg_len > 32 && init_segment_count < arity + 1 {
                seg_len /= 2;
                init_segment_count = capacity.div_ceil(seg_len).max(arity);
            }
            let seg_cnt = init_segment_count - (arity - 1);
            (seg_len, seg_cnt)
        };

        let segment_length_mask = segment_length - 1;
        let array_length = (segment_count + 2) * segment_length;
        let segment_count_length = segment_count * segment_length;
        let capacity = array_length as usize;

        let mut rng_seed = 0x726b2b9d438b9d4d_u64;

        for _ in 0..100 {
            rng_seed = rng_seed.wrapping_add(0x9e3779b97f4a7c15);
            let seed = mix64(rng_seed);

            let mut t2count = vec![0u32; capacity];
            let mut t2hash = vec![0u64; capacity];

            for &k in &unique_keys {
                let (h0, h1, h2) = get_hashes(
                    k,
                    seed,
                    segment_count_length,
                    segment_length,
                    segment_length_mask,
                );
                t2count[h0 as usize] += 4;
                t2hash[h0 as usize] ^= k;

                t2count[h1 as usize] += 4;
                t2count[h1 as usize] ^= 1;
                t2hash[h1 as usize] ^= k;

                t2count[h2 as usize] += 4;
                t2count[h2 as usize] ^= 2;
                t2hash[h2 as usize] ^= k;
            }

            let mut alone = Vec::with_capacity(capacity);
            for (i, &count) in t2count.iter().enumerate().take(capacity) {
                if (count >> 2) == 1 {
                    alone.push(i as u32);
                }
            }

            let mut reverse_order = Vec::with_capacity(size);

            while let Some(index) = alone.pop() {
                let idx = index as usize;
                if (t2count[idx] >> 2) == 1 {
                    let k = t2hash[idx];
                    let found = (t2count[idx] & 3) as u8;
                    reverse_order.push((k, found));

                    let (h0, h1, h2) = get_hashes(
                        k,
                        seed,
                        segment_count_length,
                        segment_length,
                        segment_length_mask,
                    );
                    let h = [h0, h1, h2];

                    let other1 = h[((found + 1) % 3) as usize] as usize;
                    t2count[other1] -= 4;
                    t2count[other1] ^= ((found + 1) % 3) as u32;
                    t2hash[other1] ^= k;
                    if (t2count[other1] >> 2) == 1 {
                        alone.push(other1 as u32);
                    }

                    let other2 = h[((found + 2) % 3) as usize] as usize;
                    t2count[other2] -= 4;
                    t2count[other2] ^= ((found + 2) % 3) as u32;
                    t2hash[other2] ^= k;
                    if (t2count[other2] >> 2) == 1 {
                        alone.push(other2 as u32);
                    }
                }
            }

            if reverse_order.len() == size {
                let mut fingerprints = vec![0u64; capacity];
                while let Some((k, found)) = reverse_order.pop() {
                    let (h0, h1, h2) = get_hashes(
                        k,
                        seed,
                        segment_count_length,
                        segment_length,
                        segment_length_mask,
                    );
                    let h = [h0 as usize, h1 as usize, h2 as usize];
                    let fp = mix64(k);
                    let fp = if fp == 0 { 1 } else { fp };
                    let f1 = fingerprints[h[((found + 1) % 3) as usize]];
                    let f2 = fingerprints[h[((found + 2) % 3) as usize]];
                    fingerprints[h[found as usize]] = fp ^ f1 ^ f2;
                }

                return Ok(Self {
                    seed,
                    segment_length,
                    segment_length_mask,
                    segment_count_length,
                    fingerprints,
                });
            }
        }

        Err(WotError::LimitExceeded(
            "BinaryFuse64 peeling failed after 100 attempts".to_string(),
        ))
    }

    /// Checks if a 64-bit key is present in the filter with negligible (~2^-64) false positive rate.
    #[inline]
    pub fn contains(&self, key: u64) -> bool {
        if self.fingerprints.is_empty()
            || !is_valid_fuse_params(
                self.segment_length,
                self.segment_length_mask,
                self.segment_count_length,
                self.fingerprints.len(),
            )
        {
            return false;
        }
        let (h0, h1, h2) = get_hashes(
            key,
            self.seed,
            self.segment_count_length,
            self.segment_length,
            self.segment_length_mask,
        );
        let fp = mix64(key);
        let fp = if fp == 0 { 1 } else { fp };
        let (Some(&f0), Some(&f1), Some(&f2)) = (
            self.fingerprints.get(h0 as usize),
            self.fingerprints.get(h1 as usize),
            self.fingerprints.get(h2 as usize),
        ) else {
            return false;
        };
        let actual = f0 ^ f1 ^ f2;
        actual == fp
    }

    /// Serializes filter parameters and fingerprints into base64url representation.
    pub fn encode(&self) -> EncodedBinaryFuse64 {
        let mut bytes = Vec::with_capacity(self.fingerprints.len() * 8);
        for &fp in &self.fingerprints {
            bytes.extend_from_slice(&fp.to_le_bytes());
        }
        EncodedBinaryFuse64 {
            seed: self.seed,
            segment_length: self.segment_length,
            segment_length_mask: self.segment_length_mask,
            segment_count_length: self.segment_count_length,
            fingerprints_b64: URL_SAFE_NO_PAD.encode(&bytes),
        }
    }

    /// Decodes a filter from its base64url representation.
    pub fn decode(encoded: &EncodedBinaryFuse64) -> Result<Self, WotError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded.fingerprints_b64)
            .map_err(|e| {
                WotError::Serialization(format!("Invalid base64url fingerprints: {}", e))
            })?;
        if bytes.len() % 8 != 0 {
            return Err(WotError::Serialization(
                "Fingerprints byte length is not a multiple of 8".to_string(),
            ));
        }
        let mut fingerprints = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            fingerprints.push(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        if !is_valid_fuse_params(
            encoded.segment_length,
            encoded.segment_length_mask,
            encoded.segment_count_length,
            fingerprints.len(),
        ) {
            return Err(WotError::Serialization(
                "Invalid BinaryFuse64 filter parameters".to_string(),
            ));
        }
        Ok(Self {
            seed: encoded.seed,
            segment_length: encoded.segment_length,
            segment_length_mask: encoded.segment_length_mask,
            segment_count_length: encoded.segment_count_length,
            fingerprints,
        })
    }
}

/// Compact wire representation of a BinaryFuse64 filter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodedBinaryFuse64 {
    pub seed: u64,
    pub segment_length: u32,
    pub segment_length_mask: u32,
    pub segment_count_length: u32,
    pub fingerprints_b64: String,
}

/// Unsigned provider filter payload describing certified member levels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderFilterPayload {
    pub typ: String,
    pub iss: Did,
    pub name: String,
    pub v: u64,
    pub iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    pub member_count: u32,
    /// Trust level (1..=3) -> Encoded BinaryFuse64 filter
    pub level_filters: BTreeMap<u8, EncodedBinaryFuse64>,
}

/// Signed wire format for provider filters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedProviderFilter {
    pub typ: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

/// Locally stored provider filter with verified signature and cached filter structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProviderFilter {
    pub raw_json: String,
    pub payload: ProviderFilterPayload,
    #[serde(default)]
    pub decoded_filters: BTreeMap<u8, BinaryFuse64>,
    pub local_trust_level: u8,
    pub imported_at: u64,
}

impl StoredProviderFilter {
    /// Queries whether `target_did` is certified by this provider, returning the highest matching level (1..=3).
    pub fn certified_level(&self, target_did: &str) -> Option<u8> {
        for &lvl in &[3, 2, 1] {
            if !self.payload.level_filters.contains_key(&lvl) {
                continue;
            }
            let hash = match hash_member_did(&self.payload.iss, self.payload.v, lvl, target_did) {
                Ok(h) => h,
                Err(_) => continue,
            };

            if let Some(filter) = self.decoded_filters.get(&lvl) {
                if filter.contains(hash) {
                    return Some(lvl);
                }
            } else if let Some(encoded) = self.payload.level_filters.get(&lvl)
                && let Ok(filter) = BinaryFuse64::decode(encoded)
                && filter.contains(hash)
            {
                return Some(lvl);
            }
        }
        None
    }
}

/// Creates and signs a new provider filter document, returning its raw JSON string.
pub fn create_and_sign_provider_filter<S: WotSigner>(
    signer: &S,
    name: &str,
    v: u64,
    iat: u64,
    source_url: Option<String>,
    members: &[(Did, u8)],
) -> Result<String, WotError> {
    let signer_did = canonicalize_did(signer.did())?;

    // Group members by level (1..=3)
    let mut level_members: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
    for (did, level) in members {
        if *level == 0 || *level > 3 {
            return Err(WotError::InvalidTrustLevel(*level));
        }
        let can_did = canonicalize_did(did)?;
        let hash = hash_member_did(&signer_did, v, *level, &can_did)?;
        level_members.entry(*level).or_default().push(hash);
    }

    let mut level_filters = BTreeMap::new();
    for (level, hashes) in level_members {
        let filter = BinaryFuse64::build(&hashes)?;
        level_filters.insert(level, filter.encode());
    }

    let payload = ProviderFilterPayload {
        typ: PROVIDER_FILTER_TYP.to_string(),
        iss: signer_did,
        name: name.to_string(),
        v,
        iat,
        source_url,
        member_count: members.len() as u32,
        level_filters,
    };

    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let sig = signer.sign(payload_b64.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(sig);

    let signed = SignedProviderFilter {
        typ: PROVIDER_FILTER_TYP.to_string(),
        payload_b64,
        signature_b64,
    };

    serde_json::to_string(&signed).map_err(WotError::from)
}

/// Parses and cryptographically verifies a raw JSON provider filter.
pub fn parse_and_verify_provider_filter(
    raw_json: &str,
    now_secs: u64,
) -> Result<StoredProviderFilter, WotError> {
    if raw_json.len() > MAX_PROVIDER_FILTER_RAW_LEN {
        return Err(WotError::LimitExceeded(format!(
            "Provider filter exceeds {} bytes limit",
            MAX_PROVIDER_FILTER_RAW_LEN
        )));
    }

    let signed: SignedProviderFilter = serde_json::from_str(raw_json)?;
    if signed.typ != PROVIDER_FILTER_TYP {
        return Err(WotError::Serialization(format!(
            "Invalid provider filter typ: {}",
            signed.typ
        )));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&signed.payload_b64)
        .map_err(|e| WotError::Serialization(format!("Invalid base64url payload: {}", e)))?;
    let payload: ProviderFilterPayload = serde_json::from_slice(&payload_bytes)?;

    if payload.typ != PROVIDER_FILTER_TYP {
        return Err(WotError::Serialization(format!(
            "Invalid provider filter payload typ: {}",
            payload.typ
        )));
    }

    let canonical_iss = canonicalize_did(&payload.iss)?;
    if canonical_iss != payload.iss {
        return Err(WotError::InvalidDid(
            "Provider filter issuer DID not in canonical form".to_string(),
        ));
    }
    let vk = extract_verifying_key(&canonical_iss)?;

    // Strict signature verification over payload_b64
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signed.signature_b64)
        .map_err(|e| WotError::Serialization(format!("Invalid base64url signature: {}", e)))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| WotError::InvalidSignature)?;
    vk.verify_strict(signed.payload_b64.as_bytes(), &sig)
        .map_err(|_| WotError::InvalidSignature)?;

    // Timestamp verification
    if payload.iat > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(WotError::FutureTimestamp {
            claim_secs: payload.iat,
            now_secs,
        });
    }
    if payload.v > now_secs.saturating_add(MAX_VERSION_AHEAD_SECS) {
        return Err(WotError::FutureTimestamp {
            claim_secs: payload.v,
            now_secs,
        });
    }

    let mut decoded_filters = BTreeMap::new();
    for (&lvl, encoded) in &payload.level_filters {
        if lvl == 0 || lvl > 3 {
            return Err(WotError::InvalidTrustLevel(lvl));
        }
        let decoded = BinaryFuse64::decode(encoded)?;
        decoded_filters.insert(lvl, decoded);
    }

    Ok(StoredProviderFilter {
        raw_json: raw_json.to_string(),
        payload,
        decoded_filters,
        local_trust_level: 0,
        imported_at: now_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ed25519WotSigner;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn create_test_signer() -> (Ed25519WotSigner, Did) {
        let sk = SigningKey::generate(&mut OsRng);
        let signer = Ed25519WotSigner::new(sk).expect("valid signer");
        let did = signer.did().to_string();
        (signer, did)
    }

    #[test]
    fn test_binary_fuse_0_keys() {
        let filter = BinaryFuse64::build(&[]).expect("build empty filter");
        assert_eq!(filter.fingerprints.len(), 0);
        assert!(!filter.contains(0));
        assert!(!filter.contains(42));
        assert!(!filter.contains(0xdeadbeef));
    }

    #[test]
    fn test_binary_fuse_1_key() {
        let key = 0x1234_5678_9abc_def0_u64;
        let filter = BinaryFuse64::build(&[key]).expect("build 1-key filter");
        assert!(filter.contains(key));
        assert!(!filter.contains(key + 1));
        assert!(!filter.contains(0));
    }

    #[test]
    fn test_binary_fuse_10_keys() {
        let keys: Vec<u64> = (1..=10).map(|i| mix64(i * 1000 + 42)).collect();
        let filter = BinaryFuse64::build(&keys).expect("build 10-key filter");
        for &k in &keys {
            assert!(filter.contains(k));
        }
        for i in 11..=100 {
            assert!(!filter.contains(mix64(i * 1000 + 42)));
        }
    }

    #[test]
    fn test_binary_fuse_5000_keys_zero_fn_and_fp() {
        let keys: Vec<u64> = (0..5000).map(|i| mix64(i * 37 + 0xbeef)).collect();
        let filter = BinaryFuse64::build(&keys).expect("build 5000-key filter");

        // Zero false negatives: all 5,000 keys MUST be contained
        for &k in &keys {
            assert!(filter.contains(k), "Missing key {}", k);
        }

        // Test over 10,000 random non-member keys: false positives must be 0
        let mut false_positives = 0;
        for i in 100_000..110_000 {
            let non_member = mix64(i * 53 + 0xcafe);
            if filter.contains(non_member) {
                false_positives += 1;
            }
        }
        assert_eq!(
            false_positives, 0,
            "Expected 0 false positives out of 10,000 queries"
        );
    }

    #[test]
    fn test_filter_encode_decode_roundtrip() {
        let keys: Vec<u64> = (1..=20).map(|i| mix64(i * 77)).collect();
        let filter = BinaryFuse64::build(&keys).unwrap();
        let encoded = filter.encode();
        let decoded = BinaryFuse64::decode(&encoded).expect("decode valid filter");

        assert_eq!(filter, decoded);
        for &k in &keys {
            assert!(decoded.contains(k));
        }
    }

    #[test]
    fn test_provider_filter_sign_verify_and_certified_level() {
        let (signer, issuer_did) = create_test_signer();
        let (_, member_alice) = create_test_signer();
        let (_, member_bob) = create_test_signer();
        let (_, non_member) = create_test_signer();

        let now_secs = 1_700_000_000;
        let members = vec![
            (member_alice.clone(), 3), // Level 3
            (member_bob.clone(), 2),   // Level 2
        ];

        let raw_json = create_and_sign_provider_filter(
            &signer,
            "Bio-Verband Deutschland",
            1,
            now_secs,
            Some("https://bio-verband.de/seal".to_string()),
            &members,
        )
        .expect("create provider filter");

        let stored = parse_and_verify_provider_filter(&raw_json, now_secs)
            .expect("parse and verify provider filter");

        assert_eq!(stored.payload.iss, issuer_did);
        assert_eq!(stored.payload.name, "Bio-Verband Deutschland");
        assert_eq!(stored.payload.member_count, 2);
        assert_eq!(stored.certified_level(&member_alice), Some(3));
        assert_eq!(stored.certified_level(&member_bob), Some(2));
        assert_eq!(stored.certified_level(&non_member), None);

        // Tampering test
        let mut tampered = raw_json.clone();
        tampered.replace_range(20..25, "XXXXX");
        assert!(parse_and_verify_provider_filter(&tampered, now_secs).is_err());
    }
}
