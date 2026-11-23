use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

use crate::error::WotError;
use crate::identity::{Did, Digest128, WotSigner, canonicalize_did, extract_verifying_key};

pub const SD_JWT_TYP: &str = "wot-trustlist+sd-jwt";
pub const SD_JWT_ALG: &str = "EdDSA";
pub const MAX_SD_ENTRIES: usize = 256;
pub const MAX_SD_JWT_RAW_LEN: usize = 65_536;
pub const DECOY_BUCKET_MULTIPLE: usize = 8;
pub const MAX_CLOCK_SKEW_SECS: u64 = 86_400; // 24 hours
pub const MAX_VERSION_AHEAD_SECS: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdJwtHeader {
    pub alg: String,
    pub typ: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdJwtPayload {
    pub iss: Did,
    pub v: u64,
    pub iat: u64,
    pub max_hops: u8,
    pub _sd: Vec<Digest128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRecord {
    pub raw_b64: String,
    pub target_did: Did,
    pub level: u8,
    pub contact_max_hops: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSdJwt {
    pub jws_compact: String,
    pub v: u64,
    pub iat: u64,
    pub max_hops: u8,
    pub disclosures: BTreeMap<Digest128, DisclosureRecord>,
}

impl StoredSdJwt {
    /// Renders the SD-JWT to a redacted wire string for a recipient at distance `target_distance`.
    ///
    /// If `self.max_hops < target_distance`, returns `None` (the entire list should be omitted).
    /// Otherwise, only disclosures with `contact_max_hops >= target_distance` are included.
    pub fn to_redacted_wire_string(&self, target_distance: u8) -> Option<String> {
        if self.max_hops < target_distance {
            return None;
        }

        let mut discs: Vec<&str> = self
            .disclosures
            .values()
            .filter(|d| d.contact_max_hops >= target_distance)
            .map(|d| d.raw_b64.as_str())
            .collect();

        if discs.is_empty() {
            Some(format!("{}~", self.jws_compact))
        } else {
            discs.sort();
            Some(format!("{}~{}~", self.jws_compact, discs.join("~")))
        }
    }

    /// Computes a deterministic 64-bit fingerprint of all disclosures disclosed at `target_distance`.
    pub fn disclosure_fingerprint(&self, target_distance: u8) -> u64 {
        if self.max_hops < target_distance {
            return 0;
        }

        let mut digests: Vec<&Digest128> = self
            .disclosures
            .iter()
            .filter(|(_, d)| d.contact_max_hops >= target_distance)
            .map(|(k, _)| k)
            .collect();

        if digests.is_empty() {
            return 0;
        }

        digests.sort();
        let mut hasher = Sha256::new();
        for d in digests {
            hasher.update(d.as_bytes());
            hasher.update(b"\n");
        }
        let hash = hasher.finalize();
        u64::from_be_bytes(hash[0..8].try_into().expect("Slice of 8 bytes"))
    }
}

/// Helper to compute 128-bit truncated SHA-256 digest from raw Base64URL string.
pub fn compute_digest128(raw_b64: &str) -> Digest128 {
    let hash = Sha256::digest(raw_b64.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[0..16])
}

/// Helper to build a disclosure raw Base64 string and its 128-bit digest.
pub fn encode_disclosure(
    salt_bytes: &[u8],
    target_did: &str,
    level: u8,
    contact_max_hops: u8,
) -> Result<(String, Digest128), WotError> {
    if salt_bytes.len() < 16 {
        return Err(WotError::MalformedSdJwt(
            "Salt must be at least 16 bytes".to_string(),
        ));
    }
    let salt_b64 = URL_SAFE_NO_PAD.encode(salt_bytes);
    let json_str = serde_json::to_string(&(&salt_b64, target_did, level, contact_max_hops))?;
    let raw_b64 = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
    let digest = compute_digest128(&raw_b64);
    Ok((raw_b64, digest))
}

/// Creates and signs a new SD-JWT trust list using the provided signer.
pub fn create_and_sign_sd_jwt<S: WotSigner>(
    signer: &S,
    v: u64,
    iat: u64,
    max_hops: u8,
    contacts: &[(Did, u8, u8)], // (target_did, level, contact_max_hops)
) -> Result<(String, StoredSdJwt), WotError> {
    let canonical_iss = canonicalize_did(signer.did())?;

    if !(1..=8).contains(&max_hops) {
        return Err(WotError::InvalidHopLimit(max_hops));
    }

    if contacts.len() > MAX_SD_ENTRIES {
        return Err(WotError::LimitExceeded(
            "Too many contacts for SD-JWT".to_string(),
        ));
    }

    let mut disclosures = BTreeMap::new();
    let mut sd_digests = Vec::new();
    let mut seen_targets = HashSet::new();

    for (target_did, level, contact_max_hops) in contacts {
        let canonical_target = canonicalize_did(target_did)?;
        if canonical_target == canonical_iss {
            return Err(WotError::SelfTrustForbidden);
        }
        if !seen_targets.insert(canonical_target.clone()) {
            return Err(WotError::MalformedSdJwt(
                "Duplicate target DID in contacts".to_string(),
            ));
        }
        if *level > 3 {
            return Err(WotError::InvalidTrustLevel(*level));
        }
        if *contact_max_hops > 8 {
            return Err(WotError::InvalidHopLimit(*contact_max_hops));
        }

        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);

        let (raw_b64, digest) =
            encode_disclosure(&salt_bytes, &canonical_target, *level, *contact_max_hops)?;
        sd_digests.push(digest.clone());
        disclosures.insert(
            digest,
            DisclosureRecord {
                raw_b64,
                target_did: canonical_target,
                level: *level,
                contact_max_hops: *contact_max_hops,
            },
        );
    }

    // Pad with decoy digests to next multiple of DECOY_BUCKET_MULTIPLE (at least 8)
    let num_real = sd_digests.len();
    let target_len = std::cmp::max(
        DECOY_BUCKET_MULTIPLE,
        num_real.div_ceil(DECOY_BUCKET_MULTIPLE) * DECOY_BUCKET_MULTIPLE,
    );

    let mut existing_digests: HashSet<String> = sd_digests.iter().cloned().collect();
    while sd_digests.len() < target_len {
        let mut decoy_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut decoy_bytes);
        let decoy_digest = URL_SAFE_NO_PAD.encode(decoy_bytes);
        if existing_digests.insert(decoy_digest.clone()) {
            sd_digests.push(decoy_digest);
        }
    }

    sd_digests.sort();

    let header = SdJwtHeader {
        alg: SD_JWT_ALG.to_string(),
        typ: SD_JWT_TYP.to_string(),
    };
    let payload = SdJwtPayload {
        iss: canonical_iss.clone(),
        v,
        iat,
        max_hops,
        _sd: sd_digests,
    };

    let header_json = serde_json::to_string(&header)?;
    let payload_json = serde_json::to_string(&payload)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig_bytes = signer.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    let jws_compact = format!("{}.{}", signing_input, sig_b64);

    let mut raw_discs: Vec<String> = disclosures.values().map(|d| d.raw_b64.clone()).collect();
    raw_discs.sort();

    let wire_string = if raw_discs.is_empty() {
        format!("{}~", jws_compact)
    } else {
        format!("{}~{}~", jws_compact, raw_discs.join("~"))
    };

    let stored = StoredSdJwt {
        jws_compact,
        v,
        iat,
        max_hops,
        disclosures,
    };

    Ok((wire_string, stored))
}

/// Parses and cryptographically verifies an incoming SD-JWT wire string.
pub fn parse_and_verify_sd_jwt(raw: &str, now_secs: u64) -> Result<(Did, StoredSdJwt), WotError> {
    if raw.len() > MAX_SD_JWT_RAW_LEN {
        return Err(WotError::LimitExceeded(
            "SD-JWT raw length exceeded".to_string(),
        ));
    }

    let parts: Vec<&str> = raw.split('~').collect();
    if parts.is_empty() {
        return Err(WotError::MalformedSdJwt("Empty SD-JWT".to_string()));
    }

    let jws_compact = parts[0];
    let jws_parts: Vec<&str> = jws_compact.split('.').collect();
    if jws_parts.len() != 3 {
        return Err(WotError::MalformedSdJwt(
            "Invalid JWS compact structure".to_string(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(jws_parts[0])
        .map_err(|e| WotError::MalformedSdJwt(format!("Header base64 decode error: {e}")))?;
    let header: SdJwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| WotError::MalformedSdJwt(format!("Header JSON error: {e}")))?;

    if header.alg != SD_JWT_ALG || header.typ != SD_JWT_TYP {
        return Err(WotError::MalformedSdJwt(
            "Unsupported alg or typ".to_string(),
        ));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(jws_parts[1])
        .map_err(|e| WotError::MalformedSdJwt(format!("Payload base64 decode error: {e}")))?;
    let payload: SdJwtPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| WotError::MalformedSdJwt(format!("Payload JSON error: {e}")))?;

    if payload._sd.len() > MAX_SD_ENTRIES {
        return Err(WotError::LimitExceeded(
            "Too many entries in _sd".to_string(),
        ));
    }

    let mut unique_sd = HashSet::with_capacity(payload._sd.len());
    for d in &payload._sd {
        if !unique_sd.insert(d.clone()) {
            return Err(WotError::MalformedSdJwt(
                "Duplicate digest in _sd".to_string(),
            ));
        }
    }

    if !(1..=8).contains(&payload.max_hops) {
        return Err(WotError::InvalidHopLimit(payload.max_hops));
    }

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

    let canonical_iss = canonicalize_did(&payload.iss)?;
    if canonical_iss != payload.iss {
        return Err(WotError::InvalidDid(
            "Issuer DID not in canonical form".to_string(),
        ));
    }

    let vk = extract_verifying_key(&canonical_iss)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(jws_parts[2])
        .map_err(|_| WotError::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(WotError::InvalidSignature);
    }
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| WotError::InvalidSignature)?,
    );

    let signing_input = format!("{}.{}", jws_parts[0], jws_parts[1]);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| WotError::InvalidSignature)?;

    let mut disclosures = BTreeMap::new();
    let mut seen_targets = HashSet::new();

    // The remaining parts are raw Base64 disclosures (skipping trailing empty string if raw ended with '~')
    for raw_disc in parts[1..].iter() {
        if raw_disc.is_empty() {
            continue;
        }

        let digest = compute_digest128(raw_disc);
        if !unique_sd.contains(&digest) {
            return Err(WotError::MalformedSdJwt(
                "Disclosure digest not present in _sd".to_string(),
            ));
        }

        if disclosures.contains_key(&digest) {
            return Err(WotError::MalformedSdJwt(
                "Duplicate disclosure token in SD-JWT".to_string(),
            ));
        }

        let disc_bytes = URL_SAFE_NO_PAD.decode(raw_disc).map_err(|e| {
            WotError::MalformedSdJwt(format!("Disclosure base64 decode error: {e}"))
        })?;

        let tuple: (String, String, u8, u8) = serde_json::from_slice(&disc_bytes)
            .map_err(|e| WotError::MalformedSdJwt(format!("Disclosure JSON array error: {e}")))?;

        let (salt_b64, target_did, level, contact_max_hops) = tuple;

        let salt_bytes = URL_SAFE_NO_PAD
            .decode(&salt_b64)
            .map_err(|e| WotError::MalformedSdJwt(format!("Salt base64 decode error: {e}")))?;
        if salt_bytes.len() < 16 {
            return Err(WotError::MalformedSdJwt(
                "Salt must be at least 16 bytes".to_string(),
            ));
        }

        let canonical_target = canonicalize_did(&target_did)?;
        if canonical_target != target_did {
            return Err(WotError::InvalidDid(
                "Target DID not in canonical form".to_string(),
            ));
        }
        if canonical_target == canonical_iss {
            return Err(WotError::SelfTrustForbidden);
        }
        if !seen_targets.insert(canonical_target.clone()) {
            return Err(WotError::MalformedSdJwt(
                "Duplicate target DID in disclosures".to_string(),
            ));
        }

        if level > 3 {
            return Err(WotError::InvalidTrustLevel(level));
        }
        if contact_max_hops > 8 {
            return Err(WotError::InvalidHopLimit(contact_max_hops));
        }

        disclosures.insert(
            digest,
            DisclosureRecord {
                raw_b64: (*raw_disc).to_string(),
                target_did: canonical_target,
                level,
                contact_max_hops,
            },
        );
    }

    Ok((
        canonical_iss,
        StoredSdJwt {
            jws_compact: jws_compact.to_string(),
            v: payload.v,
            iat: payload.iat,
            max_hops: payload.max_hops,
            disclosures,
        },
    ))
}
