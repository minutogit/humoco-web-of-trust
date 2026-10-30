use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use crate::error::WotError;

/// Canonical did:key identifier string (e.g. "did:key:z6Mku...").
pub type Did = String;

/// 22-character Base64URL string representing a 128-bit SHA-256 digest.
pub type Digest128 = String;

/// Canonicalizes a DID string, stripping optional allowed prefixes like `alice:chk@`.
///
/// Rules:
/// - Outer whitespaces are trimmed; internal whitespaces are strictly rejected.
/// - If `@` is present, there must be exactly one `@`.
/// - The prefix before `@` must not be empty and must consist only of lowercase ASCII letters,
///   digits, hyphens, and colons (`a-z`, `0-9`, `-`, `:`).
/// - The DID part must start with `"did:key:z"`.
/// - The payload after `"did:key:z"` must be valid Base58 decoding to exactly 34 bytes.
/// - The first two bytes must be `[0xed, 0x01]` (Ed25519 Multicodec).
/// - The 32-byte public key must not be a weak key.
/// - Re-encoding to Base58 must match the input string exactly (canonical encoding check).
pub fn canonicalize_did(input: &str) -> Result<Did, WotError> {
    let trimmed = input.trim();
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(WotError::InvalidDid(input.to_string()));
    }

    let did_part = if trimmed.contains('@') {
        let parts: Vec<&str> = trimmed.split('@').collect();
        if parts.len() != 2 {
            return Err(WotError::InvalidDid(input.to_string()));
        }
        let prefix = parts[0];
        if prefix.is_empty() {
            return Err(WotError::InvalidDid(input.to_string()));
        }
        if !prefix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == ':') {
            return Err(WotError::InvalidDid(input.to_string()));
        }
        parts[1]
    } else {
        trimmed
    };

    let raw_b58 = did_part
        .strip_prefix("did:key:z")
        .ok_or_else(|| WotError::InvalidDid(input.to_string()))?;

    if raw_b58.is_empty() {
        return Err(WotError::InvalidDid(input.to_string()));
    }

    let decoded_bytes = bs58::decode(raw_b58)
        .into_vec()
        .map_err(|_| WotError::InvalidDid(input.to_string()))?;

    if decoded_bytes.len() != 34 || decoded_bytes[0..2] != [0xed, 0x01] {
        return Err(WotError::InvalidDid(input.to_string()));
    }

    let vk_bytes: [u8; 32] = decoded_bytes[2..34]
        .try_into()
        .map_err(|_| WotError::InvalidDid(input.to_string()))?;

    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| WotError::InvalidDid(input.to_string()))?;
    if vk.is_weak() {
        return Err(WotError::WeakPublicKey);
    }

    let canonical_b58 = bs58::encode(&decoded_bytes).into_string();
    if canonical_b58 != raw_b58 {
        return Err(WotError::InvalidDid("Non-canonical base58 encoding".to_string()));
    }

    Ok(format!("did:key:z{}", canonical_b58))
}

/// Extracts an Ed25519 `VerifyingKey` from a canonical or prefixed DID string.
pub fn extract_verifying_key(did_or_user_id: &str) -> Result<VerifyingKey, WotError> {
    let canonical = canonicalize_did(did_or_user_id)?;
    let raw_b58 = canonical
        .strip_prefix("did:key:z")
        .ok_or_else(|| WotError::InvalidDid(did_or_user_id.to_string()))?;

    let decoded_bytes = bs58::decode(raw_b58)
        .into_vec()
        .map_err(|_| WotError::InvalidDid(did_or_user_id.to_string()))?;

    let vk_bytes: [u8; 32] = decoded_bytes[2..34]
        .try_into()
        .map_err(|_| WotError::InvalidDid(did_or_user_id.to_string()))?;

    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| WotError::InvalidDid(did_or_user_id.to_string()))?;
    if vk.is_weak() {
        return Err(WotError::WeakPublicKey);
    }

    Ok(vk)
}

/// Computes the canonical `did:key:z...` string from an Ed25519 `VerifyingKey`.
pub fn did_from_verifying_key(vk: &VerifyingKey) -> Result<Did, WotError> {
    if vk.is_weak() {
        return Err(WotError::WeakPublicKey);
    }

    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(vk.as_bytes());

    Ok(format!("did:key:z{}", bs58::encode(&bytes).into_string()))
}

/// Abstract signer trait for signing Web of Trust documents.
pub trait WotSigner {
    /// Returns the canonical DID of the signer.
    fn did(&self) -> &str;

    /// Signs the given message bytes, returning a 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// Ed25519-dalek implementation of `WotSigner`.
pub struct Ed25519WotSigner {
    signing_key: SigningKey,
    did: Did,
}

impl Ed25519WotSigner {
    /// Creates a new `Ed25519WotSigner` from an Ed25519 `SigningKey`.
    pub fn new(signing_key: SigningKey) -> Result<Self, WotError> {
        let vk = signing_key.verifying_key();
        let did = did_from_verifying_key(&vk)?;
        Ok(Self { signing_key, did })
    }

    /// Accessor to the underlying `SigningKey`.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl WotSigner for Ed25519WotSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}
