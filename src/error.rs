use thiserror::Error;

/// Errors that can occur within the Web of Trust library.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum WotError {
    /// The DID format is invalid or cannot be canonicalized.
    #[error("Invalid DID: {0}")]
    InvalidDid(String),

    /// The public key is weak or vulnerable to low-order group attacks.
    #[error("Weak public key")]
    WeakPublicKey,

    /// The cryptographic signature could not be verified.
    #[error("Invalid signature")]
    InvalidSignature,

    /// The signer DID does not match the expected issuer DID.
    #[error("Signer mismatch: expected {expected}, actual {actual}")]
    SignerMismatch {
        expected: String,
        actual: String,
    },

    /// The SD-JWT string or structure is malformed.
    #[error("Malformed SD-JWT: {0}")]
    MalformedSdJwt(String),

    /// An invalid trust level was specified (must be between 0 and 3).
    #[error("Invalid trust level: {0}")]
    InvalidTrustLevel(u8),

    /// An invalid hop limit was specified (must be between 1 and 8).
    #[error("Invalid hop limit: {0}")]
    InvalidHopLimit(u8),

    /// Trusting oneself is forbidden.
    #[error("Self trust forbidden")]
    SelfTrustForbidden,

    /// A timestamp claim lies too far in the future compared to the reference time.
    #[error("Future timestamp detected: claim_secs={claim_secs}, now_secs={now_secs}")]
    FutureTimestamp {
        claim_secs: u64,
        now_secs: u64,
    },

    /// The issuer signed conflicting lists for the exact same version number.
    #[error("Equivocation detected for issuer {issuer} at version {version}")]
    EquivocationDetected {
        issuer: String,
        version: u64,
    },

    /// A resource or security limit was exceeded.
    #[error("Limit exceeded: {0}")]
    LimitExceeded(String),

    /// Failure to serialize or deserialize data structures.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for WotError {
    fn from(err: serde_json::Error) -> Self {
        WotError::Serialization(err.to_string())
    }
}
