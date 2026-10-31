#![forbid(unsafe_code)]
//! # humoco-wot
//!
//! Subjective, offline-first Web of Trust library for the HuMoCo ecosystem.
//!
//! Features:
//! - 128-bit truncated SD-JWT trust lists (IETF RFC 9901 compliant).
//! - Shannon factoring path evaluation (preventing Sybil bottleneck over-counting).
//! - Reciprocal Tit-for-Tat routing and distance-based disclosure redaction.
//! - Two-phase gossip synchronization with topological reachability spam filtering.

pub mod error;
pub mod graph;
pub mod identity;
pub mod register;
pub mod scorer;
pub mod sd_jwt;
pub mod sync;

pub use error::WotError;
pub use graph::{level_to_factor, EgoGraphCache, GraphEdge};
pub use identity::{
    canonicalize_did, did_from_verifying_key, extract_verifying_key, Did, Digest128,
    Ed25519WotSigner, WotSigner,
};
pub use register::{OwnTrustEntry, SentRecord, TrustRegister, WotPolicy};
pub use scorer::{
    evaluate_trust, evaluate_trust_from_observer, exact_path_union_prob, TrustEvaluation,
    TrustPath, MAX_CANDIDATE_PATHS, MIN_PATH_PROBABILITY,
};
pub use sd_jwt::{
    compute_digest128, create_and_sign_sd_jwt, encode_disclosure, parse_and_verify_sd_jwt,
    DisclosureRecord, SdJwtHeader, SdJwtPayload, StoredSdJwt, DECOY_BUCKET_MULTIPLE,
    MAX_CLOCK_SKEW_SECS, MAX_SD_ENTRIES, MAX_SD_JWT_RAW_LEN, MAX_VERSION_AHEAD_SECS, SD_JWT_ALG,
    SD_JWT_TYP,
};
pub use sync::{
    peek_unverified_issuer, ImportStats, SyncReceipt, SyncReceiptEntry, WotSyncPackage,
};
