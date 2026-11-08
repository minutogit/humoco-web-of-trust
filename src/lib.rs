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
pub mod provider_filter;
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
pub use provider_filter::{
    create_and_sign_provider_filter, hash_member_did, mix64, parse_and_verify_provider_filter,
    BinaryFuse64, EncodedBinaryFuse64, ProviderFilterPayload, SignedProviderFilter,
    StoredProviderFilter, MAX_PROVIDER_FILTER_RAW_LEN, PROVIDER_FILTER_TYP,
};
pub use register::{OwnTrustEntry, SentRecord, TrustRegister, WotPolicy};
pub use scorer::{
    evaluate_trust, evaluate_trust_from_observer, evaluate_trust_with_providers,
    exact_path_union_prob, TrustEvaluation, TrustPath, MAX_CANDIDATE_PATHS, MIN_PATH_PROBABILITY,
};
pub use sd_jwt::{
    compute_digest128, create_and_sign_sd_jwt, encode_disclosure, parse_and_verify_sd_jwt,
    DisclosureRecord, SdJwtHeader, SdJwtPayload, StoredSdJwt, DECOY_BUCKET_MULTIPLE,
    MAX_CLOCK_SKEW_SECS, MAX_SD_ENTRIES, MAX_SD_JWT_RAW_LEN, MAX_VERSION_AHEAD_SECS, SD_JWT_ALG,
    SD_JWT_TYP,
};
pub use sync::{
    compute_readers_fingerprint, peek_unverified_issuer, DropClassReceipt, DropClassSubpackage,
    DropSentRecord, DropSyncReceipt, ImportStats, SyncReceipt, SyncReceiptEntry, WotSyncPackage,
};
