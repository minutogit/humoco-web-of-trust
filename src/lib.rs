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
pub mod successor_and_offenders;
pub mod sync;

pub use error::WotError;
pub use graph::{EgoGraphCache, GraphEdge, level_to_factor};
pub use identity::{
    Did, Digest128, Ed25519WotSigner, WotSigner, canonicalize_did, did_from_verifying_key,
    extract_verifying_key,
};
pub use provider_filter::{
    BinaryFuse64, EncodedBinaryFuse64, MAX_PROVIDER_FILTER_RAW_LEN, PROVIDER_FILTER_TYP,
    ProviderFilterPayload, SignedProviderFilter, StoredProviderFilter,
    create_and_sign_provider_filter, hash_member_did, mix64, parse_and_verify_provider_filter,
};
pub use register::{OwnTrustEntry, SentRecord, TrustRegister, WotPolicy};
pub use scorer::{
    MAX_CANDIDATE_PATHS, MIN_PATH_PROBABILITY, TrustEvaluation, TrustPath, evaluate_trust,
    evaluate_trust_from_observer, evaluate_trust_with_providers, exact_path_union_prob,
};
pub use sd_jwt::{
    DECOY_BUCKET_MULTIPLE, DisclosureRecord, MAX_CLOCK_SKEW_SECS, MAX_SD_ENTRIES,
    MAX_SD_JWT_RAW_LEN, MAX_VERSION_AHEAD_SECS, SD_JWT_ALG, SD_JWT_TYP, SdJwtHeader, SdJwtPayload,
    StoredSdJwt, compute_digest128, create_and_sign_sd_jwt, encode_disclosure,
    parse_and_verify_sd_jwt,
};
pub use successor_and_offenders::{
    KEY_SUCCESSOR_DOMAIN, KeyRotationReason, KeySuccessorAttestation, LOCK_RECEIPT_DOMAIN,
    MAX_SUCCESSOR_CHAIN_LEN, SERVER_OFFENDER_FILTER_DOMAIN, SERVER_OFFENDERS_TYP,
    ServerOffenderList, ServerOffenderRecord, WotEquivocationProof, WotLockDelegation,
    WotLockReceipt, WotLockReceiptKind, resolve_successor_chain,
};
pub use sync::{
    DropClassReceipt, DropClassSubpackage, DropSentRecord, DropSyncReceipt, ImportStats,
    SyncReceipt, SyncReceiptEntry, WotSyncPackage, compute_readers_fingerprint,
    peek_unverified_issuer,
};
