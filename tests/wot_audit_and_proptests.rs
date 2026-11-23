use std::collections::{BTreeMap, HashSet, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use humoco_wot::successor_and_offenders::LOCK_DELEGATE_PREFIX;
use humoco_wot::{
    BinaryFuse64, Did, Ed25519WotSigner, EgoGraphCache, EncodedBinaryFuse64, KEY_SUCCESSOR_DOMAIN,
    KeyRotationReason, KeySuccessorAttestation, LOCK_RECEIPT_DOMAIN, MAX_CLOCK_SKEW_SECS,
    MAX_PROVIDER_FILTER_RAW_LEN, MAX_SD_ENTRIES, MAX_SD_JWT_RAW_LEN, MAX_VERSION_AHEAD_SECS,
    PROVIDER_FILTER_TYP, ProviderFilterPayload, SD_JWT_ALG, SD_JWT_TYP, SdJwtHeader, SdJwtPayload,
    ServerOffenderList, ServerOffenderRecord, SignedProviderFilter, TrustRegister,
    WotEquivocationProof, WotError, WotLockDelegation, WotLockReceipt, WotLockReceiptKind,
    WotPolicy, WotSigner, WotSyncPackage, canonicalize_did, compute_digest128,
    create_and_sign_provider_filter, create_and_sign_sd_jwt, did_from_verifying_key,
    encode_disclosure, evaluate_trust, exact_path_union_prob, hash_member_did, mix64,
    parse_and_verify_provider_filter, parse_and_verify_sd_jwt, peek_unverified_issuer,
};
use proptest::prelude::*;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

fn make_identity() -> (Ed25519WotSigner, Did) {
    let sk = SigningKey::generate(&mut OsRng);
    let signer = Ed25519WotSigner::new(sk).expect("valid Ed25519 signer");
    let did = signer.did().to_string();
    (signer, did)
}

fn deterministic_did(seed: u8) -> Did {
    let sk = SigningKey::from_bytes(&[seed.max(1); 32]);
    did_from_verifying_key(&sk.verifying_key()).expect("valid deterministic key")
}

/// Exact O(2^E) two-terminal reliability oracle over active directed edges on `0..num_nodes`.
fn brute_force_reliability(
    num_nodes: usize,
    edges: &[(u32, u32, f64)],
    start: u32,
    target: u32,
    max_hops: usize,
) -> f64 {
    assert!(edges.len() <= 12, "brute force oracle bound");
    if start == target {
        return 1.0;
    }
    let m = edges.len();
    let mut total_prob = 0.0;

    for mask in 0..(1usize << m) {
        let mut mask_prob = 1.0;
        let mut adj = vec![Vec::new(); num_nodes];
        for (i, &(u, v, p)) in edges.iter().enumerate() {
            if (mask >> i) & 1 == 1 {
                mask_prob *= p;
                adj[u as usize].push(v);
            } else {
                mask_prob *= 1.0 - p;
            }
        }
        if mask_prob == 0.0 {
            continue;
        }
        // Check reachability within `max_hops`
        let mut dist = vec![usize::MAX; num_nodes];
        let mut q = VecDeque::new();
        dist[start as usize] = 0;
        q.push_back(start);
        while let Some(curr) = q.pop_front() {
            let d = dist[curr as usize];
            if d >= max_hops {
                continue;
            }
            for &next in &adj[curr as usize] {
                if dist[next as usize] == usize::MAX {
                    dist[next as usize] = d + 1;
                    q.push_back(next);
                }
            }
        }
        if dist[target as usize] <= max_hops {
            total_prob += mask_prob;
        }
    }
    total_prob.clamp(0.0, 1.0)
}

fn make_signed_receipt(
    sk: &SigningKey,
    kind: WotLockReceiptKind,
    slot: [u8; 32],
    child_lock: [u8; 32],
    entry_hash: [u8; 32],
    write_seq: u64,
) -> WotLockReceipt {
    let mut r = WotLockReceipt {
        kind,
        lock_pub: sk.verifying_key().to_bytes(),
        bucket: [0x11; 32],
        slot,
        child_lock,
        entry_hash,
        retain_until_quarter: 8060,
        write_seq,
        bucket_head: [0x44; 32],
        recipient_nonce: [write_seq as u8; 32],
        sig: [0; 64],
    };
    r.sig = sk.sign(&r.digest()).to_bytes();
    r
}

fn sign_custom_sd_jwt(
    signer: &Ed25519WotSigner,
    header: &SdJwtHeader,
    payload: &SdJwtPayload,
    raw_disclosures: &[String],
) -> String {
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let p_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signer.sign(signing_input.as_bytes()));
    let jws = format!("{}.{}", signing_input, sig_b64);
    if raw_disclosures.is_empty() {
        format!("{}~", jws)
    } else {
        format!("{}~{}~", jws, raw_disclosures.join("~"))
    }
}

fn sign_custom_provider_filter(
    signer: &Ed25519WotSigner,
    payload: &ProviderFilterPayload,
) -> String {
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signer.sign(payload_b64.as_bytes()));
    let signed = SignedProviderFilter {
        typ: PROVIDER_FILTER_TYP.to_string(),
        payload_b64,
        signature_b64: sig_b64,
    };
    serde_json::to_string(&signed).unwrap()
}

// =========================================================================
// Regression Tests for WOT-F1 .. WOT-F7
// =========================================================================

#[test]
fn test_wot_f1_binary_fuse64_rejects_malformed_params_and_never_panics() {
    let valid_filter = BinaryFuse64::build(&[10, 20, 30]).expect("valid filter");
    let valid_enc = valid_filter.encode();

    // 1. Non-power-of-two segment_length
    let mut bad = valid_enc.clone();
    bad.segment_length = 30;
    bad.segment_length_mask = 29;
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 2. Wrong segment_length_mask
    let mut bad = valid_enc.clone();
    bad.segment_length_mask = 30;
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 3. segment_count_length not a multiple of segment_length
    let mut bad = valid_enc.clone();
    bad.segment_count_length = 48;
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 4. Oversized segment_count_length causing OOB in naive contains()
    let mut bad = valid_enc.clone();
    bad.segment_count_length = 1_048_576;
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 5. Empty fingerprints with non-zero metadata
    let bad = EncodedBinaryFuse64 {
        seed: 0,
        segment_length: 32,
        segment_length_mask: 31,
        segment_count_length: 64,
        fingerprints_b64: String::new(),
    };
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 6. Non-empty fingerprints with mismatched segment_count_length == 0
    let mut bad = valid_enc.clone();
    bad.segment_count_length = 0;
    assert!(BinaryFuse64::decode(&bad).is_err());

    // 7. Corrupted deserialized BinaryFuse64::contains() must fail safely (false, no panic)
    let corrupted = BinaryFuse64 {
        seed: 42,
        segment_length: 32,
        segment_length_mask: 31,
        segment_count_length: 1_000_000,
        fingerprints: vec![1, 2, 3, 4],
    };
    assert!(!corrupted.contains(12345));

    let non_pow2 = BinaryFuse64 {
        seed: 42,
        segment_length: 3,
        segment_length_mask: 2,
        segment_count_length: 6,
        fingerprints: vec![0; 12],
    };
    assert!(!non_pow2.contains(12345));

    // Empty fingerprints with non-zero segment_length also returns false safely
    let empty_dirty = BinaryFuse64 {
        seed: 0,
        segment_length: 32,
        segment_length_mask: 31,
        segment_count_length: 64,
        fingerprints: Vec::new(),
    };
    assert!(!empty_dirty.contains(0));
}

#[test]
fn test_wot_f2_binary_fuse64_medium_and_boundary_sizes() {
    for &size in &[0usize, 1, 64, 65, 92, 128, 193, 200, 250, 500, 1000] {
        let keys: Vec<u64> = (0..size as u64).map(|i| mix64(i * 97 + 13)).collect();
        let filter = BinaryFuse64::build(&keys)
            .unwrap_or_else(|e| panic!("BinaryFuse64::build failed at size {size}: {e}"));
        let encoded = filter.encode();
        let decoded = BinaryFuse64::decode(&encoded)
            .unwrap_or_else(|e| panic!("BinaryFuse64::decode failed at size {size}: {e}"));
        assert_eq!(filter, decoded);

        for &k in &keys {
            assert!(decoded.contains(k), "False negative at size {size}");
        }
        for j in 0..200u64 {
            let non_member = mix64((size as u64 + 10_000 + j) * 131 + 7);
            assert!(
                !decoded.contains(non_member),
                "Unexpected false positive at size {size}"
            );
        }
    }
}

#[test]
fn test_wot_f3_sybil_clique_dos_bounded_and_guarantor_clears_stale_iat() {
    let (signer_me, did_me) = make_identity();
    let (signer_bob, did_bob) = make_identity();
    let (_, did_target) = make_identity();
    let now_secs = 1_750_000_000u64;

    // 1. Dead-end 60-node fully-connected level-3 Sybil clique behind 1 direct contact
    let clique: Vec<(Ed25519WotSigner, Did)> = (0..60).map(|_| make_identity()).collect();
    let clique_dids: Vec<Did> = clique.iter().map(|(_, d)| d.clone()).collect();

    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    reg.set_own_list_max_hops(3, now_secs).unwrap();
    reg.set_contact_trust(&did_bob, 1, 3, now_secs).unwrap();
    reg.ensure_own_list_signed(&signer_me, now_secs).unwrap();

    let bob_contacts: Vec<(Did, u8, u8)> = clique_dids.iter().map(|d| (d.clone(), 3, 3)).collect();
    let (wire_bob, _) = create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 3, &bob_contacts).unwrap();

    let mut clique_wires = Vec::with_capacity(clique.len() + 1);
    clique_wires.push(wire_bob);
    for (i, (sk, _)) in clique.iter().enumerate() {
        let mut peers: Vec<(Did, u8, u8)> = clique_dids
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, d)| (d.clone(), 3, 3))
            .collect();
        // First 5 clique members also connect to target
        if i < 5 {
            peers.push((did_target.clone(), 3, 3));
        }
        let (w, _) = create_and_sign_sd_jwt(sk, 1, now_secs, 3, &peers).unwrap();
        clique_wires.push(w);
    }

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: clique_wires,
        },
        Some(&did_bob),
        now_secs,
    )
    .unwrap();

    // Connected target: completes immediately without exponential DFS blowup, bounded by Bob's 0.30 bottleneck
    let eval_connected = reg.evaluate_did(&did_target, Some(now_secs)).unwrap();
    assert!(eval_connected.score > 0.0);
    assert!(
        eval_connected.score <= 0.300001,
        "Bottleneck exceeded: {}",
        eval_connected.score
    );

    // Unreachable target behind clique: instant O(V+E) reverse-BFS rejection
    let (_, did_unreachable) = make_identity();
    let eval_unreachable = reg.evaluate_did(&did_unreachable, Some(now_secs)).unwrap();
    assert_eq!(eval_unreachable.score, 0.0);
    assert!(eval_unreachable.shortest_hops.is_none());

    // 2. Live guarantor upgrade clears stale third-party `list_iat` on the upgraded edge
    let mut reg2 = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    let old_iat = now_secs - 3 * 31_536_000; // 3 years old (2 years excess after 1-year grace -> 0.25 decay)
    reg2.set_contact_trust(&did_bob, 3, 3, now_secs).unwrap();
    let (wire_bob_old, _) =
        create_and_sign_sd_jwt(&signer_bob, 1, old_iat, 3, &[(did_target.clone(), 2, 3)]).unwrap();
    reg2.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_bob_old],
        },
        Some(&did_bob),
        now_secs,
    )
    .unwrap();

    // Without guarantor: Bob -> Target uses Bob's decayed old list edge (0.60 * 0.25 = 0.15)
    let without_g = reg2.evaluate_did(&did_target, Some(now_secs)).unwrap();
    assert_eq!(without_g.oldest_list_iat, Some(old_iat));
    assert!((without_g.score - 0.85 * 0.15).abs() < 1e-6);

    // With Bob acting as live guarantor (0.85 > decayed edge): upgrades edge AND clears stale iat
    let with_g = reg2
        .evaluate_voucher(&did_target, &[&did_bob], false, Some(now_secs))
        .unwrap();
    assert!((with_g.score - 0.85 * 0.85).abs() < 1e-6);
    assert_eq!(with_g.oldest_list_iat, None);
}

#[test]
fn test_wot_f4_equivocation_entry_hash_only_and_signature_verification() {
    let lock_sk = SigningKey::generate(&mut OsRng);
    let slot = [0x22; 32];
    let child_a = [0xA1; 32];
    let hash_a = [0x33; 32];
    let hash_b = [0x44; 32];

    let rec_a = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        slot,
        child_a,
        hash_a,
        1,
    );
    let rec_b_diff_hash = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        slot,
        child_a,
        hash_b,
        2,
    );
    let rec_b_identical = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        slot,
        child_a,
        hash_a,
        2,
    );
    let rec_b_diff_slot = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        [0x99; 32],
        [0xB2; 32],
        hash_b,
        2,
    );

    // 1. Same child_lock + distinct entry_hash MUST verify (parity with humoco-proto)
    let proof_entry_hash = WotEquivocationProof {
        receipt_a: rec_a.clone(),
        receipt_b: rec_b_diff_hash,
    };
    assert_eq!(
        proof_entry_hash.verify().unwrap(),
        lock_sk.verifying_key().to_bytes()
    );

    let mut list = ServerOffenderList::new();
    list.insert_verified(
        ServerOffenderRecord {
            proof: proof_entry_hash,
            delegation: None,
            recorded_at: 1_795_000_000,
        },
        1_795_000_000,
    )
    .expect("entry_hash-only equivocation must insert cleanly");
    assert!(list.is_lock_pub_revoked(&lock_sk.verifying_key().to_bytes()));

    // 2. Identical child_lock AND identical entry_hash MUST be rejected
    let non_conflicting = WotEquivocationProof {
        receipt_a: rec_a.clone(),
        receipt_b: rec_b_identical,
    };
    assert_eq!(non_conflicting.verify(), Err(WotError::InvalidSignature));

    // 3. Differing slot MUST be rejected
    let wrong_slot = WotEquivocationProof {
        receipt_a: rec_a.clone(),
        receipt_b: rec_b_diff_slot,
    };
    assert_eq!(wrong_slot.verify(), Err(WotError::InvalidSignature));

    // 4. Forged receipt_a OR receipt_b signature MUST be rejected
    let mut forged_a = WotEquivocationProof {
        receipt_a: rec_a.clone(),
        receipt_b: make_signed_receipt(
            &lock_sk,
            WotLockReceiptKind::FirstWrite,
            slot,
            [0xB2; 32],
            hash_a,
            2,
        ),
    };
    forged_a.receipt_a.sig[0] ^= 0xFF;
    assert_eq!(forged_a.verify(), Err(WotError::InvalidSignature));

    let mut forged_b = WotEquivocationProof {
        receipt_a: rec_a,
        receipt_b: make_signed_receipt(
            &lock_sk,
            WotLockReceiptKind::FirstWrite,
            slot,
            [0xB2; 32],
            hash_a,
            2,
        ),
    };
    forged_b.receipt_b.sig[63] ^= 0xFF;
    assert_eq!(forged_b.verify(), Err(WotError::InvalidSignature));
}

#[test]
fn test_wot_f5_provider_filter_canonical_iss_and_pretty_json_reimport() {
    let (signer_me, did_me) = make_identity();
    let (signer_prov, did_prov) = make_identity();
    let (_, did_member) = make_identity();
    let now_secs = 1_750_000_000u64;

    // 1. Non-canonical prefixed iss in payload MUST be rejected
    let mut empty_levels = BTreeMap::new();
    let filter = BinaryFuse64::build(&[hash_member_did(&did_prov, 1, 2, &did_member).unwrap()])
        .unwrap()
        .encode();
    empty_levels.insert(2, filter);
    let non_canonical_payload = ProviderFilterPayload {
        typ: PROVIDER_FILTER_TYP.to_string(),
        iss: format!("alice:chk@{}", did_prov),
        name: "NonCanonical".to_string(),
        v: 1,
        iat: now_secs,
        source_url: None,
        member_count: 1,
        level_filters: empty_levels,
    };
    let bad_raw = sign_custom_provider_filter(&signer_prov, &non_canonical_payload);
    assert!(matches!(
        parse_and_verify_provider_filter(&bad_raw, now_secs),
        Err(WotError::InvalidDid(_))
    ));

    // 2. Re-importing identical signed filter with pretty whitespace must NOT trigger EquivocationDetected
    let compact = create_and_sign_provider_filter(
        &signer_prov,
        "Test Verband",
        7,
        now_secs,
        None,
        &[(did_member.clone(), 2)],
    )
    .unwrap();
    let signed_val: SignedProviderFilter = serde_json::from_str(&compact).unwrap();
    let pretty = serde_json::to_string_pretty(&signed_val).unwrap();
    assert_ne!(compact, pretty);

    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    reg.import_provider_filter(&compact, now_secs).unwrap();
    reg.set_provider_trust(&did_prov, 2).unwrap();
    reg.import_provider_filter(&pretty, now_secs)
        .expect("re-importing same signed payload_b64 with whitespace must succeed");
    assert_eq!(
        reg.provider_filters[&did_prov].local_trust_level, 2,
        "local_trust_level must be preserved on idempotent re-import"
    );

    // 3. Different payload at same version v=7 MUST still raise EquivocationDetected
    let (_, did_other) = make_identity();
    let equiv = create_and_sign_provider_filter(
        &signer_prov,
        "Test Verband",
        7,
        now_secs,
        None,
        &[(did_other, 2)],
    )
    .unwrap();
    assert!(matches!(
        reg.import_provider_filter(&equiv, now_secs),
        Err(WotError::EquivocationDetected { .. })
    ));
    let _ = signer_me;
}

#[test]
fn test_wot_f6_key_successor_rejects_non_canonical_dids() {
    let (signer_a, _) = make_identity();
    let (signer_b, _) = make_identity();
    let now_secs = 1_795_000_000u64;

    let valid = KeySuccessorAttestation::sign_dual(
        &signer_a,
        &signer_b,
        KeyRotationReason::Routine,
        None,
        now_secs,
    )
    .unwrap();

    let mut bad_old = valid.clone();
    bad_old.old_did = format!("alias@{}", valid.old_did);
    assert!(matches!(
        bad_old.verify(now_secs),
        Err(WotError::InvalidDid(_))
    ));

    let mut bad_new = valid;
    bad_new.new_did = format!("alias@{}", bad_new.new_did);
    assert!(matches!(
        bad_new.verify(now_secs),
        Err(WotError::InvalidDid(_))
    ));
}

#[test]
fn test_wot_f7_sync_bounds_envelope_max_hops_union_dedup_and_graph_saturation() {
    let (signer_me, did_me) = make_identity();
    let (signer_bob, did_bob) = make_identity();
    let (signer_carol, did_carol) = make_identity();
    let (_, did_dave) = make_identity();
    let (_, did_eve) = make_identity();
    let now_secs = 1_750_000_000u64;

    // 1. Oversized input to peek_unverified_issuer returns None quickly
    let (wire_bob_sample, _) = create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 3, &[]).unwrap();
    let oversized = format!("{wire_bob_sample}~{}", "A".repeat(MAX_SD_JWT_RAW_LEN));
    assert!(oversized.len() > MAX_SD_JWT_RAW_LEN);
    assert_eq!(peek_unverified_issuer(&oversized), None);

    // 2. Envelope max_hops < hop_dist rejected as spam during import
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    reg.set_contact_trust(&did_bob, 2, 3, now_secs).unwrap();
    reg.ensure_own_list_signed(&signer_me, now_secs).unwrap();

    let (wire_bob, _) =
        create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 3, &[(did_carol.clone(), 2, 3)]).unwrap();
    // Carol is at hop_dist = 2, but Carol's envelope declares max_hops = 1 (under-redacted leak!)
    let (wire_carol_leaked, _) =
        create_and_sign_sd_jwt(&signer_carol, 1, now_secs, 1, &[(did_dave.clone(), 2, 3)]).unwrap();

    let stats = reg
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![wire_bob, wire_carol_leaked],
            },
            Some(&did_bob),
            now_secs,
        )
        .unwrap();
    assert_eq!(stats.imported, 1);
    assert_eq!(stats.rejected_spam, 1);
    assert!(!reg.raw_list_store.contains_key(&did_carol));

    // 3. Same-version union merge rejects duplicate target_did under a distinct disclosure digest
    let d1 = encode_disclosure(&[0x11u8; 16], &did_dave, 2, 3).unwrap();
    let d2_dup_dave = encode_disclosure(&[0x22u8; 16], &did_dave, 3, 3).unwrap();
    let d3_eve = encode_disclosure(&[0x33u8; 16], &did_eve, 2, 3).unwrap();
    let payload = SdJwtPayload {
        iss: did_bob.clone(),
        v: 42,
        iat: now_secs,
        max_hops: 3,
        _sd: vec![d1.1.clone(), d2_dup_dave.1.clone(), d3_eve.1.clone()],
    };
    let header = SdJwtHeader {
        alg: SD_JWT_ALG.to_string(),
        typ: SD_JWT_TYP.to_string(),
    };
    let pkg_part1 = sign_custom_sd_jwt(&signer_bob, &header, &payload, &[d1.0]);
    let pkg_part2_dup =
        sign_custom_sd_jwt(&signer_bob, &header, &payload, &[d2_dup_dave.0, d3_eve.0]);

    let s1 = reg
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![pkg_part1],
            },
            Some(&did_bob),
            now_secs,
        )
        .unwrap();
    assert_eq!(s1.updated, 1);

    let s2 = reg
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![pkg_part2_dup],
            },
            Some(&did_bob),
            now_secs,
        )
        .unwrap();
    assert_eq!(s2.rejected_crypto, 1);
    assert_eq!(s2.merged, 1); // Eve merged cleanly, duplicate Dave rejected
    let bob_discs = &reg.raw_list_store[&did_bob].disclosures;
    assert_eq!(bob_discs.len(), 2);
    assert_eq!(bob_discs[&d1.1].level, 2); // Original Dave entry preserved
    assert_eq!(bob_discs[&d3_eve.1].target_did, did_eve);

    // 4. Graph shortest_distances_from_self saturates at u8::MAX on >= 260-hop chain (no overflow/panic)
    let mut long_graph = EgoGraphCache::new(deterministic_did(1));
    let mut prev = 0u32;
    for i in 2..=262usize {
        let next = long_graph.get_or_create_node(&format!("did:key:node{i}"));
        long_graph.add_or_update_edge(prev, next, 2, now_secs);
        prev = next;
    }
    let dists = long_graph.shortest_distances_from_self();
    assert_eq!(dists[&255], 255);
    assert_eq!(dists[&260], 255);

    // 5. encode_disclosure escapes special JSON characters properly
    let (raw_b64, _) = encode_disclosure(&[0xAA; 16], "did:key:\"escaped\"", 1, 2).unwrap();
    let decoded_json = URL_SAFE_NO_PAD.decode(&raw_b64).unwrap();
    let parsed: (String, String, u8, u8) = serde_json::from_slice(&decoded_json).unwrap();
    assert_eq!(parsed.1, "did:key:\"escaped\"");
}

// =========================================================================
// High-Signal Mutant-Killing KAT & Security Boundary Tests
// =========================================================================

#[test]
fn test_wire_kat_lock_receipt_delegation_and_offender_boundaries() {
    let lock_sk = SigningKey::from_bytes(&[0x55; 32]);
    let admin_sk = SigningKey::from_bytes(&[0x66; 32]);
    let other_sk = SigningKey::from_bytes(&[0x77; 32]);
    let lock_pub = lock_sk.verifying_key().to_bytes();
    let admin_pub = admin_sk.verifying_key().to_bytes();
    let other_pub = other_sk.verifying_key().to_bytes();

    // 1. Independent preimage KAT for WotLockReceipt::digest() (both kinds)
    for &(kind, kind_byte) in &[
        (WotLockReceiptKind::FirstWrite, 0u8),
        (WotLockReceiptKind::ConflictSeen, 1u8),
    ] {
        let mut r = WotLockReceipt {
            kind,
            lock_pub,
            bucket: [0x10; 32],
            slot: [0x20; 32],
            child_lock: [0x30; 32],
            entry_hash: [0x40; 32],
            retain_until_quarter: 0x1234,
            write_seq: 0x0102_0304_0506_0708,
            bucket_head: [0x50; 32],
            recipient_nonce: [0x60; 32],
            sig: [0; 64],
        };
        let mut h = Sha256::new();
        h.update(LOCK_RECEIPT_DOMAIN);
        h.update([kind_byte]);
        h.update(r.lock_pub);
        h.update(r.bucket);
        h.update(r.slot);
        h.update(r.child_lock);
        h.update(r.entry_hash);
        h.update(r.retain_until_quarter.to_le_bytes());
        h.update(r.write_seq.to_le_bytes());
        h.update(r.bucket_head);
        h.update(r.recipient_nonce);
        let expected_digest: [u8; 32] = h.finalize().into();

        assert_eq!(r.digest(), expected_digest);
        r.sig = lock_sk.sign(&expected_digest).to_bytes();
        r.verify_signature().expect("valid receipt signature");

        // Tamper every significant field -> verify_signature MUST fail!
        let mut t = r.clone();
        t.sig[0] ^= 1;
        assert_eq!(t.verify_signature(), Err(WotError::InvalidSignature));

        let mut t = r.clone();
        t.slot[0] ^= 1;
        assert_eq!(t.verify_signature(), Err(WotError::InvalidSignature));

        let mut t = r.clone();
        t.child_lock[0] ^= 1;
        assert_eq!(t.verify_signature(), Err(WotError::InvalidSignature));

        let mut t = r.clone();
        t.entry_hash[0] ^= 1;
        assert_eq!(t.verify_signature(), Err(WotError::InvalidSignature));

        let mut t = r.clone();
        t.write_seq += 1;
        assert_eq!(t.verify_signature(), Err(WotError::InvalidSignature));

        // Weak identity/small-order lock_pub MUST return WeakPublicKey
        let mut weak = r.clone();
        weak.lock_pub = [0u8; 32]; // small-order point on curve25519
        assert!(matches!(
            weak.verify_signature(),
            Err(WotError::WeakPublicKey)
        ));
    }

    // 2. Delegation canonical_message KAT + URL validation + weak key checks
    let del = WotLockDelegation {
        admin_pub,
        lock_pub,
        write_url: "https://sync.example.org/write".to_string(),
        read_url: "http://localhost:8080/read".to_string(),
        issued_at: 1_795_000_000,
        sig: [0; 64],
    };
    let expected_msg = format!(
        "{LOCK_DELEGATE_PREFIX}\n{}\n{}\nhttps://sync.example.org/write\nhttp://localhost:8080/read\n1795000000",
        hex_encode(&admin_pub),
        hex_encode(&lock_pub),
    );
    assert_eq!(del.canonical_message(), expected_msg);

    let mut signed_del = del.clone();
    signed_del.sig = admin_sk.sign(expected_msg.as_bytes()).to_bytes();
    signed_del
        .verify()
        .expect("independently signed delegation must verify");

    // Bad URLs: bad scheme, whitespace, control char, oversized > 2048
    for bad_url in [
        "ftp://sync.example.org",
        "https://sync.example.org/a b",
        "https://sync.example.org/\n",
        &format!("https://sync.example.org/{}", "a".repeat(2040)),
    ] {
        let mut bd = del.clone();
        bd.write_url = bad_url.to_string();
        bd.sig = admin_sk.sign(bd.canonical_message().as_bytes()).to_bytes();
        assert_eq!(bd.verify(), Err(WotError::InvalidSignature));

        let mut bd_read = del.clone();
        bd_read.read_url = bad_url.to_string();
        bd_read.sig = admin_sk
            .sign(bd_read.canonical_message().as_bytes())
            .to_bytes();
        assert_eq!(bd_read.verify(), Err(WotError::InvalidSignature));
    }

    // Weak lock_pub or weak admin_pub -> Err(WeakPublicKey)
    let mut weak_lock_del = del.clone();
    weak_lock_del.lock_pub = [0u8; 32];
    weak_lock_del.sig = admin_sk
        .sign(weak_lock_del.canonical_message().as_bytes())
        .to_bytes();
    assert_eq!(weak_lock_del.verify(), Err(WotError::WeakPublicKey));

    let mut weak_admin_del = del;
    weak_admin_del.admin_pub = [0u8; 32];
    assert_eq!(weak_admin_del.verify(), Err(WotError::WeakPublicKey));

    // 3. KeyRotationReason distinct domain digests + skew boundary
    let (signer_a, did_a) = make_identity();
    let (signer_b, did_b) = make_identity();
    let now_secs = 1_795_000_000u64;
    let d_routine = KeySuccessorAttestation::signing_digest(
        &did_a,
        &did_b,
        KeyRotationReason::Routine,
        None,
        now_secs,
    )
    .unwrap();
    let d_comp = KeySuccessorAttestation::signing_digest(
        &did_a,
        &did_b,
        KeyRotationReason::Compromise,
        None,
        now_secs,
    )
    .unwrap();
    let d_mig = KeySuccessorAttestation::signing_digest(
        &did_a,
        &did_b,
        KeyRotationReason::DeviceMigration,
        None,
        now_secs,
    )
    .unwrap();
    assert_ne!(d_routine, d_comp);
    assert_ne!(d_routine, d_mig);
    assert_ne!(d_comp, d_mig);

    // Independent SHA-256 KAT for KEY_SUCCESSOR_DOMAIN
    let mut kh = Sha256::new();
    kh.update(KEY_SUCCESSOR_DOMAIN);
    kh.update((did_a.len() as u32).to_le_bytes());
    kh.update(did_a.as_bytes());
    kh.update((did_b.len() as u32).to_le_bytes());
    kh.update(did_b.as_bytes());
    kh.update([0x02u8]); // Compromise
    kh.update([0u8]); // None
    kh.update(now_secs.to_le_bytes());
    let expected_ks: [u8; 32] = kh.finalize().into();
    assert_eq!(d_comp, expected_ks);

    let att = KeySuccessorAttestation::sign_dual(
        &signer_a,
        &signer_b,
        KeyRotationReason::Routine,
        None,
        now_secs + MAX_CLOCK_SKEW_SECS,
    )
    .unwrap();
    att.verify(now_secs)
        .expect("exact skew boundary must succeed");
    assert!(matches!(
        att.verify(now_secs - 1),
        Err(WotError::FutureTimestamp { .. })
    ));

    // 4. ServerOffenderList clock skew boundary + denylist negative check
    let mut list = ServerOffenderList::new();
    let rec_a = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        [1; 32],
        [2; 32],
        [3; 32],
        1,
    );
    let rec_b = make_signed_receipt(
        &lock_sk,
        WotLockReceiptKind::FirstWrite,
        [1; 32],
        [4; 32],
        [3; 32],
        2,
    );
    let offender_rec = ServerOffenderRecord {
        proof: WotEquivocationProof {
            receipt_a: rec_a,
            receipt_b: rec_b,
        },
        delegation: Some(signed_del),
        recorded_at: now_secs + MAX_CLOCK_SKEW_SECS,
    };
    assert!(matches!(
        list.insert_verified(offender_rec.clone(), now_secs - 1),
        Err(WotError::FutureTimestamp { .. })
    ));
    list.insert_verified(offender_rec, now_secs)
        .expect("exact skew boundary must succeed");

    let fuse = list.build_denylist_filter().unwrap();
    assert!(ServerOffenderList::filter_contains_pubkey(&fuse, &lock_pub));
    assert!(ServerOffenderList::filter_contains_pubkey(
        &fuse, &admin_pub
    ));
    assert!(!ServerOffenderList::filter_contains_pubkey(
        &fuse, &other_pub
    ));
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_shannon_diamond_bridge_exact_oracle() {
    // 1. Wheatstone bridge graph (both r0 > 0 and r1 > 0!):
    // Edges: 0:(0->1)=0.3, 1:(0->2)=0.6, 2:(1->2)=0.85, 3:(1->3)=0.85, 4:(2->3)=0.6
    let edges = vec![
        (0u32, 1u32, 0.30),
        (0, 2, 0.60),
        (1, 2, 0.85),
        (1, 3, 0.85),
        (2, 3, 0.60),
    ];
    let paths = vec![
        vec![0, 3],
        vec![1, 4],
        vec![0, 2, 4],
        vec![1, 2, 3], // undirected/reversed-like check using paths list directly
    ];
    let exact_paths = vec![vec![0, 3], vec![1, 4], vec![0, 2, 4]];
    let probs: Vec<f64> = edges.iter().map(|e| e.2).collect();
    let expected = brute_force_reliability(4, &edges, 0, 3, 4);
    let actual = exact_path_union_prob(&exact_paths, &probs, 0);
    assert!(
        (actual - expected).abs() < 1e-12,
        "Wheatstone bridge mismatch: actual={actual}, expected={expected}"
    );
    let _ = paths;

    // 2. Disconnected components with non-trivial shared edges inside each component
    // Component A: paths [0, 1] and [0, 2]; Component B: paths [3, 4] and [3, 5]
    let comp_probs = [0.60, 0.30, 0.85, 0.85, 0.30, 0.60];
    let p_a = 0.60 * (1.0 - (1.0 - 0.30) * (1.0 - 0.85));
    let p_b = 0.85 * (1.0 - (1.0 - 0.30) * (1.0 - 0.60));
    let expected_comp = 1.0 - (1.0 - p_a) * (1.0 - p_b);
    let actual_comp = exact_path_union_prob(
        &[vec![0, 1], vec![0, 2], vec![3, 4], vec![3, 5]],
        &comp_probs,
        0,
    );
    assert!(
        (actual_comp - expected_comp).abs() < 1e-12,
        "Component union mismatch: actual={actual_comp}, expected={expected_comp}"
    );

    // 3. Subsumption order invariance: subset before superset & superset before subset
    assert!((exact_path_union_prob(&[vec![0], vec![0, 1]], &[0.60, 0.85], 0) - 0.60).abs() < 1e-12);
    assert!((exact_path_union_prob(&[vec![0, 1], vec![0]], &[0.60, 0.85], 0) - 0.60).abs() < 1e-12);
    assert!(
        (exact_path_union_prob(&[vec![0, 1], vec![0, 1]], &[0.60, 0.85], 0) - 0.51).abs() < 1e-12
    );

    // 4. Depth >= 16 fallback stability
    let fallback = exact_path_union_prob(&[vec![0, 1], vec![0, 2]], &[0.60, 0.30, 0.85], 16);
    assert!(fallback > 0.0 && fallback < 1.0);
}

#[test]
fn test_sd_jwt_and_provider_filter_security_boundaries() {
    let (signer, did_signer) = make_identity();
    let (_, did_peer) = make_identity();
    let now_secs = 1_750_000_000u64;

    // 1. SD-JWT alg/typ individual rejection
    let valid_payload = SdJwtPayload {
        iss: did_signer.clone(),
        v: 1,
        iat: now_secs,
        max_hops: 2,
        _sd: vec![],
    };
    let bad_alg = sign_custom_sd_jwt(
        &signer,
        &SdJwtHeader {
            alg: "none".to_string(),
            typ: SD_JWT_TYP.to_string(),
        },
        &valid_payload,
        &[],
    );
    assert!(matches!(
        parse_and_verify_sd_jwt(&bad_alg, now_secs),
        Err(WotError::MalformedSdJwt(_))
    ));

    let bad_typ = sign_custom_sd_jwt(
        &signer,
        &SdJwtHeader {
            alg: SD_JWT_ALG.to_string(),
            typ: "jwt".to_string(),
        },
        &valid_payload,
        &[],
    );
    assert!(matches!(
        parse_and_verify_sd_jwt(&bad_typ, now_secs),
        Err(WotError::MalformedSdJwt(_))
    ));

    // 2. Salt < 16 bytes rejected by encode_disclosure AND parse_and_verify_sd_jwt
    assert!(encode_disclosure(&[1u8; 15], &did_peer, 2, 2).is_err());
    let short_salt_b64 = URL_SAFE_NO_PAD.encode([1u8; 15]);
    let short_disc_json = serde_json::to_string(&(&short_salt_b64, &did_peer, 2u8, 2u8)).unwrap();
    let short_disc_raw = URL_SAFE_NO_PAD.encode(short_disc_json.as_bytes());
    let short_disc_digest = compute_digest128(&short_disc_raw);
    let short_salt_wire = sign_custom_sd_jwt(
        &signer,
        &SdJwtHeader {
            alg: SD_JWT_ALG.to_string(),
            typ: SD_JWT_TYP.to_string(),
        },
        &SdJwtPayload {
            iss: did_signer.clone(),
            v: 1,
            iat: now_secs,
            max_hops: 2,
            _sd: vec![short_disc_digest],
        },
        &[short_disc_raw],
    );
    assert!(matches!(
        parse_and_verify_sd_jwt(&short_salt_wire, now_secs),
        Err(WotError::MalformedSdJwt(_))
    ));

    // 3. SD-JWT exact boundaries (RAW_LEN, MAX_SD_ENTRIES, clock skew, version ahead, contact_max_hops)
    let exact_len = " ".repeat(MAX_SD_JWT_RAW_LEN);
    assert!(matches!(
        parse_and_verify_sd_jwt(&exact_len, now_secs),
        Err(WotError::MalformedSdJwt(_))
    ));
    let over_len = " ".repeat(MAX_SD_JWT_RAW_LEN + 1);
    assert!(matches!(
        parse_and_verify_sd_jwt(&over_len, now_secs),
        Err(WotError::LimitExceeded(_))
    ));

    let max_contacts: Vec<(Did, u8, u8)> = (1..=MAX_SD_ENTRIES)
        .map(|i| {
            let mut key_bytes = [1u8; 32];
            key_bytes[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            let sk = SigningKey::from_bytes(&key_bytes);
            (
                did_from_verifying_key(&sk.verifying_key()).unwrap(),
                2u8,
                8u8,
            )
        })
        .collect();
    let (max_wire, stored_max) =
        create_and_sign_sd_jwt(&signer, 1, now_secs, 8, &max_contacts).unwrap();
    assert_eq!(stored_max.disclosures.len(), MAX_SD_ENTRIES);
    parse_and_verify_sd_jwt(&max_wire, now_secs).expect("exact MAX_SD_ENTRIES must verify");

    let mut too_many = max_contacts.clone();
    too_many.push((deterministic_did(250), 1, 1));
    assert!(matches!(
        create_and_sign_sd_jwt(&signer, 1, now_secs, 2, &too_many),
        Err(WotError::LimitExceeded(_))
    ));

    // contact_max_hops == 9 rejected
    assert!(matches!(
        create_and_sign_sd_jwt(&signer, 1, now_secs, 2, &[(did_peer.clone(), 2, 9)]),
        Err(WotError::InvalidHopLimit(9))
    ));
    let bad_ch_raw = URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&(&URL_SAFE_NO_PAD.encode([7u8; 16]), &did_peer, 2u8, 9u8))
            .unwrap()
            .as_bytes(),
    );
    let bad_ch_dig = compute_digest128(&bad_ch_raw);
    let bad_ch_wire = sign_custom_sd_jwt(
        &signer,
        &SdJwtHeader {
            alg: SD_JWT_ALG.to_string(),
            typ: SD_JWT_TYP.to_string(),
        },
        &SdJwtPayload {
            iss: did_signer.clone(),
            v: 1,
            iat: now_secs,
            max_hops: 2,
            _sd: vec![bad_ch_dig],
        },
        &[bad_ch_raw],
    );
    assert!(matches!(
        parse_and_verify_sd_jwt(&bad_ch_wire, now_secs),
        Err(WotError::InvalidHopLimit(9))
    ));

    // Exact timestamp skew boundaries in parse_and_verify_sd_jwt
    let (skew_ok, _) =
        create_and_sign_sd_jwt(&signer, 1, now_secs + MAX_CLOCK_SKEW_SECS, 2, &[]).unwrap();
    parse_and_verify_sd_jwt(&skew_ok, now_secs).unwrap();
    let (skew_bad, _) =
        create_and_sign_sd_jwt(&signer, 1, now_secs + MAX_CLOCK_SKEW_SECS + 1, 2, &[]).unwrap();
    assert!(matches!(
        parse_and_verify_sd_jwt(&skew_bad, now_secs),
        Err(WotError::FutureTimestamp { .. })
    ));

    let (v_ok, _) =
        create_and_sign_sd_jwt(&signer, now_secs + MAX_VERSION_AHEAD_SECS, now_secs, 2, &[])
            .unwrap();
    parse_and_verify_sd_jwt(&v_ok, now_secs).unwrap();
    let (v_bad, _) = create_and_sign_sd_jwt(
        &signer,
        now_secs + MAX_VERSION_AHEAD_SECS + 1,
        now_secs,
        2,
        &[],
    )
    .unwrap();
    assert!(matches!(
        parse_and_verify_sd_jwt(&v_bad, now_secs),
        Err(WotError::FutureTimestamp { .. })
    ));

    // disclosure_fingerprint exact max_hops boundary
    assert_ne!(stored_max.disclosure_fingerprint(8), 0);
    assert_eq!(stored_max.disclosure_fingerprint(9), 0);

    // 4. Provider filter exact size, timestamp & level boundaries
    let exact_pf = " ".repeat(MAX_PROVIDER_FILTER_RAW_LEN);
    assert!(matches!(
        parse_and_verify_provider_filter(&exact_pf, now_secs),
        Err(WotError::Serialization(_))
    ));
    let over_pf = " ".repeat(MAX_PROVIDER_FILTER_RAW_LEN + 1);
    assert!(matches!(
        parse_and_verify_provider_filter(&over_pf, now_secs),
        Err(WotError::LimitExceeded(_))
    ));

    assert!(matches!(
        create_and_sign_provider_filter(
            &signer,
            "Bad0",
            1,
            now_secs,
            None,
            &[(did_peer.clone(), 0)]
        ),
        Err(WotError::InvalidTrustLevel(0))
    ));
    assert!(matches!(
        create_and_sign_provider_filter(
            &signer,
            "Bad4",
            1,
            now_secs,
            None,
            &[(did_peer.clone(), 4)]
        ),
        Err(WotError::InvalidTrustLevel(4))
    ));

    let pf_skew_ok = create_and_sign_provider_filter(
        &signer,
        "Skew",
        now_secs + MAX_VERSION_AHEAD_SECS,
        now_secs + MAX_CLOCK_SKEW_SECS,
        None,
        &[],
    )
    .unwrap();
    parse_and_verify_provider_filter(&pf_skew_ok, now_secs).unwrap();

    let pf_iat_bad = create_and_sign_provider_filter(
        &signer,
        "Skew",
        1,
        now_secs + MAX_CLOCK_SKEW_SECS + 1,
        None,
        &[],
    )
    .unwrap();
    assert!(matches!(
        parse_and_verify_provider_filter(&pf_iat_bad, now_secs),
        Err(WotError::FutureTimestamp { .. })
    ));

    let pf_v_bad = create_and_sign_provider_filter(
        &signer,
        "Skew",
        now_secs + MAX_VERSION_AHEAD_SECS + 1,
        now_secs,
        None,
        &[],
    )
    .unwrap();
    assert!(matches!(
        parse_and_verify_provider_filter(&pf_v_bad, now_secs),
        Err(WotError::FutureTimestamp { .. })
    ));

    for bad_lvl in [0u8, 4u8] {
        let mut levels = BTreeMap::new();
        levels.insert(bad_lvl, BinaryFuse64::build(&[]).unwrap().encode());
        let raw = sign_custom_provider_filter(
            &signer,
            &ProviderFilterPayload {
                typ: PROVIDER_FILTER_TYP.to_string(),
                iss: did_signer.clone(),
                name: "BadLvl".to_string(),
                v: 1,
                iat: now_secs,
                source_url: None,
                member_count: 0,
                level_filters: levels,
            },
        );
        assert!(matches!(
            parse_and_verify_provider_filter(&raw, now_secs),
            Err(WotError::InvalidTrustLevel(l)) if l == bad_lvl
        ));
    }
}

#[test]
fn test_sync_delta_third_party_skip_and_reciprocity_dirty_flag() {
    let (signer_me, did_me) = make_identity();
    let (signer_bob, did_bob) = make_identity();
    let (signer_carol, did_carol) = make_identity();
    let (_, did_dave) = make_identity();
    let now_secs = 1_750_000_000u64;

    let mut reg_me = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    reg_me.set_own_list_max_hops(3, now_secs).unwrap();
    reg_me.set_contact_trust(&did_bob, 2, 3, now_secs).unwrap();
    reg_me
        .set_contact_trust(&did_carol, 2, 3, now_secs)
        .unwrap();
    reg_me.sign_own_list(&signer_me, now_secs).unwrap();

    // Seed Bob and Carol with forwardable lists (reciprocal 3-hop)
    let (wire_bob, _) =
        create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 3, &[(did_dave.clone(), 2, 3)]).unwrap();
    let (wire_carol, _) =
        create_and_sign_sd_jwt(&signer_carol, 1, now_secs, 3, &[(did_me.clone(), 2, 3)]).unwrap();
    reg_me
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![wire_bob, wire_carol],
            },
            None,
            now_secs,
        )
        .unwrap();
    assert!(reg_me.own_list_dirty);
    reg_me.sign_own_list(&signer_me, now_secs + 1).unwrap();
    assert!(!reg_me.own_list_dirty);

    // Prepare sync package for Carol -> commits Me, Bob, and Carol to sent_log[Carol]
    let (pkg1, rcpt1) = reg_me
        .prepare_sync_package(Some(&did_carol), None, false)
        .unwrap();
    assert_eq!(pkg1.lists.len(), 3);
    reg_me.commit_sync_receipt(rcpt1, now_secs + 2);

    // Second incremental prepare -> 0 lists because both Me and Bob match sent_log!
    let (pkg2, _) = reg_me
        .prepare_sync_package(Some(&did_carol), None, false)
        .unwrap();
    assert!(pkg2.lists.is_empty());

    // Importing unchanged package keeps own_list_dirty == false
    reg_me
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![],
            },
            None,
            now_secs + 3,
        )
        .unwrap();
    assert!(!reg_me.own_list_dirty);
}

// =========================================================================
// Property-Based Tests (proptest!)
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_binary_fuse64_roundtrip_all_sizes(
        size in 0usize..=500,
        seed_offset in any::<u64>(),
    ) {
        let keys: Vec<u64> = (0..size as u64)
            .map(|i| mix64(i.wrapping_add(seed_offset).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
            .collect();
        let filter = BinaryFuse64::build(&keys).expect("build must succeed");
        let encoded = filter.encode();
        let decoded = BinaryFuse64::decode(&encoded).expect("decode must succeed");
        prop_assert_eq!(&filter, &decoded);

        let key_set: HashSet<u64> = keys.iter().copied().collect();
        for &k in &keys {
            prop_assert!(decoded.contains(k));
        }
        for probe in 0..32u64 {
            let candidate = mix64(seed_offset ^ probe.wrapping_mul(0xbf58_476d_1ce4_e5b9));
            if !key_set.contains(&candidate) {
                prop_assert!(!decoded.contains(candidate));
            }
        }
    }

    #[test]
    fn prop_binary_fuse64_arbitrary_encoded_never_panics(
        seed in any::<u64>(),
        segment_length in any::<u32>(),
        segment_length_mask in any::<u32>(),
        segment_count_length in any::<u32>(),
        fps in prop::collection::vec(any::<u64>(), 0..32),
        query in any::<u64>(),
    ) {
        let raw_bytes: Vec<u8> = fps.iter().flat_map(|v| v.to_le_bytes()).collect();
        let enc = EncodedBinaryFuse64 {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints_b64: URL_SAFE_NO_PAD.encode(raw_bytes),
        };
        let _ = BinaryFuse64::decode(&enc);

        let direct = BinaryFuse64 {
            seed,
            segment_length,
            segment_length_mask,
            segment_count_length,
            fingerprints: fps,
        };
        let _ = direct.contains(query);
    }

    #[test]
    fn prop_scorer_matches_bruteforce_and_metamorphic_invariants(
        raw_edges in prop::collection::vec((0usize..5, 0usize..5, 0u8..=3), 0..=10),
        target_idx in 1usize..5,
        guarantor_mask in 0u8..16,
    ) {
        let dids: Vec<Did> = (1..=5u8).map(deterministic_did).collect();
        let mut graph = EgoGraphCache::new(dids[0].clone());
        for d in &dids[1..] {
            graph.get_or_create_node(d);
        }

        // Deduplicate (u, v) keeping max level (matching EgoGraphCache semantics when iat is equal)
        let mut best_edge_level: BTreeMap<(u32, u32), u8> = BTreeMap::new();
        for (u, v, lvl) in raw_edges {
            if u != v {
                graph.add_or_update_edge(u as u32, v as u32, lvl, 1_000);
                if lvl >= 1 {
                    best_edge_level
                        .entry((u as u32, v as u32))
                        .and_modify(|e| *e = (*e).max(lvl))
                        .or_insert(lvl);
                }
            }
        }

        // Apply guarantor bridges identically in both oracle and policy
        let mut guarantors: Vec<&str> = Vec::new();
        for (g_idx, g_did) in dids.iter().enumerate().skip(1) {
            if (guarantor_mask >> g_idx) & 1 == 1 && g_idx != target_idx {
                guarantors.push(g_did.as_str());
            }
        }

        let mut oracle_edges_map: BTreeMap<(u32, u32), f64> = best_edge_level
            .iter()
            .map(|(&(u, v), &lvl)| ((u, v), humoco_wot::level_to_factor(lvl)))
            .collect();
        for g_idx in 1usize..dids.len() {
            if (guarantor_mask >> g_idx) & 1 == 1 && g_idx != target_idx {
                oracle_edges_map
                    .entry((g_idx as u32, target_idx as u32))
                    .and_modify(|p| *p = p.max(0.85))
                    .or_insert(0.85);
            }
        }
        let oracle_edges: Vec<(u32, u32, f64)> = oracle_edges_map
            .into_iter()
            .filter(|&(_, p)| p > 0.0)
            .map(|((u, v), p)| (u, v, p))
            .collect();

        let policy = WotPolicy {
            freshness_half_life_secs: None,
            ..Default::default()
        };

        // 1. Exact brute-force match (when active edges <= 12, always true for 5-node subset here?
        // Actually max unique (u,v) with u!=v in 5 nodes is 20; if > 12, skip brute-force check, still check bounds & monotonicity)
        let eval = evaluate_trust(&graph, &policy, &dids[target_idx], &guarantors, false, None)
            .expect("eval succeeds");
        prop_assert!(eval.score >= 0.0 && eval.score <= 1.0);

        if oracle_edges.len() <= 12 {
            let expected = brute_force_reliability(5, &oracle_edges, 0, target_idx as u32, 5);
            prop_assert!(
                (eval.score - expected).abs() < 1e-9,
                "Oracle mismatch: actual={}, expected={}, edges={:?}",
                eval.score,
                expected,
                oracle_edges
            );
        }

        // 2. Metamorphic: KnownOffender ALWAYS blocks with score 0.0
        let eval_off = evaluate_trust(&graph, &policy, &dids[target_idx], &guarantors, true, None)
            .expect("offender eval succeeds");
        prop_assert_eq!(eval_off.score, 0.0);
        prop_assert!(eval_off.blocked_by_offender);

        // 3. Metamorphic: Adding a Level-0 edge never changes score
        let mut graph_lvl0 = graph.clone();
        graph_lvl0.add_or_update_edge(0, target_idx as u32, 0, 2_000);
        let eval_lvl0 =
            evaluate_trust(&graph_lvl0, &policy, &dids[target_idx], &guarantors, false, None)
                .unwrap();
        prop_assert!((eval_lvl0.score - eval.score).abs() < 1e-12);

        // 4. Metamorphic: Raising edge 0 -> target to Level 3 monotonically cannot decrease score
        let mut graph_raised = graph.clone();
        graph_raised.add_or_update_edge(0, target_idx as u32, 3, 2_000);
        let eval_raised =
            evaluate_trust(&graph_raised, &policy, &dids[target_idx], &guarantors, false, None)
                .unwrap();
        prop_assert!(eval_raised.score + 1e-12 >= eval.score);
    }

    #[test]
    fn prop_untrusted_parsers_never_panic(raw in ".*") {
        let _ = canonicalize_did(&raw);
        let _ = peek_unverified_issuer(&raw);
        let _ = parse_and_verify_sd_jwt(&raw, 1_750_000_000);
        let _ = parse_and_verify_provider_filter(&raw, 1_750_000_000);
    }
}
