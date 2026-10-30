use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use humoco_wot::error::WotError;
use humoco_wot::identity::{
    canonicalize_did, did_from_verifying_key, extract_verifying_key, Did, Ed25519WotSigner,
    WotSigner,
};
use humoco_wot::register::{TrustRegister, WotPolicy};
use humoco_wot::sd_jwt::{
    create_and_sign_sd_jwt, encode_disclosure, parse_and_verify_sd_jwt, DECOY_BUCKET_MULTIPLE,
};
use humoco_wot::sync::WotSyncPackage;

fn create_identity() -> (Ed25519WotSigner, Did) {
    let sk = SigningKey::generate(&mut OsRng);
    let signer = Ed25519WotSigner::new(sk).expect("Valid signer");
    let did = signer.did().to_string();
    (signer, did)
}

#[test]
fn test_01_did_canonicalization_and_validation() {
    let (signer, did) = create_identity();

    // 1. Valid bare did:key
    let canonical = canonicalize_did(&did).expect("Valid did:key");
    assert_eq!(canonical, did);

    // 2. Valid prefixed DID (strips prefix)
    let prefixed = format!("alice:chk@{}", did);
    let canonical_prefixed = canonicalize_did(&prefixed).expect("Valid prefixed DID");
    assert_eq!(canonical_prefixed, did);

    // 3. Valid complex prefix with hyphens and numbers
    let complex_prefixed = format!("user-99:chk-valid-42@{}", did);
    assert_eq!(canonicalize_did(&complex_prefixed).unwrap(), did);

    // 4. Reject double @
    let double_at = format!("foo@bar@{}", did);
    assert!(matches!(
        canonicalize_did(&double_at),
        Err(WotError::InvalidDid(_))
    ));

    // 5. Reject empty prefix before @
    let empty_prefix = format!("@{}", did);
    assert!(matches!(
        canonicalize_did(&empty_prefix),
        Err(WotError::InvalidDid(_))
    ));

    // 6. Reject invalid characters in prefix
    let invalid_prefix = format!("Alice_Capital@{}", did);
    assert!(matches!(
        canonicalize_did(&invalid_prefix),
        Err(WotError::InvalidDid(_))
    ));

    // 7. Reject internal whitespace
    let space_did = format!("did:key: z{}", &did[10..]);
    assert!(matches!(
        canonicalize_did(&space_did),
        Err(WotError::InvalidDid(_))
    ));

    // 8. Reject wrong multicodec
    let mut raw_bytes = bs58::decode(&did[9..]).into_vec().unwrap();
    raw_bytes[0] = 0xed;
    raw_bytes[1] = 0x02; // Wrong codec (should be 0x01)
    let wrong_codec = format!("did:key:z{}", bs58::encode(&raw_bytes).into_string());
    assert!(matches!(
        canonicalize_did(&wrong_codec),
        Err(WotError::InvalidDid(_))
    ));

    // 9. Reject wrong length (trailing garbage)
    let mut extra_bytes = raw_bytes.clone();
    extra_bytes.push(0x42);
    let garbage_did = format!("did:key:z{}", bs58::encode(&extra_bytes).into_string());
    assert!(matches!(
        canonicalize_did(&garbage_did),
        Err(WotError::InvalidDid(_))
    ));

    // 10. Reject weak public key (all zero bytes)
    let mut weak_bytes = vec![0xed, 0x01];
    weak_bytes.extend_from_slice(&[0u8; 32]);
    let weak_did = format!("did:key:z{}", bs58::encode(&weak_bytes).into_string());
    assert!(matches!(
        canonicalize_did(&weak_did),
        Err(WotError::WeakPublicKey)
    ));

    // 11. Extract and round-trip verifying key
    let vk = extract_verifying_key(&did).expect("Extract verifying key");
    let re_did = did_from_verifying_key(&vk).expect("DID from verifying key");
    assert_eq!(re_did, did);
    assert_eq!(signer.did(), did);
}

#[test]
fn test_02_sd_jwt_roundtrip_tampering_redaction_and_decoys() {
    let (signer_alice, did_alice) = create_identity();
    let (_, did_bob) = create_identity();
    let (_, did_carol) = create_identity();

    let now_secs = 1_700_000_000;
    let contacts = vec![
        (did_bob.clone(), 3, 4),   // Level 3 (85%), contact_max_hops = 4
        (did_carol.clone(), 1, 1), // Level 1 (30%), contact_max_hops = 1
    ];

    let (wire_sd_jwt, stored) =
        create_and_sign_sd_jwt(&signer_alice, 10, now_secs, 4, &contacts).expect("Create SD-JWT");

    // Decoy padding check: with 2 contacts, _sd must be padded to DECOY_BUCKET_MULTIPLE (8)
    let parts: Vec<&str> = wire_sd_jwt.split('~').collect();
    let jws_parts: Vec<&str> = parts[0].split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(jws_parts[1]).unwrap();
    let payload: humoco_wot::SdJwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload._sd.len(), DECOY_BUCKET_MULTIPLE);
    assert_eq!(payload.v, 10);
    assert_eq!(payload.iat, now_secs);
    assert_eq!(payload.max_hops, 4);

    // Verify raw SD-JWT
    let (iss, verified) =
        parse_and_verify_sd_jwt(&wire_sd_jwt, now_secs).expect("Verify valid SD-JWT");
    assert_eq!(iss, did_alice);
    assert_eq!(verified.disclosures.len(), 2);

    // Tampering test 1: Modify signature
    let mut tampered_sig = wire_sd_jwt.clone();
    let last_char = if tampered_sig.contains('A') { 'B' } else { 'A' };
    tampered_sig.replace_range(10..11, &last_char.to_string());
    assert!(parse_and_verify_sd_jwt(&tampered_sig, now_secs).is_err());

    // Tampering test 2: Modify disclosure payload
    let mut parts_clone = parts.clone();
    if parts_clone.len() > 1 && !parts_clone[1].is_empty() {
        parts_clone[1] = "eyJnYXJiYWdlIjoxfQ"; // Invalid disclosure
        let tampered_disc = parts_clone.join("~");
        assert!(parse_and_verify_sd_jwt(&tampered_disc, now_secs).is_err());
    }

    // Distance redaction test:
    // target_distance = 1: Bob (hops 4) and Carol (hops 1) both included
    let red_1 = stored.to_redacted_wire_string(1).expect("Redacted for hop 1");
    let (_, ver_1) = parse_and_verify_sd_jwt(&red_1, now_secs).unwrap();
    assert_eq!(ver_1.disclosures.len(), 2);

    // target_distance = 2: Carol (hops 1) is redacted, only Bob remains!
    let red_2 = stored.to_redacted_wire_string(2).expect("Redacted for hop 2");
    let (_, ver_2) = parse_and_verify_sd_jwt(&red_2, now_secs).unwrap();
    assert_eq!(ver_2.disclosures.len(), 1);
    let remaining_target = &ver_2.disclosures.values().next().unwrap().target_did;
    assert_eq!(remaining_target, &did_bob);

    // target_distance = 5: exceeds list max_hops (4) -> dropped entirely
    assert!(stored.to_redacted_wire_string(5).is_none());
}

#[test]
fn test_03_wallet_recovery_and_future_timestamp_bounds() {
    let (signer, did) = create_identity();
    let (_, peer_did) = create_identity();

    let reference_now = 1_700_000_000;
    let policy = WotPolicy::default();
    let mut register = TrustRegister::new(&did, policy).unwrap();

    // Direct contact addition
    register
        .set_contact_trust(&peer_did, 2, 3, reference_now)
        .unwrap();

    // Initial signing
    let _wire_v1 = register.sign_own_list(&signer, reference_now).unwrap();
    assert_eq!(register.own_signed_list.as_ref().unwrap().v, reference_now);

    // Device loss simulation: new register recreated from scratch at later unix timestamp
    let recovered_now = reference_now + 100_000;
    let mut recovered_register = TrustRegister::new(&did, WotPolicy::default()).unwrap();
    recovered_register
        .set_contact_trust(&peer_did, 2, 3, recovered_now)
        .unwrap();

    let _wire_v2 = recovered_register
        .sign_own_list(&signer, recovered_now)
        .unwrap();
    let v2 = recovered_register.own_signed_list.as_ref().unwrap().v;
    assert!(v2 >= recovered_now);
    assert!(v2 > reference_now);

    // Future timestamp rejection:
    // 1. iat far in the future (> 24 hours)
    let future_iat = reference_now + 200_000;
    let (future_wire, _) =
        create_and_sign_sd_jwt(&signer, reference_now, future_iat, 4, &[]).unwrap();
    assert!(matches!(
        parse_and_verify_sd_jwt(&future_wire, reference_now),
        Err(WotError::FutureTimestamp { .. })
    ));

    // 2. v far in the future (> 1_000_000 seconds ahead)
    let poison_v = reference_now + 2_000_000;
    let (poison_wire, _) =
        create_and_sign_sd_jwt(&signer, poison_v, reference_now, 4, &[]).unwrap();
    assert!(matches!(
        parse_and_verify_sd_jwt(&poison_wire, reference_now),
        Err(WotError::FutureTimestamp { .. })
    ));
}

#[test]
fn test_04_handshake_flow_and_reciprocal_tit_for_tat() {
    let (signer_alice, did_alice) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_, did_charlie) = create_identity();

    let now_secs = 1_700_000_000;

    let mut reg_alice = TrustRegister::new(&did_alice, WotPolicy::default()).unwrap();
    let mut reg_bob = TrustRegister::new(&did_bob, WotPolicy::default()).unwrap();

    // Alice adds Charlie and signs her list
    reg_alice
        .set_contact_trust(&did_charlie, 3, 4, now_secs)
        .unwrap();
    reg_alice.sign_own_list(&signer_alice, now_secs).unwrap();

    // Alice exports sync package for Bob
    let (pkg_alice, receipt_alice) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    reg_alice.commit_sync_receipt(receipt_alice, now_secs);

    // Bob imports Alice's package BEFORE adding Alice to own_contacts (direct handshake)
    let stats_bob = reg_bob
        .import_sync_package(&pkg_alice, Some(&did_alice), now_secs)
        .unwrap();
    assert_eq!(stats_bob.imported, 1);
    assert!(reg_bob.raw_list_store.contains_key(&did_alice));

    // Bob now configures trust for Alice (level = 2, desired_hops = 3)
    reg_bob
        .set_contact_trust(&did_alice, 2, 3, now_secs)
        .unwrap();

    // Tit-for-Tat check: Bob immediately sees Alice's forwardable list
    // Alice's list max_hops is 4, Bob's desired is 3 -> effective_hops is 3!
    let eff_hops = reg_bob.effective_hops_for_contact(&did_alice);
    assert_eq!(eff_hops, Some(3));

    // Bob signs his own list with effective_hops = 3
    reg_bob.sign_own_list(&signer_bob, now_secs).unwrap();
    let (pkg_bob, _) = reg_bob
        .prepare_sync_package(Some(&did_alice), None, false)
        .unwrap();

    // Alice imports Bob's package -> Alice configures trust for Bob afterwards or during
    reg_alice
        .set_contact_trust(&did_bob, 2, 3, now_secs)
        .unwrap();
    reg_alice.sign_own_list(&signer_alice, now_secs).unwrap();
    assert!(!reg_alice.own_list_dirty);

    // Bob's list arrives at Alice: reciprocity is updated -> marks Alice's own list dirty
    let stats_alice = reg_alice
        .import_sync_package(&pkg_bob, Some(&did_bob), now_secs)
        .unwrap();
    assert_eq!(stats_alice.imported, 1);
    assert!(reg_alice.own_list_dirty);
}

#[test]
fn test_05_two_phase_sync_receipt_and_union_merge_delta() {
    let (signer_alice, did_alice) = create_identity();
    let (_, did_bob) = create_identity();
    let (_, did_dave) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg_alice = TrustRegister::new(&did_alice, WotPolicy::default()).unwrap();

    reg_alice
        .set_contact_trust(&did_bob, 2, 3, now_secs)
        .unwrap();
    reg_alice.sign_own_list(&signer_alice, now_secs).unwrap();

    // Phase 1: prepare without commit
    let (pkg1, receipt1) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    assert_eq!(pkg1.lists.len(), 1);

    // Without committing receipt, prepare_sync_package generates list again
    let (pkg1_repeat, _) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    assert_eq!(pkg1_repeat.lists.len(), 1);

    // Commit receipt
    reg_alice.commit_sync_receipt(receipt1, now_secs);

    // Now sent_log filters it out -> empty package
    let (pkg_empty, _) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    assert!(pkg_empty.lists.is_empty());

    // Phase 2: Union-Merge Delta
    // Carol creates a list at version v=50 with disclosure for Dave (contact_max_hops = 3)
    let (signer_carol, did_carol) = create_identity();
    let (_, stored_carol_v50) = create_and_sign_sd_jwt(
        &signer_carol,
        50,
        now_secs,
        4,
        &[(did_dave.clone(), 3, 3)],
    )
    .unwrap();

    // Alice initially receives Carol's list with completely redacted disclosures
    let wire_redacted = format!("{}~", stored_carol_v50.jws_compact);
    let pkg_redacted = WotSyncPackage {
        format_version: 1,
        lists: vec![wire_redacted],
    };

    // Alice trusts Carol so import is allowed
    reg_alice
        .set_contact_trust(&did_carol, 2, 4, now_secs)
        .unwrap();
    let stats = reg_alice
        .import_sync_package(&pkg_redacted, Some(&did_carol), now_secs)
        .unwrap();
    assert_eq!(stats.imported, 1);

    // Alice transmits Carol's list to Bob and commits receipt
    let (_pkg_to_bob, receipt_to_bob) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    reg_alice.commit_sync_receipt(receipt_to_bob, now_secs);

    // Later: Alice receives Carol's full list of the same version v=50 with Dave disclosed!
    let wire_full = stored_carol_v50.to_redacted_wire_string(1).unwrap();
    let pkg_full = WotSyncPackage {
        format_version: 1,
        lists: vec![wire_full],
    };
    let merge_stats = reg_alice
        .import_sync_package(&pkg_full, Some(&did_carol), now_secs)
        .unwrap();
    assert_eq!(merge_stats.merged, 1);

    // Alice prepares package for Bob again: because disclosure_fingerprint changed,
    // Carol's newly revealed disclosures are delivered to Bob!
    let (pkg_update, _) = reg_alice
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();
    assert_eq!(pkg_update.lists.len(), 1);
}

#[test]
fn test_06_sybil_bottleneck_and_cyclic_graphs() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_, did_target) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Me trusts Bob with Level 1 (30%)
    reg.set_contact_trust(&did_bob, 1, 4, now_secs).unwrap();

    // 2. Bob creates 30 Sybil contacts S_1 .. S_30 with Level 3 (85%)
    let mut sybil_signers = Vec::new();
    let mut bob_contacts = Vec::new();

    for _ in 0..30 {
        let (s_signer, s_did) = create_identity();
        bob_contacts.push((s_did, 3, 4));
        sybil_signers.push(s_signer);
    }

    let (wire_bob, _) =
        create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 4, &bob_contacts).unwrap();
    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_bob],
        },
        Some(&did_bob),
        now_secs,
    )
    .unwrap();

    // 3. Every Sybil S_i trusts Target with Level 3 (85%)
    let mut sybil_pkg_lists = Vec::new();
    for s_signer in &sybil_signers {
        let (wire_s, _) = create_and_sign_sd_jwt(
            s_signer,
            1,
            now_secs,
            4,
            &[(did_target.clone(), 3, 4)],
        )
        .unwrap();
        sybil_pkg_lists.push(wire_s);
    }

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: sybil_pkg_lists,
        },
        None,
        now_secs,
    )
    .unwrap();

    // EVALUATION 1: Bottleneck test
    // Even with 30 parallel Sybils behind Bob, the trust to Target MUST NOT exceed Bob's 30%!
    let eval1 = reg.evaluate_did(&did_target, Some(now_secs)).unwrap();
    assert!(
        eval1.score <= 0.300000001,
        "Expected score <= 0.30, got {}",
        eval1.score
    );
    assert_eq!(eval1.shortest_hops, Some(3));

    // EVALUATION 2: True multi-path test
    // Add an independent 2-hop route: Me -(60%)-> Anna -(60%)-> Tom -(85%)-> Target
    let (signer_anna, did_anna) = create_identity();
    let (signer_tom, did_tom) = create_identity();

    reg.set_contact_trust(&did_anna, 2, 4, now_secs).unwrap(); // 60%

    let (wire_anna, _) =
        create_and_sign_sd_jwt(&signer_anna, 1, now_secs, 4, &[(did_tom.clone(), 2, 4)]).unwrap(); // 60%
    let (wire_tom, _) =
        create_and_sign_sd_jwt(&signer_tom, 1, now_secs, 4, &[(did_target.clone(), 3, 4)]).unwrap(); // 85%

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_anna, wire_tom],
        },
        None,
        now_secs,
    )
    .unwrap();

    let eval2 = reg.evaluate_did(&did_target, Some(now_secs)).unwrap();
    // With two independent branches, score must rise significantly above 0.30 (> 0.45)!
    assert!(
        eval2.score > 0.45,
        "Expected multi-path score > 0.45, got {}",
        eval2.score
    );

    // EVALUATION 3: Cyclic graph termination
    // Add cycle: Target -> Anna
    let (signer_target, _) = create_identity();
    let (wire_cycle, _) =
        create_and_sign_sd_jwt(&signer_target, 1, now_secs, 4, &[(did_anna.clone(), 3, 4)]).unwrap();
    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_cycle],
        },
        None,
        now_secs,
    )
    .unwrap();

    let eval3 = reg.evaluate_did(&did_target, Some(now_secs)).unwrap();
    assert!(eval3.score > 0.45);
}

#[test]
fn test_07_voucher_evaluation_and_known_offender_veto() {
    let (_signer_me, did_me) = create_identity();
    let (_, did_carol) = create_identity();
    let (_, did_creator) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // Me trusts Carol with Level 3 (85%)
    reg.set_contact_trust(&did_carol, 3, 4, now_secs).unwrap();

    // Voucher creator is unknown, but Carol acts as guarantor (guarantor_weight = 0.85)
    // Expected trust: 0.85 * 0.85 = 0.7225
    let eval = reg
        .evaluate_voucher(&did_creator, &[&did_carol], false, Some(now_secs))
        .unwrap();

    assert!(!eval.blocked_by_offender);
    assert!(
        (eval.score - 0.7225).abs() < 1e-4,
        "Expected score ~0.7225, got {}",
        eval.score
    );
    assert_eq!(eval.shortest_hops, Some(2));

    // SST V4 known double-spender veto:
    let blocked_eval = reg
        .evaluate_voucher(&did_creator, &[&did_carol], true, Some(now_secs))
        .unwrap();
    assert_eq!(blocked_eval.score, 0.0);
    assert!(blocked_eval.blocked_by_offender);
    assert!(blocked_eval.shortest_hops.is_none());
}

#[test]
fn test_08_island_spam_rejection_and_orphan_pruning() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (signer_dave, did_dave) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Generate 50 disconnected fake island lists
    let mut fake_lists = Vec::new();
    for _ in 0..50 {
        let (fake_signer, _) = create_identity();
        let (wire, _) = create_and_sign_sd_jwt(&fake_signer, 1, now_secs, 4, &[]).unwrap();
        fake_lists.push(wire);
    }

    // Import without direct_sender_did: all 50 MUST be rejected as unreachable!
    let spam_pkg = WotSyncPackage {
        format_version: 1,
        lists: fake_lists,
    };
    let spam_stats = reg.import_sync_package(&spam_pkg, None, now_secs).unwrap();
    assert_eq!(spam_stats.rejected_spam, 50);
    assert_eq!(spam_stats.imported, 0);
    assert!(reg.raw_list_store.is_empty());

    // 2. Pruning test: Me -> Bob -> Dave
    reg.set_contact_trust(&did_bob, 2, 4, now_secs).unwrap();

    let (wire_bob, _) =
        create_and_sign_sd_jwt(&signer_bob, 1, now_secs, 4, &[(did_dave.clone(), 2, 4)]).unwrap();
    let (wire_dave, _) =
        create_and_sign_sd_jwt(&signer_dave, 1, now_secs, 4, &[]).unwrap();

    let valid_pkg = WotSyncPackage {
        format_version: 1,
        lists: vec![wire_bob, wire_dave],
    };
    let valid_stats = reg.import_sync_package(&valid_pkg, None, now_secs).unwrap();
    assert_eq!(valid_stats.imported, 2);
    assert!(reg.raw_list_store.contains_key(&did_bob));
    assert!(reg.raw_list_store.contains_key(&did_dave));

    // Removing Bob must automatically prune Dave from raw_list_store!
    let removed = reg.remove_contact_trust(&did_bob).unwrap();
    assert!(removed);
    assert!(!reg.raw_list_store.contains_key(&did_dave));
}

#[test]
fn test_09_serde_roundtrip_cache_invariance_and_evaluations() {
    let (signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (signer_carol, did_carol) = create_identity();
    let (_, did_target) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Setup contacts and lists: Me -(60%)-> Bob -(85%)-> Carol -(85%)-> Target
    reg.set_contact_trust(&did_bob, 2, 4, now_secs).unwrap();
    reg.sign_own_list(&signer_me, now_secs).unwrap();

    let (wire_bob, _) = create_and_sign_sd_jwt(
        &signer_bob,
        1,
        now_secs + 10,
        4,
        &[(did_carol.clone(), 3, 4)],
    )
    .unwrap();

    let (wire_carol, _) = create_and_sign_sd_jwt(
        &signer_carol,
        1,
        now_secs + 20,
        4,
        &[(did_target.clone(), 3, 4)],
    )
    .unwrap();

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_bob, wire_carol],
        },
        None,
        now_secs + 30,
    )
    .unwrap();

    // 2. Perform initial evaluations on original instance
    let eval_voucher_orig = reg
        .evaluate_voucher(&did_target, &[&did_carol], false, Some(now_secs + 30))
        .unwrap();
    let eval_did_orig = reg.evaluate_did(&did_target, Some(now_secs + 30)).unwrap();
    let (pkg_orig, rec_orig) = reg
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();

    assert!(eval_voucher_orig.score > 0.0);
    assert!(eval_did_orig.score > 0.0);
    assert!(!pkg_orig.lists.is_empty());

    // 3. Round-trip through serde JSON
    let json_str = serde_json::to_string(&reg).expect("Serialize TrustRegister");
    let deserialized: TrustRegister =
        serde_json::from_str(&json_str).expect("Deserialize TrustRegister");

    // Invariant: ephemeral graph_cache must start empty
    // Direct read-only calls must immediately succeed identically without any mutating setup
    let eval_voucher_deser = deserialized
        .evaluate_voucher(&did_target, &[&did_carol], false, Some(now_secs + 30))
        .unwrap();
    let eval_did_deser = deserialized
        .evaluate_did(&did_target, Some(now_secs + 30))
        .unwrap();
    let (pkg_deser, rec_deser) = deserialized
        .prepare_sync_package(Some(&did_bob), None, false)
        .unwrap();

    // 4. Assert 100% identical outputs
    assert_eq!(eval_voucher_deser.score, eval_voucher_orig.score);
    assert_eq!(
        eval_voucher_deser.shortest_hops,
        eval_voucher_orig.shortest_hops
    );
    assert_eq!(
        eval_voucher_deser.paths.len(),
        eval_voucher_orig.paths.len()
    );
    assert_eq!(
        eval_voucher_deser.oldest_list_iat,
        eval_voucher_orig.oldest_list_iat
    );
    assert_eq!(
        eval_voucher_deser.blocked_by_offender,
        eval_voucher_orig.blocked_by_offender
    );

    assert_eq!(eval_did_deser.score, eval_did_orig.score);
    assert_eq!(eval_did_deser.shortest_hops, eval_did_orig.shortest_hops);
    assert_eq!(eval_did_deser.paths.len(), eval_did_orig.paths.len());

    assert_eq!(pkg_deser.lists, pkg_orig.lists);
    assert_eq!(pkg_deser.format_version, pkg_orig.format_version);
    assert_eq!(rec_deser.recipient_did, rec_orig.recipient_did);
    assert_eq!(rec_deser.entries.len(), rec_orig.entries.len());
}

#[test]
fn test_10_equivocation_rejection_and_state_preservation() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_, did_carol) = create_identity();
    let (_, did_dave) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();
    reg.set_contact_trust(&did_bob, 2, 4, now_secs).unwrap();

    // 1. Bob creates initial valid list v=10 trusting Carol
    let (wire_bob_orig, stored_orig) = create_and_sign_sd_jwt(
        &signer_bob,
        10,
        now_secs,
        4,
        &[(did_carol.clone(), 2, 4)],
    )
    .unwrap();

    let stats1 = reg
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![wire_bob_orig],
            },
            Some(&did_bob),
            now_secs,
        )
        .unwrap();
    assert_eq!(stats1.imported, 1);
    assert_eq!(
        reg.raw_list_store.get(&did_bob).unwrap().jws_compact,
        stored_orig.jws_compact
    );

    // 2. Bob equivocates: creates conflicting list with identical version v=10 but different payload (trusting Dave)
    let (wire_bob_equiv, _) = create_and_sign_sd_jwt(
        &signer_bob,
        10,
        now_secs + 1,
        4,
        &[(did_dave.clone(), 3, 4)],
    )
    .unwrap();

    let stats2 = reg
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![wire_bob_equiv],
            },
            Some(&did_bob),
            now_secs + 2,
        )
        .unwrap();

    // Conflicting JWS bodies for identical version MUST be rejected as invalid/crypto error
    assert_eq!(stats2.rejected_crypto, 1);
    assert_eq!(stats2.imported, 0);
    assert_eq!(stats2.updated, 0);

    // Invariant: original stored list MUST remain uncorrupted and intact
    let preserved = reg.raw_list_store.get(&did_bob).unwrap();
    assert_eq!(preserved.jws_compact, stored_orig.jws_compact);
    assert_eq!(preserved.v, 10);
    assert!(preserved
        .disclosures
        .values()
        .any(|d| d.target_did == did_carol));
}

#[test]
fn test_11_direct_sender_signature_verification_and_level_zero_transit_rejection() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (signer_charlie, did_charlie) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Direct sender spoofing test:
    // Create an SD-JWT purporting to be from Bob, but with tampered signature
    let (wire_bob, _) = create_and_sign_sd_jwt(
        &signer_bob,
        1,
        now_secs,
        4,
        &[(did_charlie.clone(), 3, 4)],
    )
    .unwrap();
    let mut tampered_wire = wire_bob;
    // Corrupt signature part
    tampered_wire.replace_range(10..15, "XXXXX");

    let spoof_pkg = WotSyncPackage {
        format_version: 1,
        lists: vec![tampered_wire],
    };
    let spoof_stats = reg
        .import_sync_package(&spoof_pkg, Some(&did_bob), now_secs)
        .unwrap();

    assert_eq!(spoof_stats.rejected_crypto, 1);
    assert!(!reg.raw_list_store.contains_key(&did_bob));

    // 2. Level 0 non-transit bridge test:
    // Me trusts Bob with Level 0 (existence only, gamma = 0.0)
    reg.set_contact_trust(&did_bob, 0, 4, now_secs).unwrap();

    let (valid_wire_bob, _) = create_and_sign_sd_jwt(
        &signer_bob,
        1,
        now_secs,
        4,
        &[(did_charlie.clone(), 3, 4)],
    )
    .unwrap();
    let (wire_charlie, _) =
        create_and_sign_sd_jwt(&signer_charlie, 1, now_secs, 4, &[]).unwrap();

    // Bob's list is admitted (because Bob is direct contact), but Charlie's list must be rejected
    // because Bob's Level 0 edge CANNOT serve as a transit bridge in EgoGraphCache!
    let pkg = WotSyncPackage {
        format_version: 1,
        lists: vec![valid_wire_bob, wire_charlie],
    };
    let stats = reg.import_sync_package(&pkg, None, now_secs).unwrap();
    assert_eq!(stats.imported, 1); // Bob's list
    assert_eq!(stats.rejected_spam, 1); // Charlie's list rejected as unreachable
    assert!(!reg.raw_list_store.contains_key(&did_charlie));

    // Evaluations for Level 0 contact and downstream must be 0.0
    let eval_bob = reg.evaluate_did(&did_bob, Some(now_secs)).unwrap();
    assert_eq!(eval_bob.score, 0.0);
    let eval_charlie = reg.evaluate_did(&did_charlie, Some(now_secs)).unwrap();
    assert_eq!(eval_charlie.score, 0.0);
}

#[test]
fn test_12_evaluate_voucher_edge_cases_and_oldest_iat() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_signer_carol, did_carol) = create_identity();
    let (_, did_creator) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. is_known_offender == true with creator == self_did:
    // MUST always produce score = 0.0 and blocked_by_offender = true
    let self_blocked = reg
        .evaluate_voucher(&did_me, &[], true, Some(now_secs))
        .unwrap();
    assert_eq!(self_blocked.score, 0.0);
    assert!(self_blocked.blocked_by_offender);
    assert!(self_blocked.shortest_hops.is_none());

    // 2. Wallet owner as guarantor for third-party voucher:
    // Me acts as guarantor for did_creator
    let self_guar_eval = reg
        .evaluate_voucher(&did_creator, &[&did_me], false, Some(now_secs))
        .unwrap();
    assert_eq!(self_guar_eval.score, 0.85); // Default policy.guarantor_weight
    assert_eq!(self_guar_eval.shortest_hops, Some(1));
    assert!(self_guar_eval.oldest_list_iat.is_none()); // Direct guarantee, no third-party list

    // 3. Custom policy.guarantor_weight verification:
    let custom_policy = WotPolicy {
        guarantor_weight: 0.50,
        ..Default::default()
    };
    let reg_custom = TrustRegister::new(&did_me, custom_policy).unwrap();
    let custom_eval = reg_custom
        .evaluate_voucher(&did_creator, &[&did_me], false, Some(now_secs))
        .unwrap();
    assert!(
        (custom_eval.score - 0.50).abs() < 1e-4,
        "Expected score 0.50, got {}",
        custom_eval.score
    );

    // 4. Invalid guarantor DID in guarantor_ids:
    let err_eval = reg.evaluate_voucher(&did_creator, &["not-a-did"], false, Some(now_secs));
    assert!(matches!(err_eval, Err(WotError::InvalidDid(_))));

    // 5. oldest_list_iat verification:
    // Setup 2-hop route: Me -(60%)-> Bob -(85%)-> Carol
    let iat_bob = 1_700_000_100;
    reg.set_contact_trust(&did_bob, 2, 4, now_secs).unwrap(); // Direct edge updated_at = now_secs

    let (wire_bob, _) = create_and_sign_sd_jwt(
        &signer_bob,
        1,
        iat_bob,
        4,
        &[(did_carol.clone(), 3, 4)],
    )
    .unwrap();
    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_bob],
        },
        Some(&did_bob),
        now_secs + 200,
    )
    .unwrap();

    // 1-hop evaluation to Bob: direct contact -> oldest_list_iat MUST be None
    let eval_bob = reg.evaluate_did(&did_bob, Some(now_secs)).unwrap();
    assert!(eval_bob.oldest_list_iat.is_none());

    // 2-hop evaluation to Carol: uses Bob's list -> oldest_list_iat MUST be Some(iat_bob)
    let eval_carol = reg.evaluate_did(&did_carol, Some(now_secs)).unwrap();
    assert_eq!(eval_carol.oldest_list_iat, Some(iat_bob));

    // 2-hop guarantor: Carol acts as guarantor for did_creator
    // Me -(0.60)-> Bob -(0.85)-> Carol -(0.85)-> Creator
    let eval_voucher = reg
        .evaluate_voucher(&did_creator, &[&did_carol], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_voucher.shortest_hops, Some(3));
    assert_eq!(eval_voucher.oldest_list_iat, Some(iat_bob));
    let expected_score = 0.60 * 0.85 * 0.85;
    assert!(
        (eval_voucher.score - expected_score).abs() < 1e-4,
        "Expected score ~{}, got {}",
        expected_score,
        eval_voucher.score
    );
}

#[test]
fn test_13_decoy_padding_multiples_and_input_hardening() {
    let (signer, did) = create_identity();
    let (_, peer1) = create_identity();
    let (_, _peer2) = create_identity();
    let now_secs = 1_700_000_000;

    // 1. Decoy padding: verify padding to multiples of DECOY_BUCKET_MULTIPLE (8)
    // 0 contacts -> 8
    let (w0, _) = create_and_sign_sd_jwt(&signer, 1, now_secs, 4, &[]).unwrap();
    let (_, ver0) = parse_and_verify_sd_jwt(&w0, now_secs).unwrap();
    let p0_parts: Vec<&str> = w0.split('~').next().unwrap().split('.').collect();
    let p0_bytes = URL_SAFE_NO_PAD.decode(p0_parts[1]).unwrap();
    let p0: humoco_wot::SdJwtPayload = serde_json::from_slice(&p0_bytes).unwrap();
    assert_eq!(p0._sd.len(), 8);
    assert_eq!(ver0.disclosures.len(), 0);

    // 1 contact -> 8
    let (w1, _) =
        create_and_sign_sd_jwt(&signer, 1, now_secs, 4, &[(peer1.clone(), 2, 3)]).unwrap();
    let p1_parts: Vec<&str> = w1.split('~').next().unwrap().split('.').collect();
    let p1_bytes = URL_SAFE_NO_PAD.decode(p1_parts[1]).unwrap();
    let p1: humoco_wot::SdJwtPayload = serde_json::from_slice(&p1_bytes).unwrap();
    assert_eq!(p1._sd.len(), 8);

    // 9 contacts -> 16
    let mut contacts9 = Vec::new();
    for _ in 0..9 {
        let (_, p) = create_identity();
        contacts9.push((p, 1, 2));
    }
    let (w9, _) = create_and_sign_sd_jwt(&signer, 1, now_secs, 4, &contacts9).unwrap();
    let p9_parts: Vec<&str> = w9.split('~').next().unwrap().split('.').collect();
    let p9_bytes = URL_SAFE_NO_PAD.decode(p9_parts[1]).unwrap();
    let p9: humoco_wot::SdJwtPayload = serde_json::from_slice(&p9_bytes).unwrap();
    assert_eq!(p9._sd.len(), 16);
    assert_eq!(p9._sd.len() % DECOY_BUCKET_MULTIPLE, 0);

    // 2. Input hardening: salt length < 16 bytes rejected
    let short_salt = [1u8; 15];
    assert!(matches!(
        encode_disclosure(&short_salt, &peer1, 2, 3),
        Err(WotError::MalformedSdJwt(_))
    ));

    // 3. Self-trust forbidden in create_and_sign_sd_jwt
    assert!(matches!(
        create_and_sign_sd_jwt(&signer, 1, now_secs, 4, &[(did.clone(), 2, 3)]),
        Err(WotError::SelfTrustForbidden)
    ));

    // 4. Duplicate target DID rejected
    assert!(matches!(
        create_and_sign_sd_jwt(
            &signer,
            1,
            now_secs,
            4,
            &[(peer1.clone(), 1, 2), (peer1.clone(), 2, 3)]
        ),
        Err(WotError::MalformedSdJwt(_))
    ));

    // 5. Non-canonical base58 DID rejected in canonicalize_did
    let raw_b58 = peer1.strip_prefix("did:key:z").unwrap();
    let non_canonical = format!("did:key:z1{}", raw_b58); // prepending leading zero byte in b58
    assert!(canonicalize_did(&non_canonical).is_err());

    // 6. Invalid hop limit rejected
    assert!(matches!(
        create_and_sign_sd_jwt(&signer, 1, now_secs, 0, &[]),
        Err(WotError::InvalidHopLimit(0))
    ));
    assert!(matches!(
        create_and_sign_sd_jwt(&signer, 1, now_secs, 9, &[]),
        Err(WotError::InvalidHopLimit(9))
    ));
}
