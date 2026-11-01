use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use humoco_wot::error::WotError;
use humoco_wot::identity::{
    canonicalize_did, did_from_verifying_key, extract_verifying_key, Did, Ed25519WotSigner,
    WotSigner,
};
use humoco_wot::provider_filter::create_and_sign_provider_filter;
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

#[test]
fn test_14_third_party_sync_export_guard() {
    let (signer_alice, did_alice) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_, did_carol) = create_identity(); // untrusted / unrated
    let (_, did_dave) = create_identity(); // level 0
    let (_, did_eve) = create_identity(); // level 1
    let (_, did_frank) = create_identity(); // Bob's contact

    let now_secs = 1_700_000_000;
    let mut reg_alice = TrustRegister::new(&did_alice, WotPolicy::default()).unwrap();

    // 1. Alice configures direct trust:
    // - Bob: level 2
    // - Dave: level 0
    // - Eve: level 1
    // Carol is absent from own_contacts.
    reg_alice
        .set_contact_trust(&did_bob, 2, 4, now_secs)
        .unwrap();
    reg_alice
        .set_contact_trust(&did_dave, 0, 4, now_secs)
        .unwrap();
    reg_alice
        .set_contact_trust(&did_eve, 1, 4, now_secs)
        .unwrap();
    reg_alice.sign_own_list(&signer_alice, now_secs).unwrap();

    // 2. Bob creates a signed trust list that includes Frank and Alice imports it into raw_list_store
    let (wire_bob, _) = create_and_sign_sd_jwt(
        &signer_bob,
        1,
        now_secs,
        4,
        &[(did_frank.clone(), 2, 4)],
    )
    .unwrap();

    let stats = reg_alice
        .import_sync_package(
            &WotSyncPackage {
                format_version: 1,
                lists: vec![wire_bob],
            },
            Some(&did_bob),
            now_secs,
        )
        .unwrap();
    assert_eq!(stats.imported, 1);
    assert!(reg_alice.raw_list_store.contains_key(&did_bob));

    // 3. Case A: Untargeted export (recipient_did = None)
    // Includes Alice's own list AND Bob's reachable third-party list
    let (pkg_none, receipt_none) = reg_alice
        .prepare_sync_package(None, None, false)
        .unwrap();
    assert_eq!(
        pkg_none.lists.len(),
        2,
        "Untargeted export should include reachable third-party lists"
    );
    assert_eq!(receipt_none.entries.len(), 2);

    // 4. Case B: Recipient is unrated / absent (Carol)
    // Must NOT export Bob's third-party list; ONLY Alice's own signed list
    let (pkg_carol, receipt_carol) = reg_alice
        .prepare_sync_package(Some(&did_carol), None, false)
        .unwrap();
    assert_eq!(
        pkg_carol.lists.len(),
        1,
        "Unrated recipient must not receive third-party lists"
    );
    assert_eq!(receipt_carol.entries.len(), 1);
    assert_eq!(receipt_carol.entries[0].issuer_did, did_alice);

    // 5. Case C: Recipient is rated Level 0 (Dave)
    // Must NOT export Bob's third-party list; ONLY Alice's own signed list
    let (pkg_dave, receipt_dave) = reg_alice
        .prepare_sync_package(Some(&did_dave), None, false)
        .unwrap();
    assert_eq!(
        pkg_dave.lists.len(),
        1,
        "Level 0 recipient must not receive third-party lists"
    );
    assert_eq!(receipt_dave.entries.len(), 1);
    assert_eq!(receipt_dave.entries[0].issuer_did, did_alice);

    // 6. Case D: Recipient is rated Level >= 1 (Eve)
    // Must export both Alice's own signed list AND Bob's reachable third-party list
    let (pkg_eve, receipt_eve) = reg_alice
        .prepare_sync_package(Some(&did_eve), None, false)
        .unwrap();
    assert_eq!(
        pkg_eve.lists.len(),
        2,
        "Level 1 recipient must receive reachable third-party lists"
    );
    let issuers: Vec<Did> = receipt_eve
        .entries
        .into_iter()
        .map(|e| e.issuer_did)
        .collect();
    assert!(issuers.contains(&did_alice));
    assert!(issuers.contains(&did_bob));
}

#[test]
fn test_15_evaluate_voucher_for_observer() {
    use humoco_wot::evaluate_trust_from_observer;

    let (_signer_me, did_me) = create_identity();
    let (signer_obs, did_obs) = create_identity();
    let (_, did_creator) = create_identity();
    let (_, did_guarantor) = create_identity();
    let (_, did_unknown) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Observer == Creator: returns 1.0, shortest_hops = Some(0)
    // 1a. Bare DIDs
    let eval_same = reg
        .evaluate_voucher_for_observer(&did_creator, &did_creator, &[], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_same.score, 1.0);
    assert_eq!(eval_same.shortest_hops, Some(0));
    assert!(eval_same.paths.is_empty());
    assert!(!eval_same.blocked_by_offender);

    // 1b. Prefixed observer vs bare creator
    let pref_obs = format!("tenant-1:chk@{}", did_creator);
    let eval_pref1 = reg
        .evaluate_voucher_for_observer(&pref_obs, &did_creator, &[], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_pref1.score, 1.0);
    assert_eq!(eval_pref1.shortest_hops, Some(0));

    // 1c. Bare observer vs prefixed creator
    let pref_creator = format!("pos-store:chk@{}", did_creator);
    let eval_pref2 = reg
        .evaluate_voucher_for_observer(&did_creator, &pref_creator, &[], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_pref2.score, 1.0);
    assert_eq!(eval_pref2.shortest_hops, Some(0));

    // 2. Known offender veto: returns score 0.0, blocked_by_offender = true
    let eval_offender = reg
        .evaluate_voucher_for_observer(&did_obs, &did_creator, &[], true, Some(now_secs))
        .unwrap();
    assert_eq!(eval_offender.score, 0.0);
    assert_eq!(eval_offender.shortest_hops, None);
    assert!(eval_offender.paths.is_empty());
    assert!(eval_offender.blocked_by_offender);

    // 3. Unknown observer in graph: returns score 0.0, shortest_hops = None, no error
    let eval_unknown = reg
        .evaluate_voucher_for_observer(&did_unknown, &did_creator, &[], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_unknown.score, 0.0);
    assert_eq!(eval_unknown.shortest_hops, None);
    assert!(eval_unknown.paths.is_empty());
    assert!(!eval_unknown.blocked_by_offender);

    // 4. Observer is self (did_me)
    reg.set_contact_trust(&did_creator, 2, 4, now_secs).unwrap(); // 60%
    let eval_self = reg
        .evaluate_voucher_for_observer(&did_me, &did_creator, &[], false, Some(now_secs))
        .unwrap();
    let eval_direct = reg
        .evaluate_voucher(&did_creator, &[], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_self.score, eval_direct.score);
    assert_eq!(eval_self.shortest_hops, eval_direct.shortest_hops);

    // 5. Observer trusts creator directly via imported SD-JWT list:
    // Me trusts Observer with Level 1 (30%) so list is accepted
    reg.set_contact_trust(&did_obs, 1, 4, now_secs).unwrap();

    let obs_list_iat = 1_700_000_050;
    let (wire_obs, _) = create_and_sign_sd_jwt(
        &signer_obs,
        1,
        obs_list_iat,
        4,
        &[
            (did_creator.clone(), 2, 4),   // 60% direct trust from Observer to Creator
            (did_guarantor.clone(), 3, 4), // 85% trust from Observer to Guarantor
        ],
    )
    .unwrap();

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_obs],
        },
        Some(&did_obs),
        now_secs + 100,
    )
    .unwrap();

    // From Observer's perspective: direct trust to Creator is Level 2 (60%)
    let eval_obs_direct = reg
        .evaluate_voucher_for_observer(&did_obs, &did_creator, &[], false, Some(now_secs))
        .unwrap();
    assert!((eval_obs_direct.score - 0.60).abs() < 1e-6);
    assert_eq!(eval_obs_direct.shortest_hops, Some(1));
    assert_eq!(eval_obs_direct.oldest_list_iat, Some(obs_list_iat));
    assert_eq!(eval_obs_direct.paths.len(), 1);
    assert_eq!(
        eval_obs_direct.paths[0].hops,
        vec![did_obs.clone(), did_creator.clone()]
    );
    assert_eq!(eval_obs_direct.paths[0].edge_levels, vec![2]);

    // 6. Observer trusts creator via guarantor bridge:
    // Suppose a separate creator identity that observer does NOT trust directly:
    let (_, did_creator2) = create_identity();
    let eval_obs_guarantor = reg
        .evaluate_voucher_for_observer(
            &did_obs,
            &did_creator2,
            &[&did_guarantor],
            false,
            Some(now_secs),
        )
        .unwrap();
    // Path: Observer -(85% Level 3)-> Guarantor -(85% guarantor weight)-> Creator2
    // Expected score = 0.85 * 0.85 = 0.7225
    let expected_g_score = 0.85 * 0.85;
    assert!((eval_obs_guarantor.score - expected_g_score).abs() < 1e-4);
    assert_eq!(eval_obs_guarantor.shortest_hops, Some(2));
    assert_eq!(eval_obs_guarantor.oldest_list_iat, Some(obs_list_iat));
    assert_eq!(
        eval_obs_guarantor.paths[0].hops,
        vec![did_obs.clone(), did_guarantor.clone(), did_creator2.clone()]
    );

    // 7. Verify standalone function evaluate_trust_from_observer
    let graph = reg.get_or_build_graph_cache();
    let eval_standalone = evaluate_trust_from_observer(
        &graph,
        &reg.policy,
        &did_obs,
        &did_creator,
        &[],
        false,
        Some(now_secs),
    )
    .unwrap();
    assert!((eval_standalone.score - 0.60).abs() < 1e-6);
}

#[test]
fn test_16_global_hop_management_and_guarantor_bridge_retention() {
    let (_signer_me, did_me) = create_identity();
    let (_, did_bob) = create_identity();
    let (_, did_carol) = create_identity();
    let (_, did_creator) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // Setup direct contacts: Bob (Level 2), Carol (Level 0)
    reg.set_contact_trust(&did_bob, 2, 4, now_secs).unwrap();
    reg.set_contact_trust(&did_carol, 0, 4, now_secs).unwrap();
    reg.own_list_dirty = false;

    // Reject invalid hops
    assert!(matches!(reg.set_own_list_max_hops(0, now_secs + 10), Err(WotError::InvalidHopLimit(0))));
    assert!(matches!(reg.set_own_list_max_hops(9, now_secs + 10), Err(WotError::InvalidHopLimit(9))));

    // Set global max hops to 1
    reg.set_own_list_max_hops(1, now_secs + 10).unwrap();
    assert_eq!(reg.policy.own_list_max_hops, 1);
    assert_eq!(reg.own_contacts.get(&did_bob).unwrap().desired_hops, 1);
    assert_eq!(reg.own_contacts.get(&did_bob).unwrap().updated_at, now_secs + 10);
    // Level 0 contact was not modified
    assert_eq!(reg.own_contacts.get(&did_carol).unwrap().desired_hops, 4);
    assert!(reg.own_list_dirty);

    // Invariant: max_eval_depth and max_import_depth MUST NOT shrink (remain at least 5)
    assert!(reg.policy.max_eval_depth >= 5);
    assert!(reg.policy.max_import_depth >= 5);

    // Guarantor bridge test: Even though own_list_max_hops is 1, a 2-hop voucher guarantee
    // Me -(0.60)-> Bob -(0.85 guarantor_weight)-> Creator MUST still evaluate successfully!
    let eval = reg
        .evaluate_voucher(&did_creator, &[&did_bob], false, Some(now_secs + 20))
        .unwrap();
    assert_eq!(eval.shortest_hops, Some(2));
    let expected_score = 0.60 * 0.85;
    assert!((eval.score - expected_score).abs() < 1e-4);
}

#[test]
fn test_17_age_decay_grace_period_and_half_life() {
    let (_signer_me, did_me) = create_identity();
    let (signer_bob, did_bob) = create_identity();
    let (_, did_carol) = create_identity();

    let now_secs = 1_700_000_000;
    let one_year = 31_536_000_u64;

    let policy = WotPolicy {
        freshness_grace_secs: one_year,
        freshness_half_life_secs: Some(one_year),
        ..Default::default()
    };
    let mut reg = TrustRegister::new(&did_me, policy).unwrap();

    // Me trusts Bob Level 3 (85%)
    reg.set_contact_trust(&did_bob, 3, 4, now_secs).unwrap();

    // Case 1: Bob's list iat is 364 days ago (within 1-year grace period)
    let iat_fresh = now_secs - (one_year - 86400);
    let (wire_fresh, _) = create_and_sign_sd_jwt(&signer_bob, 1, iat_fresh, 4, &[(did_carol.clone(), 3, 4)]).unwrap();
    reg.raw_list_store.clear();
    reg.import_sync_package(&WotSyncPackage { format_version: 1, lists: vec![wire_fresh] }, Some(&did_bob), now_secs).unwrap();

    let eval_fresh = reg.evaluate_did(&did_carol, Some(now_secs)).unwrap();
    let full_strength = 0.85 * 0.85;
    assert!((eval_fresh.score - full_strength).abs() < 1e-4, "Expected full strength, got {}", eval_fresh.score);

    // Case 2: Bob's list iat is 2 years ago (1 year grace + 1 year half-life -> 50% decay)
    let iat_2yr = now_secs - (2 * one_year);
    let (wire_2yr, _) = create_and_sign_sd_jwt(&signer_bob, 2, iat_2yr, 4, &[(did_carol.clone(), 3, 4)]).unwrap();
    reg.raw_list_store.clear();
    reg.import_sync_package(&WotSyncPackage { format_version: 1, lists: vec![wire_2yr] }, Some(&did_bob), now_secs).unwrap();

    let eval_2yr = reg.evaluate_did(&did_carol, Some(now_secs)).unwrap();
    let half_strength = full_strength * 0.5;
    assert!((eval_2yr.score - half_strength).abs() < 1e-4, "Expected half strength, got {}", eval_2yr.score);

    // Case 3: Bob's list iat is 3 years ago (1 year grace + 2 years half-life -> 25% decay)
    let iat_3yr = now_secs - (3 * one_year);
    let (wire_3yr, _) = create_and_sign_sd_jwt(&signer_bob, 3, iat_3yr, 4, &[(did_carol.clone(), 3, 4)]).unwrap();
    reg.raw_list_store.clear();
    reg.import_sync_package(&WotSyncPackage { format_version: 1, lists: vec![wire_3yr] }, Some(&did_bob), now_secs).unwrap();

    let eval_3yr = reg.evaluate_did(&did_carol, Some(now_secs)).unwrap();
    let quarter_strength = full_strength * 0.25;
    assert!((eval_3yr.score - quarter_strength).abs() < 1e-4, "Expected quarter strength, got {}", eval_3yr.score);
}

#[test]
fn test_18_sync_package_size_limit_continue_behavior() {
    let (signer_me, did_me) = create_identity();
    let (mut signer_large, mut did_large) = create_identity();
    let (mut signer_small, mut did_small) = create_identity();
    let (_, did_dave) = create_identity();

    // Ensure did_large sorts lexicographically before did_small so it is evaluated first
    if did_large > did_small {
        std::mem::swap(&mut signer_large, &mut signer_small);
        std::mem::swap(&mut did_large, &mut did_small);
    }

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // Me trusts Large, Small, and Dave (Level >= 1 so third-party sync is allowed)
    reg.set_contact_trust(&did_large, 2, 4, now_secs).unwrap();
    reg.set_contact_trust(&did_small, 2, 4, now_secs).unwrap();
    reg.set_contact_trust(&did_dave, 2, 4, now_secs).unwrap();
    reg.sign_own_list(&signer_me, now_secs).unwrap();

    // Large list: list with many disclosures (large byte footprint)
    let mut large_contacts = Vec::new();
    for _ in 0..15 {
        let (_, dummy) = create_identity();
        large_contacts.push((dummy, 1, 4));
    }
    let (wire_large, _) = create_and_sign_sd_jwt(&signer_large, 1, now_secs, 4, &large_contacts).unwrap();

    // Small list: minimal empty list
    let (wire_small, _) = create_and_sign_sd_jwt(&signer_small, 1, now_secs, 4, &[]).unwrap();

    reg.import_sync_package(
        &WotSyncPackage {
            format_version: 1,
            lists: vec![wire_large.clone(), wire_small.clone()],
        },
        None,
        now_secs,
    )
    .unwrap();

    // Set max_bytes such that Alice's own list + Small list fit, but Large list does NOT fit!
    let own_wire = reg.own_signed_list.as_ref().unwrap().to_redacted_wire_string(1).unwrap();
    let base_len = 31;
    let own_len = own_wire.len() + 2;
    let small_len = wire_small.len() + 3;
    let tight_limit = base_len + own_len + small_len + 10;

    let (pkg, receipt) = reg.prepare_sync_package(Some(&did_dave), Some(tight_limit), true).unwrap();

    // Verify Large list was evaluated first and skipped, but Small list was still included via continue!
    let issuers: Vec<Did> = receipt.entries.into_iter().map(|e| e.issuer_did).collect();
    assert!(issuers.contains(&did_me), "Own list must be included");
    assert!(issuers.contains(&did_small), "Small list must be included via continue");
    assert!(!issuers.contains(&did_large), "Large list must have been skipped due to size limit");
    assert_eq!(pkg.lists.len(), 2);
}

#[test]
fn test_19_provider_filter_integration_and_voucher_evaluation() {
    let (_signer_me, did_me) = create_identity();
    let (signer_prov, did_prov) = create_identity();
    let (_, did_creator) = create_identity();
    let (_, did_guarantor) = create_identity();

    let now_secs = 1_700_000_000;
    let mut reg = TrustRegister::new(&did_me, WotPolicy::default()).unwrap();

    // 1. Create and sign provider filter:
    // Provider certifies Creator at Level 3 (85%) and Guarantor at Level 2 (60%)
    let members = vec![
        (did_creator.clone(), 3),
        (did_guarantor.clone(), 2),
    ];
    let filter_v1 = create_and_sign_provider_filter(
        &signer_prov,
        "Regional Handwerker Verband",
        10,
        now_secs,
        Some("https://verband.org/registry".to_string()),
        &members,
    )
    .expect("create provider filter");

    // Import provider filter into TrustRegister
    let imported_did = reg.import_provider_filter(&filter_v1, now_secs).expect("import filter");
    assert_eq!(imported_did, did_prov);

    // Verify local_trust_level is initially 0 -> evaluation should not use it yet
    let eval_untrusted = reg.evaluate_voucher(&did_creator, &[], false, Some(now_secs)).unwrap();
    assert_eq!(eval_untrusted.score, 0.0);

    // Set local trust level for provider to Level 2 (60%)
    reg.set_provider_trust(&did_prov, 2).unwrap();

    // Evaluation 1: Creator match in provider filter
    // Path: Me -(60% Level 2)-> Provider -(85% Level 3)-> Creator
    // Score: 0.60 * 0.85 = 0.51, Hops = 2
    let eval_creator = reg.evaluate_voucher(&did_creator, &[], false, Some(now_secs)).unwrap();
    assert_eq!(eval_creator.shortest_hops, Some(2));
    let expected_creator_score = 0.60 * 0.85;
    assert!((eval_creator.score - expected_creator_score).abs() < 1e-4);

    // Evaluation 2: Guarantor match in provider filter
    // Creator is unknown, but Guarantor is certified by Provider
    let (_, did_unknown_creator) = create_identity();
    // Path: Me -(60% Level 2)-> Provider -(60% Level 2)-> Guarantor -(85% gw)-> UnknownCreator
    // Score: 0.60 * 0.60 * 0.85 = 0.306, Hops = 3
    let eval_guar = reg
        .evaluate_voucher(&did_unknown_creator, &[&did_guarantor], false, Some(now_secs))
        .unwrap();
    assert_eq!(eval_guar.shortest_hops, Some(3));
    let expected_guar_score = 0.60 * 0.60 * 0.85;
    assert!((eval_guar.score - expected_guar_score).abs() < 1e-4);

    // Evaluation 3: Bottleneck cap enforcement
    // Me trusts Provider with Level 1 (30%).
    // Both Creator AND Guarantor are certified at Level 3 (85%).
    reg.set_provider_trust(&did_prov, 1).unwrap();
    let eval_bottleneck = reg
        .evaluate_voucher(&did_creator, &[&did_guarantor], false, Some(now_secs))
        .unwrap();
    // Shannon factoring bottleneck: Score CANNOT exceed User's trust in Provider (0.30)!
    assert!(
        eval_bottleneck.score <= 0.300000001,
        "Score must not exceed 0.30 bottleneck, got {}",
        eval_bottleneck.score
    );

    // 2. Tampering test
    let mut tampered = filter_v1.clone();
    tampered.replace_range(30..35, "XXXXX");
    assert!(reg.import_provider_filter(&tampered, now_secs).is_err());

    // 3. Rollback rejection: incoming version v=9 < existing v=10
    let filter_v_old = create_and_sign_provider_filter(
        &signer_prov,
        "Regional Handwerker Verband",
        9,
        now_secs,
        None,
        &members,
    )
    .unwrap();
    assert!(matches!(
        reg.import_provider_filter(&filter_v_old, now_secs),
        Err(WotError::LimitExceeded(_))
    ));

    // 4. Update with higher version v=11: preserves local_trust_level
    let filter_v_new = create_and_sign_provider_filter(
        &signer_prov,
        "Regional Handwerker Verband",
        11,
        now_secs,
        None,
        &members,
    )
    .unwrap();
    reg.import_provider_filter(&filter_v_new, now_secs).unwrap();
    assert_eq!(reg.provider_filters.get(&did_prov).unwrap().local_trust_level, 1);

    // 5. Equivocation rejection: same version v=11 with different members
    let (_, did_other) = create_identity();
    let filter_equiv = create_and_sign_provider_filter(
        &signer_prov,
        "Regional Handwerker Verband",
        11,
        now_secs,
        None,
        &[(did_other, 3)],
    )
    .unwrap();
    assert!(matches!(
        reg.import_provider_filter(&filter_equiv, now_secs),
        Err(WotError::EquivocationDetected { .. })
    ));

    // 6. Remove provider filter
    let removed = reg.remove_provider_filter(&did_prov).unwrap();
    assert!(removed);
    assert!(!reg.provider_filters.contains_key(&did_prov));
}
