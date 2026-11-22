---
name: wot-architecture
description: Deep API, data structure, and ADR 00-10 reference for humoco-wot (Dual-Storage, Drop-Sync subpackages, BinaryFuse64 seals, KeySuccessorAttestation, and ServerOffenderList).
---

# SKILL: HuMoCo Web of Trust API & Architecture (`ADR 00–10`)

> **Authoritative Specs:** [`docs/adr/0000-glossar.md`](../../../docs/adr/0000-glossar.md) and [`adr-00`](../../../docs/adr/adr-00-wot-grundprinzip.md) through [`adr-10`](../../../docs/adr/adr-10-server-sanktionsliste-server-offender-list.md) paired with [`src/lib.rs`](../../../src/lib.rs). Protocol invariants live in [`AGENTS.md`](../../../AGENTS.md).

## 1. ADR Index (`docs/adr/`)

- `0000-glossar.md` — Canonical German domain glossary.
- `adr-00` — Subjective, offline-first, transport-neutral foundation.
- `adr-01` — Multiplicative damping & Shannon Shared-Edge Factoring.
- `adr-03` — 4-tier trust levels (0: F2F existence 0%, 1: 30%, 2: 60%, 3: 85%) & social responsibility.
- `adr-04` — 128-bit truncated SD-JWT lists, `OsRng` salts, decoys (multiple of 8), monotonic `v = max(last_v + 1, now_secs)`.
- `adr-05` — Signature-preserving distance redaction & Tit-for-Tat reciprocal hop caps.
- `adr-06` — 2-phase delta-sync (`Sent-Log`), topological spam filter & same-version union-merge.
- `adr-07` — Dual-storage (`TrustRegister` + `EgoGraphCache`), handshake admission, closure-based `TrustProvider`.
- `adr-08` — Pure-Rust safe `BinaryFuse64` signed provider seals (`wot-provider-filter+v1`).
- `adr-09` — Dual-signed acyclic `KeySuccessorAttestation` (`HUMOCO_KEY_SUCCESSOR_V1`, `MAX_SUCCESSOR_CHAIN_LEN = 8`).
- `adr-10` — `ServerOffenderList` (`WotEquivocationProof` + 5-field `HUMOCO-LOCK-DELEGATE-V1` + `BinaryFuse64` denylist).

## 2. Dual-Storage Data Model (`src/register.rs`, `src/graph.rs`)

- **`TrustRegister`:**
  - `self_did: Did`, `own_contacts: BTreeMap<Did, OwnTrustEntry>`, `own_signed_list: Option<StoredSdJwt>`, `own_list_dirty: bool`.
  - `raw_list_store: BTreeMap<Did, StoredSdJwt>`, `sent_log: BTreeMap<Did, BTreeMap<Did, SentRecord>>`.
  - `drop_sent_log: BTreeMap<String, DropSentRecord>` (keyed by `transport_id`, `WOT-011`).
  - `shrink_hops: u8`, `shrink_until: u64` (`SHRINK_PROPAGATION_SECS = 30d`).
  - `provider_filters: BTreeMap<Did, StoredProviderFilter>` (`WOT-010`/`ADR-08`).
  - `policy: WotPolicy` (`unreciprocated_hops: 1`, `own_list_max_hops: 2`, `max_import_depth: 5`, `max_eval_depth: 5`, `guarantor_weight: 0.85`, `freshness_half_life_secs: Some(31_536_000)`, `freshness_grace_secs: 31_536_000`).
- **`EgoGraphCache`:** Ephemeral `#[serde(skip)]` adjacency cache built lazily from `level >= 1` edges for BFS hop distances and Shannon factoring.

## 3. Public API Reference (`src/`)

- **Local Contacts & Signing (`register.rs`):**
  - `TrustRegister::new(self_did, policy)`
  - `set_contact_trust(target_did, level, desired_hops, now_secs)` / `remove_contact_trust(target_did)`
  - `set_own_list_max_hops(max_hops, now_secs)` (`1..=3`, default `2`, preserves 30d shrink tombstones without shrinking `max_eval_depth`/`max_import_depth`)
  - `sign_own_list(signer, now_secs)` / `ensure_own_list_signed(signer, now_secs)`
  - `prune_unreachable_lists()` / `prune_unreachable_lists_preserving(preserve_did)`
- **P2P & Multi-Reader Drop Sync (`sync.rs`):**
  - `prepare_sync_package(recipient_did, max_bytes, force_full)` / `commit_sync_receipt(receipt, now_secs)`
  - `authorized_drop_readers()` (excludes Level `0`)
  - `prepare_drop_sync_subpackages(transport_id, custom_readers, max_class_package_bytes, force_full)` (distance-class segregated, sorted `(dist ASC, v DESC, issuer ASC)`)
  - `commit_drop_sync_receipt(receipt, now_secs)` / `clear_drop_sent_log(transport_id)`
  - `import_sync_package(package, direct_sender_did, now_secs)` (verifies Ed25519, reachability, and redaction depth)
- **Scoring & Provider Seals (`register.rs`, `scorer.rs`, `provider_filter.rs`):**
  - `evaluate_did(target_did, now_secs: Option<u64>)`
  - `evaluate_voucher(creator_id, guarantor_ids, is_known_offender, now_secs: Option<u64>)`
  - `evaluate_voucher_for_observer(observer_did, creator_id, guarantor_ids, is_known_offender, now_secs: Option<u64>)`
  - `import_provider_filter(raw_json, now_secs)` / `set_provider_trust(issuer_did, level)` / `remove_provider_filter(issuer_did)`
  - `create_and_sign_provider_filter` / `parse_and_verify_provider_filter` / `BinaryFuse64`
- **Key Succession & Server Offenders (`successor_and_offenders.rs`):**
  - `KeySuccessorAttestation::{signing_digest, sign_dual, verify}` & `resolve_successor_chain`
  - `ServerOffenderList::{new, insert_verified, is_lock_pub_revoked, is_admin_pub_revoked, build_denylist_filter, filter_contains_pubkey}`
  - `WotLockReceipt`, `WotEquivocationProof`, `WotLockDelegation` (5-field `HUMOCO-LOCK-DELEGATE-V1`)
