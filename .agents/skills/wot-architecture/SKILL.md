---
name: wot-architecture
description: Technical architecture of the HuMoCo Offline-First Web of Trust based on ADRs 00–07 (128-bit SD-JWTs, Tit-for-Tat routing, Dual Storage, Shannon Factoring, and gossip sync).
---

# SKILL: HuMoCo Web of Trust Architecture (`ADR 00–07`)

> **Authoritative Baseline:** Architecture Decision Records ([`docs/adr/0000-glossar.md`](../../docs/adr/0000-glossar.md) through [`adr-07`](../../docs/adr/adr-07-datenstruktur-speicher-und-schnittstellen.md)) and the `humoco-wot` crate ([`src/`](../../src/)) define the production architecture. Early research papers in `docs/research/` (Cuckoo filters, peppers, RSA accumulators, fixed Euro limits) are superseded historical background.

## 1. Architectural Decisions (`ADRs 00–07`)

- **ADR-00 (Subjective, Offline-First & Transport-Neutral):**
  Ego-centric trust computed per user (no global blockchain, no global credit score). `WotSyncPackage` operates 100% offline (file, QR, BLE/NFC), piggybacked on payments, or via optional zero-trust relays.
- **ADR-01 (Path Math & Shannon Factoring):**
  Multiplicative damping $T(P) = \prod_{e \in P} \gamma(e)$. Disjoint paths combine via $1 - \prod (1 - R_c)$. Shared-edge bottlenecks decompose via exact Shannon factoring: Sybil clusters behind a 30% bottleneck never exceed 30%, regardless of how many fake paths are generated.
- **ADR-03 (4-Tier Trust & Social Liability):**
  Level 0 (Human Existence F2F, 0% financial trust, anti-bot only, never traversed/forwarded), Level 1 (Acquaintance, 30%, ~0.5h work liability), Level 2 (Good Contact, 60%, ~1.0h), Level 3 (Confidant, 85%, ~4.0h).
- **ADR-04 (128-Bit SD-JWT Trust Lists):**
  Each user maintains one signed Ed25519 list per canonical `did:key`. Truncated 128-bit SHA-256 digests save QR/radio bandwidth while maintaining $2^{128}$ collision resistance. Monotonic versioning $v = \max(\text{last\_v} + 1, \text{now})$, fresh `OsRng` salts on every version, and decoy digests padded to multiples of 8.
- **ADR-05 (Distance Redaction & Tit-for-Tat):**
  Forwarding nodes never mutate claims. For recipient distance $d_{\text{target}} = d + 1$, lists with `max_hops < d_target` are omitted and disclosures with `contact_max_hops < d_target` are stripped while preserving the issuer's signature. Unreciprocated contacts cap at `unreciprocated_hops` (default 1).
- **ADR-06 (2-Phase Gossip Delta-Sync):**
  Read-only `prepare_sync_package` orders deltas with Hop-1 prioritized and checks local `SentRecord`. Sender persists `commit_sync_receipt` only upon confirmed transmission. `import_sync_package` filters unlinked island spam via topological reachability (`max_import_depth`) and performs same-version union-merge.
- **ADR-07 (Data Structure, Storage & Interfaces):**
  Dual-storage design (`TrustRegister` + `EgoGraphCache`), decoupled handshake admission (`direct_sender_did`), WASM-safe explicit `now_secs`, and zero cross-repo Cargo dependencies (`TrustProvider` wired via closure in the host).

## 2. Dual-Storage Model & Crate Layout (`src/`)

- **`TrustRegister` ([`src/register.rs`](../../src/register.rs)):**
  Persistent, serde-serializable state:
  - `own_contacts: BTreeMap<Did, OwnTrustEntry>` — local direct trust settings and desired hop limits.
  - `own_signed_list: Option<StoredSdJwt>` & `own_list_dirty: bool` — self-signed SD-JWT list and re-sign flag.
  - `raw_list_store: BTreeMap<Did, StoredSdJwt>` — collected third-party SD-JWT tokens required for signature-preserving forwarding.
  - `sent_log: BTreeMap<Did, BTreeMap<Did, SentRecord>>` — local delivery records tracking `(version, sent_at, disclosure_fingerprint)` per recipient.
  - `policy: WotPolicy` — configurable limits (`unreciprocated_hops`, `own_list_max_hops`, `max_import_depth`, `max_eval_depth`, `guarantor_weight`, `freshness_half_life_secs`).
- **`EgoGraphCache` ([`src/graph.rs`](../../src/graph.rs)):**
  Ephemeral `#[serde(skip)]` in-memory `u32` adjacency cache built on-demand from `level >= 1` edges for sub-millisecond BFS hop-distance queries and DFS + Shannon factoring evaluations.

## 3. Public API Workflow (`TrustRegister`)

- `set_contact_trust(target_did, level, desired_hops, now_secs)` / `remove_contact_trust(target_did)`: Updates local contact assignment, prunes unreachable orphans if needed, and sets `own_list_dirty = true`.
- `sign_own_list(signer, now_secs)` / `ensure_own_list_signed(signer, now_secs)`: Issues a new SD-JWT list with bumped version, Tit-for-Tat effective hops, fresh salts, and decoy padding.
- `prepare_sync_package(recipient_did, max_bytes, force_full)`: Read-only assembly of a distance-redacted, Hop-1 prioritized `(WotSyncPackage, SyncReceipt)` delta.
- `commit_sync_receipt(receipt, now_secs)`: Records sent `(version, disclosure_fingerprint)` entries into `sent_log` upon confirmed delivery.
- `import_sync_package(package, direct_sender_did, now_secs)`: Verifies Ed25519 signatures, enforces topological reachability (plus optional 1-list handshake admission), merges deltas, and flags `own_list_dirty` if Tit-for-Tat caps changed.
- `evaluate_did(target_did, now_secs)`: Computes `TrustEvaluation` (`score`, `shortest_hops`, `paths`, `oldest_list_iat`, `blocked_by_offender`) via Shannon Shared-Edge Factoring.
- `evaluate_voucher(creator_id, guarantor_ids, is_known_offender, now_secs)`: Enforces immediate `KnownOffender` veto (`0.0`) and evaluates temporary `guarantor -> creator` bridges (`policy.guarantor_weight`).
- `prune_unreachable_lists()`: Garbage-collects disconnected third-party lists from `raw_list_store`.

## 4. Next Ecosystem Integrations

- **`CORE-002`:** Connect `humoco-wot` to `human-money-core` via closure in the host app (`TrustProvider` trait) and transaction piggybacking hooks.
- **`APP-002`:** Render trust scores, 30/60/85 badges, and contact trust sliders in `human-money-app`.
- **`WOT-004`:** Finalize visual trust indicator and badge UX guidelines.
