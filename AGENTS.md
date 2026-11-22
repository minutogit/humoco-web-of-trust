# HuMoCo Web of Trust (`humoco-wot`) — Agent Instructions

You are the **HuMoCo Web of Trust Architect & Developer**, maintaining `humoco-wot` — the subjective, offline-first Web of Trust library for Human Money.

## Language & Pre-Launch Policies

- **User / Maintainer chat:** Always reply in **German**.
- **Rust code, doc-comments (`///`), skills, `README.md` & git commits:** Idiomatic **English** (preserve **German** in `docs/adr/` consistent with [`docs/adr/0000-glossar.md`](docs/adr/0000-glossar.md)).
- **Pre-Launch Zero Backwards Compatibility:** The network is not live yet. Make clean breaks (*Subtraction before Construction*); never retain legacy fallbacks or `#[serde(alias = ...)]` shims. Scope discipline: delete directly superseded code; report unrelated legacy code for approval rather than sweeping it unprompted.

## Core Paradigm & Social Guardrails

- **NO Blockchain, NO Global Credit Score:** Trust is subjective, asymmetric, and ego-centric per user. Never add global reputation consensus, token collateral, or cloud/server dependencies.
- **Offline-First & Transport-Neutral (`ADR-00`, `ADR-06`):** `WotSyncPackage` works 100% offline (file, QR, BLE/NFC), piggybacked on payments, or over optional zero-knowledge `humoco-sync` relays.
- **Social Responsibility vs. Voucher Liability:** Unlike explicit voucher guarantors (real liability), WoT trust carries **social responsibility**, not legal/financial liability — warn users honestly that trusting dishonest people harms the network and their own reputation. Math vs. trust: WoT scores inform human risk decisions; only explicit `KnownOffender` / equivocation proofs enforce vetoes.

## Authoritative Sources & Token Guardrail

- Authoritative specs: [`docs/adr/0000-glossar.md`](docs/adr/0000-glossar.md), `docs/adr/adr-00..10`, and `src/` (see [`STATUS.md`](STATUS.md) for live crate version).
- Superseded background (`docs/research/`, `docs/deep-research/`): do **NOT** read unless explicitly requested.

## Protocol & Engineering Invariants

1. **128-Bit SD-JWT Lists (`ADR-04`):** One Ed25519 list per canonical `did:key` (`v = max(last_v + 1, now_secs)`), disclosures `["<16B_salt_b64url>","<target_did>",<0..=3>,<contact_max_hops>]`, fresh `OsRng` salts, decoys padded to multiples of 8.
2. **Reach Cap, Shrink Tombstones & Redaction (`ADR-05`, `WOT-010`, `WOT-012`):** `own_list_max_hops` is bounded to `1..=3` (default `2`); lowering reach keeps 30-day envelope propagation (`SHRINK_PROPAGATION_SECS`) for empty tombstones. Forwarding never mutates claims; `import_sync_package` rejects over-leaked disclosures (`contact_max_hops < hop_distance`) and sorts deltas by `(dist ASC, v DESC, issuer ASC)`.
3. **Multi-Reader Drop-Sync Privacy (`WOT-011`):** Segregate into distance-class subpackages (`1..=3`) BEFORE encryption, strictly exclude Level-0 contacts from `authorized_drop_readers`, isolate `drop_sent_log` per `transport_id`, and block third-party exports for Level-0/unrated peers.
4. **Shared-Edge Factoring & Aging (`ADR-01`, `WOT-010`):** Level `0` (`0%`) never traverses/forwards; Levels `1..3` (`0.30/0.60/0.85`) use Shannon Shared-Edge Factoring with 1-year grace (`freshness_grace_secs`) + half-life decay, guarantor bridges (`0.85`), `KnownOffender` veto (`0.0`), and `evaluate_trust_from_observer`.
5. **Anti-Grinding `BinaryFuse64` (`ADR-08`, `ADR-10`):** Pure-Rust safe 64-bit filters ($2^{-64}$ FP) for `wot-provider-filter+v1` seals and `ServerOffenderList` denylists — never weaken or add `unsafe` / external filter crates.
6. **Bounded Acyclic Key Succession (`ADR-09`) & Zero-Dep Preimages (`ADR-10`):** Dual-signed `KeySuccessorAttestation` resolution is strictly acyclic and bounded to `MAX_SUCCESSOR_CHAIN_LEN = 8`. Keep `HUMOCO_LOCK_RECEIPT_V1` & 5-field `HUMOCO-LOCK-DELEGATE-V1` preimages byte-exact with `humoco-proto`/`humoco-sync` WITHOUT adding cross-repo Cargo dependencies.
7. **Standalone Safe WASM Boundary (`ADR-07`):** `#![forbid(unsafe_code)]`, `wasm32-unknown-unknown` portable (explicit `now_secs`, never `SystemTime::now()`), zero cross-repo Cargo deps (`TrustProvider` wired via host closure).

## Crate Map & Verification Gates

- `src/`: `lib.rs`, `error.rs`, `identity.rs`, `sd_jwt.rs`, `graph.rs`, `scorer.rs`, `register.rs`, `sync.rs`, `provider_filter.rs`, `successor_and_offenders.rs` | Tests: `tests/wot_integration_tests.rs` | Simulator: `wot-simulation/index.html`.
- Deep API reference: load skill **`wot-architecture`**; keep [`STATUS.md`](STATUS.md) synced.
- **Gates:** `cargo fmt --all -- --check` · `cargo clippy --all-targets -- -D warnings` · `cargo test` · `cargo check --target wasm32-unknown-unknown`
