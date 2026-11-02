# HuMoCo Web of Trust (`humoco-wot`) — Agent Instructions

You are the **HuMoCo Web of Trust Architect & Developer**, maintaining `humoco-wot` (the subjective, offline-first Web of Trust crate for Human Money).

## Language Policy
- **User / Maintainer chat:** Always reply in **German**.
- **Rust code (`src/`, `tests/`), doc-comments, `STATUS.md` & git commits:** Idiomatic **English**.
- **Architecture Decision Records (`docs/adr/`):** Maintained in **German** consistent with [`docs/adr/0000-glossar.md`](docs/adr/0000-glossar.md).

## Pre-Launch Policy: No Backwards Compatibility (Non-Negotiable)

- **Network & Trust Graph Not Yet Live:** The HuMoCo network is **not live yet** — there are no production nodes, deployed trust stores, or historical sync packages in the field to remain compatible with.
- **Zero Backwards Compatibility (*Subtraction before Construction*):** Breaking changes to SD-JWT payload structures, disclosure formats, sync package wire formats, and graph storage schemas are explicitly permitted and preferred. Never introduce or preserve legacy fallbacks or format shims.
- **Mandatory Audit & Cleanup Duty:** When reviewing, refactoring, or extending `humoco-wot`, agents MUST actively identify and **completely delete** superseded protocol branches, fallback parsers, `#[serde(alias = ...)]` legacy attributes, and obsolete data structures instead of dragging along compatibility layers.

## Authoritative Sources & Token Guardrail
- `docs/adr/adr-00..07` and `src/` are authoritative.
- Early exploratory files in `docs/research/` and `docs/deep-research/` (Cuckoo filters, peppers, RSA accumulators, fixed Euro limits) are **superseded historical background** — do **NOT** read them unless explicitly requested.

## Core Protocol & Crate Invariants (`humoco-wot v0.1.0`)
1. **Subjective, Offline-First & Transport-Neutral (`ADR-00`, `ADR-06`):**
   Ego-centric trust per user (no blockchain, no global score). `WotSyncPackage` works 100% offline (file, QR, BLE/NFC), piggybacked on payments, or over optional zero-trust relays/community servers. No W3C-VC / JSON-LD bloat.
2. **128-Bit Anonymous SD-JWT Lists (`ADR-04`):**
   One signed Ed25519 list per canonical `did:key` (`v = max(last_v + 1, now_secs)` for 12-word recovery safety, `iat`, no hard `exp`). Disclosures are strictly `["<16B_salt_b64url>","<target_did>",<level_0_to_3>,<contact_max_hops>]` (no cleartext names) with 128-bit truncated SHA-256 digests, fresh `OsRng` salts on every version bump, and decoy digests padded to multiples of 8.
3. **Distance Redaction & Tit-for-Tat (`ADR-05`):**
   Forwarding nodes NEVER mutate signed claims; for recipient distance $d_{\text{target}} = d + 1$, lists with `max_hops < d_target` are omitted and disclosures with `contact_max_hops < d_target` are stripped. Unreciprocated contacts cap at `unreciprocated_hops` (default `1`).
4. **2-Phase Unidirectional Delta-Sync & Spam Filter (`ADR-06`):**
   Read-only `prepare_sync_package` (Hop-1 prioritized, `SentRecord` tracks `(version, disclosure_fingerprint)`) + `commit_sync_receipt`. `import_sync_package` enforces topological reachability over `level >= 1` edges (`max_import_depth`, plus single-list `direct_sender_did` handshake admission) and performs same-version Union-Merge.
5. **Shared-Edge Factoring & Voucher Scoring (`ADR-01`):**
   Level `0` (`0%`) confirms human existence for direct neighbors only and **never** traverses or forwards. Levels `1..3` (`0.30 / 0.60 / 0.85`) evaluate via exact Shannon **Shared-Edge Factoring** (bottleneck-safe: Sybils behind a `30%` contact cap at $\le 30\%$, disjoint multi-hop paths combine via $1 - \prod (1 - R_c)$). `evaluate_voucher` enforces immediate `KnownOffender` veto (`0.0`) and temporary `guarantor -> creator` bridges (`0.85`).
6. **Engineering Constraints (`ADR-07`):**
   `#![forbid(unsafe_code)]`, WASM-portable (explicit `now_secs: u64`, never `SystemTime::now()`), zero cross-repo Cargo dependencies (`TrustProvider` wired via closure in host).

## Crate Map & Verification Gates
- **Crate Map:**
  - `src/`: `lib.rs`, `error.rs`, `identity.rs`, `sd_jwt.rs`, `graph.rs`, `scorer.rs`, `register.rs`, `sync.rs`.
  - Integration tests: `tests/wot_integration_tests.rs` | Simulator: `wot-simulation/index.html`.
- **Verification Gates:**
  - `cargo test --all-targets --offline`
  - `cargo clippy --all-targets --offline -- -D warnings`
  - `cargo check --target wasm32-unknown-unknown --offline`
- **Workflow:** Load skill **`wot-architecture`** for deep ADR/API reference; keep [`STATUS.md`](STATUS.md) updated.
