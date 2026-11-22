# HuMoCo Web of Trust (`humoco-wot`)

Subjective, offline-first Web of Trust specification and standalone `#![forbid(unsafe_code)]` Rust crate for the decentralized **Human Money (HuMoCo)** ecosystem.

See [`STATUS.md`](STATUS.md) for current version and milestone details, and [`AGENTS.md`](AGENTS.md) for agent guardrails.

## Crate Architecture (`src/`)

```text
humoco-web-of-trust/
├── src/
│   ├── lib.rs                      # Crate root & public API re-exports
│   ├── error.rs                    # WotError definitions
│   ├── identity.rs                 # Canonical did:key parsing & WotSigner trait
│   ├── register.rs                 # TrustRegister, OwnTrustEntry, SentRecord, WotPolicy
│   ├── sd_jwt.rs                   # 128-bit SD-JWT trust lists, salts & decoy padding
│   ├── graph.rs                    # EgoGraphCache, BFS distances & reachability
│   ├── scorer.rs                   # Shannon Shared-Edge Factoring, decay & guarantor bridges
│   ├── sync.rs                     # 2-phase Delta-Sync, Drop-Sync subpackages & union-merge
│   ├── provider_filter.rs          # Pure-Rust BinaryFuse64 signed provider seals (ADR-08)
│   └── successor_and_offenders.rs  # KeySuccessorAttestation (ADR-09) & ServerOffenderList (ADR-10)
├── tests/wot_integration_tests.rs  # Full integration test suite
├── docs/adr/                       # Authoritative Architecture Decision Records (German)
└── wot-simulation/index.html       # Interactive Shared-Edge simulator
```

## Development & Verification

`humoco-wot` has **zero cross-repo Cargo dependencies** (wired into `human-money-core` via host closure) and builds natively as well as for `wasm32-unknown-unknown`:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target wasm32-unknown-unknown
```

## Architecture Decision Records (`docs/adr/`, German)

- [`0000-glossar.md`](docs/adr/0000-glossar.md) — Canonical domain glossary
- [`ADR-00`](docs/adr/adr-00-wot-grundprinzip.md) — Subjective, offline-first & transport-neutral principles
- [`ADR-01`](docs/adr/adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) — Multiplicative damping & Shannon Shared-Edge Factoring
- [`ADR-03`](docs/adr/adr-03-ui-design-vertrauen-haftung.md) — Trust levels (0–3) & social responsibility
- [`ADR-04`](docs/adr/adr-04-sd-jwt-vertrauenslisten.md) — 128-bit SD-JWT trust lists, salts & monotonic versioning
- [`ADR-05`](docs/adr/adr-05-reziprokes-routing-sd-jwt.md) — Distance redaction & Tit-for-Tat reciprocal routing
- [`ADR-06`](docs/adr/adr-06-asynchrones-gossip-protokoll.md) — 2-phase gossip delta-sync & topological spam filter
- [`ADR-07`](docs/adr/adr-07-datenstruktur-speicher-und-schnittstellen.md) — Dual-storage (`TrustRegister` + `EgoGraphCache`) & host interfaces
- [`ADR-08`](docs/adr/adr-08-dienstleister-pruefsiegel-binary-fuse.md) — Pure-Rust `BinaryFuse64` provider seals ($2^{-64}$ anti-grinding)
- [`ADR-09`](docs/adr/adr-09-schluesselnachfolge-key-successor-attestation.md) — Dual-signed `KeySuccessorAttestation` (`MAX = 8` hops)
- [`ADR-10`](docs/adr/adr-10-server-sanktionsliste-server-offender-list.md) — `ServerOffenderList` (`EquivocationProof` & `BinaryFuse64` denylist)

*(Note: `docs/research/` and `docs/deep-research/` hold historical exploratory drafts superseded by `ADR-00`–`ADR-10`.)*
