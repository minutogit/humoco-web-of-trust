---
project: humoco-web-of-trust
version: "0.2.1"
phase: "active-development"
health: "green"
last_updated: "2026-11-18"
blocks: []
blocked_by: []
priority_tasks:
  - id: "WOT-013"
    title: "ADR-09 KeySuccessorAttestation & ADR-10 ServerOffenderList via EquivocationProof"
    status: "done"
    priority: "high"
    depends_on: ["WOT-010"]
    description: "Added German ADR-09 (`docs/adr/adr-09-schluesselnachfolge-key-successor-attestation.md`), German ADR-10 (`docs/adr/adr-10-server-sanktionsliste-server-offender-list.md`), glossary definitions (`0000-glossar.md`), and standalone `#![forbid(unsafe_code)]` WASM-portable module `src/successor_and_offenders.rs` (`KeySuccessorAttestation` dual-signed rotation + bounded acyclic `resolve_successor_chain`, `ServerOffenderList` validating `HUMOCO_LOCK_RECEIPT_V1` `EquivocationProof` + `HUMOCO-LOCK-DELEGATE-V1` `admin_pub`/`lock_pub` revocation + `BinaryFuse64` denylist filter). Verified with `cargo fmt --check`, `clippy -D warnings` (0 warnings), `cargo check --target wasm32-unknown-unknown --offline`, and 33 tests (6 unit + 27 integration)."
  - id: "WOT-012"
    title: "Drop-Sync Freshness Prioritization & Defense-in-Depth Redaction Verification"
    status: "done"
    priority: "high"
    depends_on: ["WOT-011"]
    description: "Sorted drop-sync subpackages by (dist ASC, v DESC, issuer ASC) so fresh lists are never starved by stale ones under class byte caps, and enforced recipient-side redaction depth verification (discarding disclosures with contact_max_hops < hop_distance unless a shorter local path exists). Verified with 31 tests (6 unit + 25 integration) and clippy (0 warnings). Plan: ../docs/plans/SYNC_REACH_PLAN.md."
  - id: "WOT-011"
    title: "Sent-Log transport binding & distance-class subpackages for encrypted multi-reader drop trust list sync"
    status: "done"
    priority: "high"
    depends_on: ["WOT-005", "WOT-010"]
    description: "Added transport-bound Sent-Log isolation (`prepare_drop_sync_subpackages`, `export_drop_sync_subpackage_for_distance_class`), distance-class subpackage segregation preventing multi-reader cross-exposure, authorized drop readers evaluation excluding Level 0 entries, and zero cross-repo Cargo dependencies (29 tests: 6 unit + 23 integration passing)."
  - id: "WOT-010"
    title: "Global Hop Policy, 1-Year Freshness Grace + Decay & BinaryFuse64 Provider Seals (ADR-08)"
    status: "done"
    priority: "high"
    depends_on: ["WOT-005", "WOT-007"]
    description: "Added `TrustRegister::set_own_list_max_hops` (`own_list_max_hops = 3` default, decoupled `max_eval_depth = 5` / `max_import_depth = 5` preserving guarantor bridges at 1 hop), 1-year grace period + 1-year half-life freshness curve (`freshness_grace_secs = 31_536_000`), `O(N)` `continue`-based sync package packing, pure-Rust safe `BinaryFuse64` signed provider filters (`wot-provider-filter+v1`, $2^{-64}$ anti-grinding false-positive rate, zero new Cargo dependencies) evaluated across both voucher creators and guarantors under Shannon Shared-Edge Factoring, and German `ADR-08` (`docs/adr/adr-08-dienstleister-pruefsiegel-binary-fuse.md`)."
  - id: "WOT-005"
    title: "Rust implementation of WoT crate (humoco-wot)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Implement the WoT library as a separate, WASM-compatible Rust crate (#![forbid(unsafe_code)]). Core integrates via TrustProvider trait and Transaction Piggybacking."
  - id: "WOT-001"
    title: "Finalize Vertrauensregister (Trust Register) JSON structure"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0007: TrustRegister with own_contacts, own_signed_list, raw_list_store, sent_log, and WotPolicy."
  - id: "WOT-002"
    title: "Define cryptographic & gossip interfaces to human_money_core"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0007: canonicalize_did, TrustEvaluation, WotSyncPackage, and TrustProvider trait implementation."
  - id: "WOT-006"
    title: "ADR-007: Trust Establishment Protocol (Handschlag)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0007: Decoupled handshake workflow, unreciprocated_hops base visibility, and WotSyncPackage."
  - id: "WOT-008"
    title: "Define MVP transport and scope parameters"
    status: "done"
    priority: "high"
    depends_on: []
    description: "Specified in ADR-0004 & ADR-0007: 128-bit CSPRNG salts + decoys, v = max(last_v + 1, now), no hard exp, transport-agnostic packaging."
  - id: "WOT-009"
    title: "Dual Storage System Architecture (Graphen-Caches)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0007: Dual Storage Architecture (raw_list_store for signatur-preserving routing + EgoGraphCache for sub-ms path evaluation)."
  - id: "WOT-004"
    title: "UI/UX designs for trust badge (Vertrauens-Ausweis)"
    status: "done"
    priority: "medium"
    depends_on: []
    description: "Human-semantic contact trust levels (Unrated, Real Person, Acquaintance, Good Contact, Close Confidant) and color/percentage/bridge-contact <TrustBadge /> delivered across human-money-app (APP-002 / APP-044)."
  - id: "WOT-007"
    title: "ADR-006: Vertrauens-Propagation (Gossip)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0006: Sent-Log delta-sync, topological spam filter, and deterministic union-merge."
---

# HuMoCo Web of Trust — Status

## Current Focus

**Full Core & App Ecosystem Integration, Drop Sync Subpackages, Freshness Prioritization & Provider Seals Completed (`v0.2.0` / `WOT-012`).**
Die Kern-Bibliothek `humoco-wot` ist als eigenständiges, WASM-kompatibles Safe-Rust-Crate (`#![forbid(unsafe_code)]`) vollständig implementiert:
- **Drop-Sync Freshness Prioritization & Defense-in-Depth Redaction Verification (`WOT-012`)**: Deterministische Frische-Sortierung `(dist ASC, v DESC, issuer ASC)` im `Sent-Log`-Packer gegen Starvation veralteter Listen sowie empfängerseitige Redaktions-Tiefenprüfung (`contact_max_hops < hop_distance`) beim Import (31 Tests: 6 Unit + 25 Integrationstests).
- **Drop Sync Isolation & Distance-Class Subpackages (`WOT-011`)**: Transportgebundene `Sent-Log`-Isolation (`prepare_drop_sync_subpackages`, `export_drop_sync_subpackage_for_distance_class`), distanzbasierte Subpaket-Aufteilung zur Verhinderung von Mehrleser-Metadatenlecks auf Ablagen, Berechtigtenprüfung unter Ausschluss von Stufe-0-Kontakten und zero neue Cargo-Dependencies (29 Tests: 6 Unit + 23 Integrationstests).
- **Global Hop Policy & Freshness Decay (`WOT-010`)**: Einstellbare Reichweite `TrustRegister::set_own_list_max_hops` (`own_list_max_hops = 3` Standard, entkoppelt von `max_eval_depth = 5` / `max_import_depth = 5` mit Beibehaltung von 1-Hop-Bürgschaftsbrücken), 1-Jahr-Schonfrist (`freshness_grace_secs = 31_536_000`) plus 1-Jahr-Halbwertszeit-Dämpfungskurve und $O(N)$ `continue`-basiertes Packen in `prepare_sync_package`.
- **Pure-Rust Safe `BinaryFuse64` Provider Seals (`ADR-08`)**: Signierte Verbands- und Prüfsiegelfilter (`wot-provider-filter+v1`, $2^{-64}$ Falsch-Positiv-Rate gegen Key-Grinding, keine neuen Cargo-Dependencies) zur kompakten Offline-Zertifizierung tausender Erzeuger/Dienstleister unter Shannon-Shared-Edge-Factoring.
- **Core & App Hooks**: `evaluate_trust_from_observer` / `TrustRegister::evaluate_voucher_for_observer` (für Gravitational Coin Selection `s_wot`) sowie Third-Party-Export-Guard in `prepare_sync_package` integriert in `human-money-core` und `human-money-app` (`APP-044` / `APP-052` / `APP-059`).

### MVP Priority Chain

```
[WOT-001, WOT-002, WOT-004, WOT-005, WOT-006, WOT-007, WOT-008, WOT-009, WOT-010, WOT-011, WOT-012] (Done ✅)
    ├── CORE-010 / CORE-011 (Sync Piggybacking, Multi-Recipient Trust Containers & s_wot) [Done ✅]
    └── APP-044 / APP-052 / APP-059 (Global Reach Selector, TrustBadges, Passwordless .wot, Provider Seals & Drop Sync) [Done ✅]
```

## Architecture

- **Architecture Decision Records (ADRs)**:
  - [`0000`: Glossar](docs/adr/0000-glossar.md) (Begriffe und Definitionen)
  - [`0000` / `ADR-00`: WoT Grundprinzip](docs/adr/adr-00-wot-grundprinzip.md) (MVP-Architektur, Offline-First & Transport-Entkopplung)
  - [`0001`: Pfadberechnung und Vertrauenswahrscheinlichkeiten](docs/adr/adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) (Netzwerk-Vertrauen & Shared-Edge Factoring)
  - [`0003`: UI-Design Vertrauen und Haftung](docs/adr/adr-03-ui-design-vertrauen-haftung.md) (30 %, 60 %, 85 % und Stufe 0)
  - [`0004`: Vertrauenslisten als SD-JWTs](docs/adr/adr-04-sd-jwt-vertrauenslisten.md) (128-Bit Truncation, 128-Bit CSPRNG-Salts, Decoy-Padding, $v = \max(\text{last\_v}+1, \text{now})$)
  - [`0005`: Reziprokes Routing](docs/adr/adr-05-reziprokes-routing-sd-jwt.md) (Distanzbasierte Redaktion ohne Zähler-Mutation & Tit-for-Tat-Policy)
  - [`0006`: Vertrauens-Propagation](docs/adr/adr-06-asynchrones-gossip-protokoll.md) (Gossip, Sent-Log Delta-Sync, topologischer Spam-Filter & Union-Merge)
  - [`0007`: Datenstruktur, Speicher & Schnittstellen](docs/adr/adr-07-datenstruktur-speicher-und-schnittstellen.md) (Dual-Storage `TrustRegister` + `EgoGraphCache`, Handschlag & Core-Schnittstellen)
  - [`0008` / `ADR-08`: Dienstleister-Prüfsiegel & Verbände](docs/adr/adr-08-dienstleister-pruefsiegel-binary-fuse.md) (Pure-Rust BinaryFuse64 Filter, $2^{-64}$ Anti-Grinding, Shannon-Integration)
  - [`0009` / `ADR-09`: Schlüsselnachfolge & Anti-Vampire-Schutz](docs/adr/adr-09-schluesselnachfolge-key-successor-attestation.md) (`KeySuccessorAttestation` Dual-Signatur- & Notfall-Nachfolge, max. 8 Hops)
  - [`0010` / `ADR-10`: Server-Sanktionsliste (`ServerOffenderList`)](docs/adr/adr-10-server-sanktionsliste-server-offender-list.md) (`EquivocationProof`, `HUMOCO-LOCK-DELEGATE-V1`, `BinaryFuse64`-Sperrfilter)
- **Research documents**: Concept canvas, Stranger discovery protocol, Game theory & attack vectors
- **WoT Simulator**: Interactive HTML simulation for network visualization (`wot-simulation/index.html`)

### Core Architectural Decisions (Updated 2026-10-30)

| Decision | Approach |
|---|---|
| **Trust Model** | Asymmetrisch, multiplikative Vertrauensfaktoren (Netzwerk-Vertrauen) mit Shared-Edge Factoring |
| **Trust Levels** | 4-stufiges Modell: Stufe 0 (Existenz, 0 %), Level 1 (30 %), Level 2 (60 %), Level 3 (85 %) |
| **Data Structures** | **SD-JWTs** (128-Bit Truncated Hashes, 128-Bit CSPRNG-Salts, Decoy-Padding, $v = \max(\text{last\_v}+1, \text{now})$, kein Pflicht-`exp`) |
| **Routing & Privacy** | Distanzbasierte Redaktion (Weglassen von Disclosures, Signatur bleibt unverändert) + Tit-for-Tat-Policy mit Offenheitsdeckelung |
| **Graph Storage** | **Dual-Storage-Architektur:** `raw_list_store` (persistente JWS-Rohdaten) + `EgoGraphCache` (schnelle In-Memory Matrix) |
| **Data Sync** | Unidirektionaler Delta-Sync über lokales Versand-Logbuch (`Sent-Log`) mit Hop-1-Priorisierung |
| **Spam Defense** | Topologischer Erreichbarkeits-Filter (Verwerfen unverbundener Insel-Listen vor Krypto-Prüfung) |

## Known Issues

- Keine offenen Blocker in `humoco-web-of-trust`. Das Rust-Crate `humoco-wot` (33 Tests: 6 Unit + 27 Integrationstests inkl. Observer-Scoring, Export-Guard, Provider Seals, Drop Subpackages, Freshness Prioritization, Redaction Check, `KeySuccessorAttestation` & `ServerOffenderList`) ist vollständig implementiert und WASM-geprüft.

## Recent Milestones

- [x] Bereinigung der Architektur auf rein SD-JWT-basierte Vertrauenslisten (inkl. Level 0-3 & Hops).
- [x] Spezifikation von 128-Bit CSPRNG-Salts und Decoy-Padding gegen GPU-Brute-Force und Größen-Tracking (ADR-0004).
- [x] Definition der monotonen Zeitstempel-Versionierung $v = \max(\text{last\_v} + 1, \text{now})$ für kollisionsfreien Seedphrase-Recovery (ADR-0004).
- [x] Spezifikation der distanzbasierten Redaktion und des reziproken Tit-for-Tat-Anreizmodells (ADR-0005).
- [x] Spezifikation des topologischen Spam-Filters und des deterministischen Union-Merge (ADR-0006).
- [x] Definition des Schemas für das `TrustRegister`, Dual-Storage-Architektur und `EgoGraphCache` (ADR-0007).
- [x] Spezifikation des entkoppelten Handschlag-Workflows und `WotSyncPackage` (ADR-0007).
- [x] Spezifikation der Rust-APIs und der `TrustProvider`-Kompatibilität für `human-money-core` (ADR-0007).
- [x] **WOT-005**: Vollständige Rust-Implementierung des eigenständigen Crates `humoco-wot` (`#![forbid(unsafe_code)]`, WASM-kompatibel, Dual-Storage, 2-Phasen Export, Handschlag-Import, Shannon-Pivoting, Garbage Collection).
- [x] Erweiterung des WoT-Simulators (`wot-simulation/index.html`) um echten Nadelöhr-Schutz (Shared-Edge Factoring nach ADR-01).
- [x] **WOT-004 & App/Core-Härtung (2026-10-31)**: `evaluate_trust_from_observer` / `TrustRegister::evaluate_voucher_for_observer` für empfängerorientiertes Coin-Selection-Scoring (`s_wot`), Third-Party-Export-Guard in `prepare_sync_package` für unbewertete/Level-0-Empfänger sowie vollständige UI/UX-Umsetzung des Vertrauens-Ausweises (`<TrustBadge />`) in `human-money-app`.
- [x] **WOT-010: Global Hop Policy, 1-Year Freshness Grace + Decay & BinaryFuse64 Provider Seals (ADR-08, 2026-11-01)**: Added `TrustRegister::set_own_list_max_hops` (`own_list_max_hops = 3` default, decoupled `max_eval_depth = 5` / `max_import_depth = 5` preserving guarantor bridges at 1 hop), 1-year grace period + 1-year half-life freshness curve (`freshness_grace_secs = 31_536_000`), `O(N)` `continue`-based sync package packing, pure-Rust safe `BinaryFuse64` signed provider filters (`wot-provider-filter+v1`, $2^{-64}$ anti-grinding false-positive rate, zero new Cargo dependencies) evaluated across both voucher creators and guarantors under Shannon Shared-Edge Factoring, and German `ADR-08` (`docs/adr/adr-08-dienstleister-pruefsiegel-binary-fuse.md`).
- [x] **WOT-011: Sent-Log Transport Binding & Distance-Class Subpackages for Drop Sync (2026-11-08)**: Transportgebundene `Sent-Log`-Isolation (`prepare_drop_sync_subpackages`, `export_drop_sync_subpackage_for_distance_class`), distanzbasierte Subpaket-Aufteilung zur Verhinderung von Mehrleser-Metadatenlecks auf Ablagen, Berechtigtenprüfung unter Ausschluss von Stufe-0-Kontakten und zero neue Cargo-Dependencies (29 Tests: 6 Unit + 23 Integrationstests passing).
- [x] **WOT-012: Drop-Sync Freshness Prioritization & Defense-in-Depth Redaction Verification (2026-11-15)**: Sortierung nach `(dist ASC, v DESC, issuer ASC)` im `Sent-Log`-Packer gegen Starvation alter Listen sowie empfängerseitige Redaktions-Tiefenprüfung (`contact_max_hops < hop_distance`) beim Import (`test_24`, `test_25`; 31 Tests: 6 Unit + 25 Integrationstests passing, `clippy` 0 Warnings).
- [x] **WOT-013: `KeySuccessorAttestation` (`ADR-09`) & `ServerOffenderList` (`ADR-10`, 2026-11-17)**: Spezifikation und `#![forbid(unsafe_code)]`/WASM-Implementierung von `KeySuccessorAttestation` (Dual-Signatur, Zyklus-/8-Hop-Schutz) und `ServerOffenderList` (`EquivocationProof` + `HUMOCO-LOCK-DELEGATE-V1` + `BinaryFuse64`-Sperrfilter; `test_26`, `test_27`; 33 Tests: 6 Unit + 27 Integrationstests passing, `clippy` 0 Warnings, `wasm32-unknown-unknown` grün).

## Next Milestones

- [ ] **CORE-002 / APP-003 (Post-MVP)**: Optionaler BLE/NFC Stranger-Discovery-Handschlag vor Ort
- [ ] Optionale Zero-Trust-Relay-Anbindung für asynchronen SD-JWT-Austausch ohne direkten Dateitransfer
