---
project: humoco-web-of-trust
version: "0.1.0"
phase: "active-development"
health: "green"
last_updated: "2026-10-30"
blocks: ["CORE-002", "APP-002"]
blocked_by: []
priority_tasks:
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
    status: "open"
    priority: "medium"
    depends_on: []
    description: "Visual design for trust indicators in the app based on 30/60/85 probability levels."
  - id: "WOT-007"
    title: "ADR-006: Vertrauens-Propagation (Gossip)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Specified in ADR-0006: Sent-Log delta-sync, topological spam filter, and deterministic union-merge."
---

# HuMoCo Web of Trust — Status

## Current Focus

**Rust crate implementation completed — ready for Core & App integration.**
Die Kern-Bibliothek `humoco-wot` ist als eigenständiges, WASM-kompatibles Safe-Rust-Crate (`#![forbid(unsafe_code)]`) vollständig implementiert und getestet. Alle mathematischen und kryptographischen Invarianten aus ADR-00 bis ADR-07 (Dual-Storage-Architektur mit `TrustRegister` & `EgoGraphCache`, 2-Phasen Delta-Export `prepare_sync_package`/`commit_sync_receipt`, Handschlag-Import, Shannon-Pivoting Shared-Edge Factoring und Garbage Collection) sind realisiert. Der interaktive Simulator (`wot-simulation/index.html`) wurde ebenfalls um den echten Nadelöhr-Schutz (Shared-Edge Factoring) erweitert.

Der Fokus verlagert sich nun auf die Anbindung der Konsumenten:
1. **`CORE-002`**: Integration von `humoco-wot` in `human-money-core` via `TrustProvider`-Closure und Transaction Piggybacking Hooks.
2. **`APP-002`**: Visualisierung von Vertrauenswerten und Badges im UI der `human-money-app`.

### MVP Priority Chain

```
[WOT-001, WOT-002, WOT-006, WOT-008, WOT-009, WOT-005] (Done ✅)
    ├── CORE-002 (Integrate TrustProvider into human-money-core) [ACTIVE / READY 🚀]
    └── APP-002 (Trust Display UI in human-money-app) [ACTIVE / READY 🚀]
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

- Keine offenen Blocker in `humoco-web-of-trust`. Das Rust-Crate `humoco-wot` ist vollständig implementiert und getestet.
- Anbindung an `human-money-core` (`CORE-002`) und UI (`APP-002`) stehen als nächste Integrationsschritte an.

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

## Next Milestones

- [ ] **CORE-002**: Anbindung von `humoco-wot` an `human-money-core` (Reputations-Check & Transaction Piggybacking)
- [ ] **APP-002**: Integration und UI-Visualisierung in `human-money-app`
- [ ] **WOT-004**: UI/UX Designs für Vertrauens-Ausweis (Trust Badge) in der App
