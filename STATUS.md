---
project: humoco-web-of-trust
version: "0.1.0"
phase: "research"
health: "green"
last_updated: "2026-04-22"
blocks: ["CORE-001", "CORE-002", "CORE-003"]
blocked_by: []
priority_tasks:
  - id: "WOT-001"
    title: "Finalize Vertrauensregister (Trust Register) JSON structure"
    status: "open"
    priority: "critical"
    depends_on: []
    description: >
      Define the exact JSON schema and Rust struct for the Vertrauensregister — the central
      local data store per user. Must include: self_did, eigene Vertrauensliste (als SD-JWT),
      den Versand-Logbuch (Sent-Log), etc.
  - id: "WOT-002"
    title: "Define cryptographic & gossip interfaces to human_money_core"
    status: "open"
    priority: "critical"
    depends_on: []
    description: "Map Ed25519 identity to WoT DID:key, define Hook-Traits for Transaction-Piggybacking (Data Sync payload injection)."
  - id: "WOT-004"
    title: "UI/UX designs for trust badge (Vertrauens-Ausweis)"
    status: "open"
    priority: "medium"
    depends_on: []
    description: "Visual design for trust indicators in the app based on 30/60/85 probability levels."
  - id: "WOT-005"
    title: "Rust implementation of WoT crate"
    status: "open"
    priority: "high"
    depends_on: ["WOT-001", "WOT-002", "WOT-006", "WOT-009"]
    description: "Implement the WoT library as a separate Rust crate. Core integrates via trait interfaces."
  - id: "WOT-006"
    title: "ADR-007: Trust Establishment Protocol (Handschlag)"
    status: "open"
    priority: "critical"
    depends_on: []
    description: >
      Define how a user adds another DID to their trust list initially: Exchange of DIDs,
      wanted Hop-Limits, and creation of the first SD-JWT (Face-to-Face vs Remote).
  - id: "WOT-007"
    title: "ADR-006: Vertrauens-Propagation (Gossip)"
    status: "done"
    priority: "critical"
    depends_on: []
    description: "Spezifiziert in ADR 0006: Versand-Logbuch, Piggybacking."
  - id: "WOT-008"
    title: "Define MVP transport and scope parameters"
    status: "open"
    priority: "high"
    depends_on: []
    description: "Document binding MVP decisions: BLE/QR usage, SD-JWT expiry limits etc."
  - id: "WOT-009"
    title: "Dual Storage System Architecture (Graphen-Caches)"
    status: "open"
    priority: "critical"
    depends_on: []
    description: "Concept for splitting raw SD-JWT persistence (for passing on signatures) from a highly optimized runtime graph structure (für Netzwerk-Vertrauen)."
---

# HuMoCo Web of Trust — Status

## Current Focus

**Architecture and research phase — transitioning to MVP specification.** 
Das System basiert auf signierten Vertrauenslisten (SD-JWTs), welche für jeden Kontakt effizient den Vertrauenswert (Level 0 bis 3) und das Erlaubnis-Limit (wie viele Hops noch weitergeleitet werden darf) bündeln. 

Beim Austausch (ADR 0006) werden diese Listen iteriert und Kontakte mit abgelaufenem Hop-Limit datenschutzkonform redigiert (ADR 0005). Die finale Graphberechnung modelliert Pfade asymmetrisch über Wahrscheinlichkeiten (Netzwerk-Vertrauen, ADR 0001).

### MVP Priority Chain

The critical path for MVP is:
```
WOT-006 (Trust Establishment / ADR-007) + WOT-009 (Dual Storage Arch)
    → WOT-001 (Vertrauensregister Schema)
            → WOT-005 (Rust Implementation)
                → CORE-001 (Trait Interfaces)
```

## Architecture

- **Aktuelle ADRs**: 
  - `0001`: Pfadberechnung und Vertrauenswahrscheinlichkeiten (Netzwerk-Vertrauen)
  - `0003`: UI-Design Vertrauen und Haftung (30 %, 60 %, 85 %)
  - `0004`: Vertrauenslisten als strukturierte SD-JWTs (128-Bit Truncation)
  - `0005`: Reziprokes Routing (Selektive Disclosure nach Echo-Limit)
  - `0006`: Vertrauens-Propagation (Gossip, Deltas & Piggyback Cache)
- **Research documents**: Concept canvas, Stranger discovery protocol, Game theory
- **WoT Simulator**: Interactive HTML simulation for network visualization (`wot-simulation/index.html`)

### Core Architectural Decisions (Updated 2026-04-10)

| Decision | Approach |
|---|---|
| Trust Model | Asymmetrisch, multiplikative Vertrauensfaktoren (Netzwerk-Vertrauen) |
| Trust Levels | 3-tier model (30 %, 60 %, 85 % probability) + Stufe 0 |
| Data Structures | **SD-JWTs** (128-Bit Hashes). Enthält pro Ziel: Vertrauensstufe (0-3) und individuelles Hop-Limit. |
| Graph Storage | Dual-Storage: SD-JWTs (Rohdaten) + Schneller lokaler Graphen-Cache |
| Data Sync | Versand-Logbuch ermöglicht asynchronen Delta-Sync (Vertrauens-Propagation via Transactions) |
| Hop Depth | Verdeckt/Auslaufend: Client redigiert abgelaufene Kontakte selektiv via SD-JWT beim Weitergeben |

## Known Issues

- No Rust implementation yet.
- **Trust Establishment Protocol (Der initiale "Handschlag") is missing** (WOT-006 / ADR-007).
- **Dual-Storage Graph Engine für Rust noch völlig ungeklärt** (WOT-009).
- Vertrauensregister JSON structure not yet finalized (WOT-001).
- Cryptographic Hook interface to `human_money_core` for Piggybacking not defined yet.

## Recent Milestones

- [x] Bereinigung der Architektur auf rein SD-JWT-basierte Vertrauenslisten (inkl. Level 0-3 & Hops).
- [x] Spezifikation von Truncated-Hashes und Dateneffizienz in ADR 0004.
- [x] Spezifikation des Gossip-Protokolls & Piggybacking via Core (ADR 0006).
- [x] Pfadberechnung auf Netzwerk-Vertrauen umgestellt (ADR 0001 neu).
- [x] Protokoll-Harmonisierung (SHA-256, Base64URL, DIDComm v2, JWE/JWS Compact).

## Next Milestones

- [ ] **WOT-006**: Trust Establishment Protocol (Zukünftiges ADR-007) ← START HERE
- [ ] **WOT-009**: Dual Storage Architecture (Entity Store vs Graph Matrix)
- [ ] **WOT-001**: Finalize Vertrauensregister JSON/Rust struct specification
- [ ] WOT-002: Define Piggyback Hooks and Ed25519 ↔ DID:key interfaces
- [ ] WOT-005: Begin Rust implementation as separate WoT crate
