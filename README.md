# Humoco Web of Trust (WoT)

Dieses Repository enthält die Spezifikation, Architektur und vollständige Rust-Implementierung des **Web of Trust (WoT)** für den dezentralen human-money Ökosystem-Stack (`human-money-core`, `humoco-proto`, `human-money-app`).

## Status

**Phase:** Rust Crate Implemented & Tested → Ready for Core/App Integration
**Version:** 0.1.0  
**Health:** Green  

Die Kern-Bibliothek `humoco-wot` ist als eigenständiges, WASM-kompatibles Safe-Rust-Crate (`#![forbid(unsafe_code)]`) vollständig implementiert. Sie stellt die Dual-Storage-Architektur (`TrustRegister` + `EgoGraphCache`), SD-JWT-Verarbeitung mit 128-Bit Truncation, 2-Phasen Delta-Export (`prepare_sync_package` / `commit_sync_receipt`), Handschlag-Import, Shannon-Pivoting Shared-Edge Factoring und Garbage Collection bereit.

Siehe [STATUS.md](STATUS.md) für detaillierte Informationen über Aufgaben, Abhängigkeiten und Meilensteine.

## Repository-Struktur

```
humoco-web-of-trust/
├── src/                    # Rust-Implementierung (#![forbid(unsafe_code)])
│   ├── lib.rs              # Crate-Wurzel, Re-Exports, TrustRegister & APIs
│   ├── identity.rs         # Kanonische DIDs, Base58-Prüfung, WotSigner Trait
│   ├── register.rs         # TrustRegister, OwnTrustEntry, SentRecord, WotPolicy
│   ├── sd_jwt.rs           # SD-JWT Parser, Signer (Ed25519) & 128-Bit Verifizierung
│   ├── graph.rs            # EgoGraphCache, Topologische Distanzen & Erreichbarkeit
│   ├── scorer.rs           # Shared-Edge Factoring (Shannon-Pivoting), Altersdämpfung, Bürgen
│   ├── sync.rs             # 2-Phasen Delta-Export, Handschlag-Import, Union-Merge, GC
│   └── error.rs            # WotError Fehlerbehandlung (thiserror)
├── tests/                  # Vollständige Integrations- und Verifikationstests
│   └── wot_integration_tests.rs # Handschlag, Reziprozität, Shared-Edge, Spam-Abwehr, GC
├── docs/
│   ├── adr/                # Architecture Decision Records (ADR-00 bis ADR-07)
│   ├── research/           # Konzept- & Forschungsdokumente
│   └── deep-research/      # Detaillierte mathematische & kryptographische Analysen
├── wot-simulation/         # Interaktive HTML5/Cytoscape-Simulation mit Nadelöhr-Schutz
├── Cargo.toml              # Crate-Konfiguration (nur 8 Standard-Dependencies, WASM-ready)
├── README.md
└── STATUS.md
```

## Entwicklung & Tests

Das Crate kommt völlig ohne unsafe Code aus und hat keine Abhängigkeit zu `human-money-core`. Es kann nativ oder für `wasm32-unknown-unknown` gebaut werden:

```bash
# Alle Unit- und Integrationstests ausführen
cargo test

# Lints prüfen
cargo clippy --all-targets -- -D warnings
```

## Dokumentation

Die technischen Entscheidungen und Spezifikationen werden in Form von **Architecture Decision Records (ADRs)** und detaillierten **Forschungs-Dokumenten** festgehalten.

### Architecture Decision Records (ADRs)

- [ADR-00: WoT Grundprinzip](docs/adr/adr-00-wot-grundprinzip.md) - Grundlegende Prinzipien und Architektur (kein globaler Ledger)
- [ADR-01: Pfadberechnung und Vertrauenswahrscheinlichkeiten](docs/adr/adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) - Netzwerk-Vertrauen, multiplikative Dämpfung und Shared-Edge Factoring
- [ADR-03: UI-Design für Vertrauen und Haftung](docs/adr/adr-03-ui-design-vertrauen-haftung.md) - 30 % / 60 % / 85 % Vertrauensstufen und Stufe 0
- [ADR-04: SD-JWT Vertrauenslisten](docs/adr/adr-04-sd-jwt-vertrauenslisten.md) - Strukturierte SD-JWTs mit 128-Bit-Salts, Decoy-Padding und $v = \max(\text{last\_v} + 1, \text{now})$
- [ADR-05: Reziprokes Routing mit SD-JWT](docs/adr/adr-05-reziprokes-routing-sd-jwt.md) - Distanzbasierte Redaktion ohne Zähler-Mutation & Tit-for-Tat-Policy
- [ADR-06: Asynchrones Gossip-Protokoll](docs/adr/adr-06-asynchrones-gossip-protokoll.md) - Sent-Log Delta-Sync, topologischer Spam-Filter und deterministischer Union-Merge
- [ADR-07: Datenstruktur, Speicher & Schnittstellen](docs/adr/adr-07-datenstruktur-speicher-und-schnittstellen.md) - Dual-Storage (`TrustRegister` + `EgoGraphCache`), Handschlag-Workflow und Core-Schnittstellen
- [0000: Glossar](docs/adr/0000-glossar.md) - Begriffsdefinitionen

### Forschung & Grundlagen

Diese Dokumente bilden die theoretische und mathematische Basis für die Implementierung:

*   [00 — Concept Canvas: Decentralized WoT](docs/research/00-concept-canvas-wot.md): Die übergeordnete Vision und strategische Säulen.
*   [01 — WoT Data Structures & Privacy](docs/research/01-wot-data-structures-and-privacy.md): Analyse von Datenstrukturen, SD-JWTs und hybriden Datenmodellen.
*   [02 — Stranger Discovery Protocol](docs/research/02-stranger-discovery-protocol.md): Der 5-Phasen-Handshake für Offline-Vertrauensbeweise (BLE/NFC).
*   [03 — Graph Calculation & Revocation](docs/research/03-graph-calculation-and-revocation.md): Multiplikative Dämpfung, Dijkstra-Pfadfindung und dreistufiges Revokationsmodell.
*   [04 — Game Theory & Attack Vectors](docs/research/04-game-theory-and-attack-vectors.md): Analyse von Sybil-Attacken, Collusion-Ringen und dem ökonomischen Wert eines `did:key`.

### Deep Research & Detail-Analysen

Für tiefere Einblicke in spezifische Fragestellungen wurden umfassende Analysen erstellt:

- [Dezentrale Identität & Sybil-Resistenz](docs/deep-research/Dezentrale%20Identität%20&%20Sybil-Resistenz.md): Untersuchung von Proof-of-Personhood-Protokollen und deren Widerstand gegen Bot-Angriffe.
- [Skin in the Game & Haftung](docs/deep-research/Skin%20in%20the%20Game%20&%20Haftung.md): Analyse kryptooekonomischer Anreize und der Rolle von Bürgschaften bei Betrug.
- [Transitives Vertrauen & Pfadberechnung](docs/deep-research/Transitives%20Vertrauen%20&%20Pfadberechnung%20Algorithmen.md): Graphentheoretische Grundlagen zur Modellierung von Vertrauens-Dämpfung und Pfadkombination.
- [Datenschutz: Beweisbare & unlesbare Graphen](docs/deep-research/Datenschutz_%20Graphen%20beweisbar,%20unlesbar%20machen.md): Strategien zur Wahrung der Privatsphäre bei gleichzeitigem Nachweis von Vertrauensbeziehungen.
- [Dezentrale Datenlebenszyklen & Widerruf](docs/deep-research/Dezentrale%20Datenlebenszyklen%20&%20Widerruf.md): Konzepte für das Revokations-Management und die zeitliche Begrenzung von Identitäten.

### WoT Simulation

- [Interactive Simulation](wot-simulation/index.html): Interaktive HTML-Simulation zur Visualisierung des WoT-Netzwerks und Vertrauenspfade (inklusive umschaltbarem Nadelöhr-Schutz via Shared-Edge Factoring).

## Architektur-Übersicht

### Kern-Entscheidungen

| Entscheidung | Ansatz |
|---|---|
| **Trust Model** | Asymmetrisch, multiplikative Vertrauensfaktoren (Netzwerk-Vertrauen) mit Shared-Edge Factoring |
| **Trust Levels** | 4-stufiges Modell: Stufe 0 (Existenz, 0 %), Level 1 (30 %), Level 2 (60 %), Level 3 (85 %) |
| **Data Structures** | **SD-JWTs** (128-Bit Truncation, 128-Bit CSPRNG-Salts, Decoy-Padding, $v = \max(\text{last\_v}+1, \text{now})$, kein Pflicht-`exp`) |
| **Routing & Privacy** | Distanzbasierte Redaktion (keine Signatur-Mutation beim Weiterleiten) + Tit-for-Tat-Policy |
| **Graph Storage** | **Dual-Storage-Architektur:** `raw_list_store` (persistente signierte Rohdaten) + `EgoGraphCache` (schnelle In-Memory Matrix) |
| **Data Sync** | Versand-Logbuch (`Sent-Log`) für unidirektionalen Delta-Sync mit Hop-1-Priorisierung |
| **Spam-Schutz** | Topologischer Erreichbarkeits-Filter (Verwerfen unverbundener Insel-Listen vor Krypto-Prüfung) |

## Nächste Schritte

1. **CORE-002**: Integration von `humoco-wot` in `human-money-core` via `TrustProvider` Trait und Piggybacking Hooks.
2. **APP-002**: Visualisierung von Vertrauenswerten und Badges im UI der `human-money-app`.
3. **WOT-004**: UI/UX Designs für Vertrauens-Ausweis (Trust Badge) in der App.
