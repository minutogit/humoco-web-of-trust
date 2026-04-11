# Humoco Web of Trust (WoT)

Dieses Repository dient der architektonischen Planung und Dokumentation der Web of Trust (WoT) Implementierung für den Tauri-basierten Wallet-Client.

## Status

**Phase:** Research & Architecture Specification  
**Version:** 0.1.0  
**Health:** Green  

Das Projekt befindet sich in der Forschungs- und Architekturphase. Der kritische Pfad für das MVP umfasst: Trust Establishment Protocol → Dual Storage Architecture → Vertrauensregister Schema → Rust Implementierung.

Siehe [STATUS.md](STATUS.md) für detaillierte Informationen über aktuelle Aufgaben, Abhängigkeiten und Meilensteine.

## Dokumentation

Die technischen Entscheidungen und Spezifikationen werden in Form von **Architecture Decision Records (ADRs)** und detaillierten **Forschungs-Dokumenten** festgehalten.

### Architecture Decision Records (ADRs)

- [ADR-00: WoT Grundprinzip](docs/adr/adr-00-wot-grundprinzip.md) - Grundlegende Prinzipien und Architektur
- [ADR-01: Pfadberechnung und Vertrauenswahrscheinlichkeiten](docs/adr/adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) - Netzwerk-Vertrauen und Pfadfindung
- [ADR-03: UI-Design für Vertrauen und Haftung](docs/adr/adr-03-ui-design-vertrauen-haftung.md) - 30%/60%/85% Vertrauensstufen
- [ADR-04: SD-JWT Vertrauenslisten](docs/adr/adr-04-sd-jwt-vertrauenslisten.md) - Strukturierte Vertrauenslisten mit 128-Bit Hashes
- [ADR-05: Reziprokes Routing mit SD-JWT](docs/adr/adr-05-reziprokes-routing-sd-jwt.md) - Selektive Disclosure nach Echo-Limit
- [ADR-06: Asynchrones Gossip-Protokoll](docs/adr/adr-06-asynchrones-gossip-protokoll.md) - Vertrauens-Propagation via Piggybacking
- [0000: Glossar](docs/adr/0000-glossar.md) - Begriffsdefinitionen

### Forschung & Grundlagen

Diese Dokumente bilden die theoretische und architektonische Basis für die `human_money_core` Implementierung:

*   [00 — Concept Canvas: Decentralized WoT](docs/research/00-concept-canvas-wot.md): Die übergeordnete Vision und strategische Säulen.
*   [01 — WoT Data Structures & Privacy](docs/research/01-wot-data-structures-and-privacy.md): Analyse von Cuckoo-Filtern, SD-JWTs und hybriden Datenmodellen.
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

- [Interactive Simulation](wot-simulation/index.html): Interaktive HTML-Simulation zur Visualisierung des WoT-Netzwerks und Vertrauenspfade.

## Architektur-Übersicht

### Kern-Entscheidungen

| Entscheidung | Ansatz |
|---|---|
| Trust Model | Asymmetrisch, multiplikative Vertrauensfaktoren (Netzwerk-Vertrauen) |
| Trust Levels | 3-tier model (30 %, 60 %, 85 % probability) + Stufe 0 |
| Data Structures | **SD-JWTs** (128-Bit Hashes). Enthält pro Ziel: Vertrauensstufe (0-3) und individuelles Hop-Limit. |
| Graph Storage | Dual-Storage: SD-JWTs (Rohdaten) + Schneller lokaler Graphen-Cache |
| Data Sync | Versand-Logbuch ermöglicht asynchronen Delta-Sync (Vertrauens-Propagation via Transactions) |
| Hop Depth | Verdeckt/Auslaufend: Client redigiert abgelaufene Kontakte selektiv via SD-JWT beim Weitergeben |

## Nächste Schritte (Priorisiert)

1. **WOT-006**: Trust Establishment Protocol (Handschlag) - Zukünftiges ADR-007
2. **WOT-009**: Dual Storage Architecture (Entity Store vs Graph Matrix)
3. **WOT-001**: Finalize Vertrauensregister JSON/Rust struct specification
4. **WOT-002**: Define Piggyback Hooks and Ed25519 ↔ DID:key interfaces
5. **WOT-005**: Begin Rust implementation as separate WoT crate
