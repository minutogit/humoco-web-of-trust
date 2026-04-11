---
name: wot-architecture
description: Assistant specialized in Web of Trust architecture, Sybil protection, and protocol design for Humoco.
---

# SKILL: WoT-Architektur & Sybil-Schutz (Humoco)

Dieses Skill-Dokument enthält die zentralen architektonischen Prinzipien und das Wissen zur Implementierung des dezentralen Web of Trust (WoT) für das Projekt `human_money_core`.

## 1. Übersicht & Zielsetzung
Der WoT-Architekt ist darauf spezialisiert, ein offline-fähiges, datensparsames und Sybil-resistentes Vertrauensnetzwerk aufzubauen. Das Ziel ist es, Vertrauenspfade zwischen fremden Identitäten (`did:key`) ohne zentrale Instanz zu berechnen und kryptographisch zu beweisen.

## 2. Kernkomponenten des Vertrauens-Modells

### 2.1 TrustManifest (Lokale Speicherung)
- **Zweck:** Hybrider Container für die Daten des lokalen Nutzers.
- **Struktur:** Hält den eigenen `did:key`, einen vorberechneten **Tiered Cuckoo-Filter** ("Deckblatt") und eine Liste roher **SD-JWT Trust Attestations** ("Stempel").
- **Dateiformat:** JSON (MVP), verschlüsselt mit dem Profil-Passwort.
- **UI Metapher:** "Vertrauens-Ausweis" (Trust ID).

### 2.2 Datenstrukturen für Vertrauen
- **Key-Value Cuckoo-Filter:** Hocheffiziente Struktur (27 Bit/Slot), die Fingerabdrücke direkt mit der Vertrauensstufe verknüpft. Ermöglicht eine Präzision von 99,9999% bei minimalem Speicherbedarf (~800 Bytes für 150 Kontakte).
- **SD-JWT (Selective Disclosure JWT):** Kryptographisch bindende Attestierung zwischen zwei Identitäten. Unterstützt selektive Offenlegung des Vertrauenslevels (`trust_level`) und Key-Binding.
- **RSA Accumulator (Optional):** Für Hochsicherheits-Transaktionen zur Erbringung eines unwiderlegbaren Beweises eines Pfads.

## 3. Graphen-Evaluierung & Sybil-Schutz

### 3.1 Vertrauensstufen (Trust Levels)
Die Vertrauensbewertung folgt einer 4-Stufen-Logik:
- **Stufe 0 (Existence):** "Ich kenne diese Person (F2F)." (Dämpfung γ=0.0 — kein finanzieller Trust).
- **Stufe 1 (Acquaintance):** Bekannter. Limit: 50€. (γ=0.30).
- **Stufe 2 (Contact):** Standard-Freund. Limit: 500€. (γ=0.60).
- **Stufe 3 (Confidant):** Enger Vertrauter. Limit: 5.000€. (γ=0.85).

### 3.2 Pfadberechnung & Dämpfung
- **Formel:** Der Trust-Score eines Pfads ist das Produkt der Dämpfungsfaktoren entlang der Kanten (`γ1 * γ2 * ...`).
- **Min-Edge-Prinzip (Bottleneck):** Das effektive Limit eines Pfades wird durch das Basis-Limit der schwächsten Kante im Pfad bestimmt, multipliziert mit dem Pfad-Score.
- **Graphentiefe:** Maximal 2-3 Hops im MVP, um Rechenaufwand und Sybil-Risiko zu begrenzen.

### 3.3 Sybil-Schutz Mechanismen
- **Intersection Trust:** Vertrauen nur gegenüber Identitäten, die über das eigene lokale Netzwerk erreichbar sind.
- **Stufe-0-Firewall:** Die Vergabe von Stufe 0 (Existence) ist ratenbegrenzt und face-to-face. Ohne diese Kante ist ein Cluster finanziell isoliert.
- **Cluster-Detection:** Erkennung von "Inzucht-Clustern" (REC-Metrik < 1.0) und automatischer Trust-Discount.

## 4. Stranger Discovery Protocol (Handshake)
Besteht aus 5 Phasen zur schnellen Identifikation von Vertrauenspfaden über BLE/NFC:
1. **BEACON:** DID-Austausch & Nonce.
2. **INTERSECTION:** Bidirektionaler Key-Value Cuckoo-Filter-Abgleich zur Identifikation von Vertrauenspfaden und Stufen.
3. **PROOF ATTACH:** Zusammenstellung der SD-JWT-Kette (Receiver Principle).
4. **VERIFICATION:** Kryptographische Verifikation von Key-Binding und Signaturen.
5. **AUTHORIZATION:** Finaler Akzeptanz-Check gegen das effektive Limit.

## 5. Revokation (Widerruf)
- **Natural Decay:** SD-JWTs verfallen nach 30-90 Tagen (erfordert Erneuerung).
- **Explicit Revocation:** Signierte "Widerrufs-Attestierungen", die mittels Gossip im Netzwerk propagiert werden.
- **Epoch Rotation:** Periodische Neuerstellung von Cuckoo-Filtern mit neuem Pepper.

## 6. Richtlinien für Weiterentwicklung
- **Privacy First:** Minimierung der Preisgabe des sozialen Graphen durch selektive Offenlegung und probabilistische Strukturen.
- **Offline First:** Alle Berechnungen müssen lokal ohne Internetverbindung möglich sein.
- **Performance:** Cuckoo-Filter Abgleiche und Signaturverifikationen müssen auf mobilen Geräten < 10s dauern.
- **Zukunftssicherheit:** Berücksichtigung einer späteren Migration auf SQLite bei wachsenden Datenmengen.
