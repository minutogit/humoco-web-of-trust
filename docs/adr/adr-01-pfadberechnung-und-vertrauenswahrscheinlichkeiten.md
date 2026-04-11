# ADR 1: Pfadberechnung und Vertrauenswahrscheinlichkeiten (Graph-Evaluierung)

**Status:** Akzeptiert
**Kontext:** Dezentrales Web of Trust (WoT) basierend auf `did:key`  
**Datum:** 6. April 2026

## 1. Problemstellung
Nachdem die Vertrauenslisten als SD-JWTs (ADR 0004) im Netzwerk asynchron verteilt wurden (ADR 0006), liegen im lokalen Wallet zahlreiche isolierte Kanten (Vertrauensbeziehungen) zwischen verschiedenen Nutzern vor. Um das Netzwerk als Basis für das "Human Money" System nutzen zu können, muss der Client in der Lage sein, aus diesen iterierbaren Listen eine sinnvolle Pfadberechnung durchzuführen, um die Vertrauenswürdigkeit eines völlig fremden Dritten zu evaluieren ("Stranger Discovery").

Es muss definiert werden, wie Vertrauen (als Wahrscheinlichkeit/Gewichtung) über mehrere Hops hinweg abnimmt und mathematisch effizient berechnet wird.

## 2. Getroffene Entscheidung
Wir nutzen die lokal gecachten Vertrauenslisten (SD-JWTs), um beim Nutzer lokal (offline) dezentrale Pfadberechnungen durchzuführen. Basis dafür ist das Kalkulationsmodell, welches bereits in der *WoT Simulation* (`wot-simulation/index.html`) erfolgreich evaluiert und visuell verifiziert wurde.

### Technische Spezifikationen

#### A. Multiplikative Dämpfung (Probability Tracking)
*   Vertrauen ist in unserem System nicht additiv, sondern wird als **Übertragungswahrscheinlichkeit** modelliert.
*   Jede Kante entspricht einem der drei Level aus ADR 0003, welche festen Vertrauensfaktoren entsprechen:
    *   **Level 1 (Bekannter):** 30 % (`0.30`)
    *   **Level 2 (Guter Kontakt):** 60 % (`0.60`)
    *   **Level 3 (Enger Vertrauter):** 85 % (`0.85`)
*   Der isolierte Wert eines einzelnen Pfades über mehrere Hops hinweg berechnet sich zwingend multiplikativ: `Vertrauen(Pfad) = Kante(A->B) * Kante(B->C) * Kante(C->D)`.
*   *Beispiel:* Wenn Alice Bob sehr stark vertraut (Level 3 / 85 %) und Bob Carol gut vertraut (Level 2 / 60 %), dann vertraut Alice Carol über genau diesen einen Pfad zu 51 % (`0.85 * 0.60 = 0.51`). Dies führt zu einer natürlichen Dämpfung des Vertrauens über die Distanz.

#### B. Pfadsuche und Zusammenführung (Netzwerk-Vertrauen)
*   Wie in der interaktiven *WoT Simulation* visuell bewiesen, reicht ein einzelner Pfad oft nicht aus, um ein fremdes Ziel als vertrauenswürdig genug zu qualifizieren. Das System **sucht deshalb aktiv nach diversen, voneinander überlappenden oder unabhängigen Pfaden** (Multi-Path Search) vom Start- zum Zielnutzer.
*   Diese gefundenen Einzelpfad-Wahrscheinlichkeiten werden als unabhängige Ereignisse vereint (Union of Independent Probabilities).
*   Formel: `Gesamtvertrauen = 1 - ( (1 - Pfad_1) * (1 - Pfad_2) * ... )`
*   Viele für sich genommen schwache Pfade (z. B. über entfernte Bekannte) können in der Summe kombiniert ein starkes, belastbares Gesamtvertrauen bilden, was organische dichte Netzwerke fördert.

#### C. Lokale Berechnung (Client-Side Ego-Graph)
*   Die Berechnung erfolgt vollständig dezentral auf dem Endgerät des Nutzers anhand seines spezifischen, lokalen Caches.
*   Es gibt keine "globale, objektive Wahrheit" über die Vertrauenswürdigkeit im System. Jeder Client baut seinen eigenen Ego-zentrierten Graphen auf und berechnet Wahrscheinlichkeiten strikt aus seiner eigenen Perspektive.

## 3. Rationale (Begründung)
*   **Sybil-Resilienz by Design:** Das probabilistische Berechnungsmodell ist stark gegenüber automatisierten Sybil-Angriffen (Erstellung massiver Fake-Accounts). Mehrere Accounts eines Angreifers müssen letztlich alle durch die eine oder wenigen echten Vertrauenskanten ("Bottleneck") fließen, die ehrliche Nutzer zum Angreifer aufgebaut haben. Die multiplikative Dämpfung limitiert den potenziellen Reputations-Schaden für das restliche Netzwerk mathematisch hart ab.
*   **Praxisgeprüft durch Simulation:** Die Effizienz dieses mathematischen Modells hat sich in unserer interaktiven HTML-Netzwerksimulation im Browser bereits visuell bewährt. Der Rust-Core muss diese Logik lediglich replizieren.

## 4. Konsequenzen
- **Positiv:** Es entsteht ein sehr natürliches, widerstandsfähiges Abbild menschlichen Vertrauens (ähnlich dem PGP Web of Trust, jedoch mathematisiert).
- **Positiv:** Schnelle, datenschutzfreundliche Auswertung der lokalen Offline-Datenpools (ohne zentrale Server-Requests).
- **Architektur-Verschlankung:** Wahrscheinlichkeiten ohne globale oder künstliche Metriken bilden den zentralen, einheitlichen Kern des Vertrauensabgleichs.
