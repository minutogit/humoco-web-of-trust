# ADR 0: Grundprinzip des Humoco Web of Trust (MVP)

**Status:** Informational / Übersicht  
**Aktualisiert:** Protokoll-Harmonisierung, Nadelöhr-Schutz & Gutschein-Bewertung  
**Kontext:** Dezentrales Web of Trust (WoT)  
**Datum:** 10. April 2026 (Aktualisiert am 30. Oktober 2026)

Diese Übersicht beschreibt den Kernmechanismus des Humoco (Human Money Core) Web of Trust, reduziert auf die essentiellen Schritte für den Austausch im direkten Umfeld (Freundeskreis) und den Aufbau des Vertrauensnetzwerks für den sicheren Handel.

## Architektur-Prämisse: Offline-First & Transport-Entkopplung (Server-Offenheit)

Das unverrückbare Fundament des Systems ist **Offline-First**:
*   **Vollständige Server-Unabhängigkeit:** Das Protokoll ist so konzipiert, dass die signierten Vertrauenslisten (SD-JWTs) 100 % selbsttragend sind. Das System funktioniert vollständig autonom über direkte P2P-Verbindungen wie NFC, Bluetooth LE, QR-Codes, lokale Dateien oder durch Transaktions-Huckepack (*Piggybacking*) innerhalb von `SecureContainer`-Umschlägen.
*   **Offenheit für Server & Transport-Entkopplung:** Die Datenstrukturen von `humoco-wot` sind strikt vom konkreten Transportweg entkoppelt. Dynamisch entstehende Server (wie blinde Postfach-Relays für asynchronen Austausch oder optionale Community-/Regional-Server zur Beschleunigung der Pfadsuche) werden ausdrücklich unterstützt. Sie transportieren und indizieren exakt dieselben signierten SD-JWTs wie lokale Direktverbindungen.
*   **Zero-Trust-Garantie:** Die Wallet verlässt sich zu keinem Zeitpunkt blind auf einen Server oder Transportkanal. Alle Vertrauensbewertungen basieren ausnahmslos auf den unverfälschbaren, kryptographischen Ed25519-Nutzersignaturen der SD-JWTs. Fällt jegliche Server-Infrastruktur aus oder wird sie zensiert, arbeitet das Humoco WoT auf P2P-Ebene logisch identisch und ohne Datenverlust weiter.

---

## 1. Die Grundbausteine: Die eigene Vertrauensliste

*   **Eine signierte Liste pro Nutzer:** Um das System hocheffizient zu halten, dokumentiert jeder Teilnehmer sein ausgesprochenes Vertrauen gebündelt in **einer einzigen persönlichen Liste**. Es gibt keinen globalen Konsens, keine Blockchain und keine verteilten Einzelsignaturen pro Freund.
*   **Asymmetrisches Vertrauen:** Vertrauen ist eine Einbahnstraße. Wenn Alice Bob vertraut, trägt sie Bob mit einer Vertrauensstufe in *ihre* Liste ein. Bobs eigene Liste ist davon völlig unabhängig.
*   **did:key als Identitätsbasis:** Jeder Teilnehmer wird durch einen kryptographischen Schlüssel (`did:key`) eindeutig identifiziert. Dies ermöglicht serverlose Authentifizierung und fälschungssichere Daten ohne zentrale Aussteller.
*   **SD-JWT als Listen-Format:** Die Liste wird als **SD-JWT** (Selective Disclosure JWT) strukturiert und vom Aussteller einmalig signiert. Hashes werden auf 128 Bit gekürzt, um maximale Dateneffizienz auf limitierten Funkstrecken (BLE, NFC, QR) zu garantieren. (Siehe [ADR 4](./adr-04-sd-jwt-vertrauenslisten.md))
*   **Lokale Alters-Gewichtung statt Zwangsablauf:** Vertrauenslisten enthalten im Drahtformat **kein** fixes `exp`-Verfallsdatum, sondern ein verpflichtendes Erstelldatum `iat` (Unix-Sekunden) und eine monotone Versionsnummer `v`. Die auswertende Wallet entscheidet lokal und autonom, wie ältere Listen gewichtet werden (z. B. über Zeit-Dämpfungsfaktoren).

---

## 2. Der Austausch: Listen sammeln und weiterreichen

Damit das Netzwerk wächst, tauschen die Teilnehmer ihre Listen untereinander aus. Man sammelt die Listen anderer Nutzer und gibt sie weiter.

*   **Listen-Austausch (Gossip):** Wenn Alice und Bob interagieren, übergibt Alice ihre aktuelle signierte Liste an Bob, und Bob seine an Alice.
*   **Listen weitergeben:** Bob sammelt nicht nur Alices Liste für sich selbst. Er "gossipt" (verteilt) sie auch weiter. Trifft Bob auf Carol, gibt er ihr nicht nur *seine* Liste, sondern auch *Alices* Liste. So sammelt das Netzwerk dezentral das Wissen über die Vertrauensbeziehungen.
*   **Stufe 0 ist KEINE Transit-Brücke (Anti-Bot & Datensparsamkeit):** 
    Stufe 0 ($\gamma = 0.0$) dient ausschließlich dazu, im direkten 1-Hop-Kontakt zu bestätigen, dass hinter einem `did:key` ein realer Mensch steht (Schutz vor Bot-Fluten). Da mathematisch $0.0 \times \text{alles} = 0.0$ gilt, dürfen über reine Stufe-0-Kanten **keine nachgelagerten Vertrauenslisten gesammelt, importiert oder weitergeleitet werden**. Dies verhindert unnötigen Daten-Ballast im lokalen Speicher und auf den Übertragungskanälen. Für Pfadberechnung und Graph-Import zählen ausschließlich Kanten mit Stufe $\ge 1$.
*   **Hop-Limits schützen die Privatsphäre und verhindern Schmarotzen:** 
    1.  **Limit der Liste (Globales Hop-Limit):** Jede Liste hat ein übergeordnetes Limit. Ist dieses erreicht, wird die Liste von einem Knoten gar nicht erst weitergeschickt.
    2.  **Limit der Einträge (Individuelles Hop-Limit):** Wenn die Liste als Ganzes weitergegeben werden darf, wird jeder einzelne Kontakt geprüft. Ist für eine Person das Limit erreicht, wird nur dieser Eintrag "geschwärzt" (Disclosure weggelassen). Dank SD-JWT bleibt die mathematische Signatur der restlichen Liste trotzdem gültig!
    3.  **Reziprokes Routing (Tit-for-Tat):** Um das Schmarotzer-Problem zu vermeiden (Nutzer profitieren von fremden Listen, sperren aber eigene), werden Hop-Limits gespiegelt. Gibt Alice Carol nur 1 Hop, spiegelt Carol ihren Eintrag für Alice ebenfalls auf 1 Hop. (Siehe [ADR 5](./adr-05-reziprokes-routing-sd-jwt.md))
*   **Datensparsamkeit durch Deltas:** Die App merkt sich im **Versand-Logbuch (Sent-Log)**, welche Versionen welcher Listen man einem Kontakt bereits geschickt hat. Bei erneuten Kontakten werden strikt nur neue oder aktualisierte Deltas übertragen. (Siehe [ADR 6](./adr-06-asynchrones-gossip-protokoll.md))

---

## 3. Der Handel: Graphen durchstöbern und Pfade berechnen

Wenn Alice mit einer ihr noch unbekannten Person Carol handeln oder deren Gutschein annehmen möchte, greift sie auf die lokal gesammelten Listen zurück.

### 3.1 Pfadsuche im Ego-Graphen
1.  **Suche in den gesammelten Listen:** Alice fragt ihre App: *"Finde ich in all den Listen, die ich gesammelt habe, eine Verbindung zu Carol?"*
2.  **Pfadfindung:** Die App stellt fest: Alice vertraut Bob. Bob vertraut Carol. Die Vertrauenskette `Alice -> Bob -> Carol` ist gefunden.

### 3.2 Berechnung des Vertrauenswertes
*   **Vertrauensstufen mit Haftung (Skin in the Game):**
    Das System kennt vier Stufen (`0..3`), wobei Stufe 0 rein der lokalen Existenzprüfung dient:
    *   **Stufe 0 (Mensch-Existenz):** $\gamma = 0.0$ / Keine Haftung (Bestätigt nur Mensch-Sein, **keine Transit-Brücke**)
    *   **Stufe 1 (Bekannter):** $\gamma = 0.30$ (30 %) / Richtwert 0,5 Stunden Arbeitszeithaftung
    *   **Stufe 2 (Guter Kontakt):** $\gamma = 0.60$ (60 %) / Richtwert 1,0 Stunden Arbeitszeithaftung
    *   **Stufe 3 (Enger Vertrauter):** $\gamma = 0.85$ (85 %) / Richtwert 4,0 Stunden Arbeitszeithaftung
*   **Multiplikative Dämpfung über Distanz:** Entlang eines isolierten Pfades sinkt das Vertrauen multiplikativ (z. B. $0.85 \times 0.60 = 51\,\%$).
*   **Nadelöhr-sichere Graphen-Mathematik (Shared-Edge Factoring):**
    *   **Echte unabhängige Pfade** über verschiedene Erstkontakte (z. B. `Ich -> Bob -> Carol` und `Ich -> Anna -> Tom -> Carol`) kombinieren sich über die Wahrscheinlichkeits-Union ($1 - \prod (1 - P_k)$) und können problemlos Werte weit über 30 % erreichen.
    *   **Nadelöhr-Schutz:** Laufen mehrere Pfade durch dieselbe Zwischenkante (z. B. `Ich --30%--> Bob` und hinter Bob verzweigen sich 20 Pfade zu Carol), wird die gemeinsame Kante mathematisch faktorisiert ($\Pr(\text{Ich} \leadsto \text{Carol}) = \gamma(\text{Ich}, \text{Bob}) \cdot \Pr(\text{Bob} \leadsto \text{Carol})$). Bobs interne Zuverlässigkeit zu Carol kann bis zu 99 % betragen, bei Alice kommen über Bob dennoch **niemals mehr als 30 %** an ($0.30 \times 0.99 = 29{,}7\,\%$). Dies macht Sybil-Cluster hinter Einzelkontakten wirkungslos. (Details in [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md))

### 3.3 Bewertung von Gutscheinen (Herausgeber & Bürgen)
Beim Empfang eines autonomen Layer-1-Gutscheins (Human Money Voucher) ermittelt das WoT dessen Vertrauenswürdigkeit zweistufig:
1.  **Betrugs-Veto (`KnownOffender`):** Ist der Herausgeber (`creator`) im lokalen Konfliktspeicher (`TrustProvider`) als überführter Betrüger bekannt (z. B. durch einen kryptographischen Double-Spend-Nachweis via SST V4), fällt der Vertrauenswert sofort auf `0 %` (rote Betrugswarnung).
2.  **Bürgen als temporäre Vertrauensbrücken:** Gültige Bürgen-Signaturen auf dem Gutschein (`role == "guarantor"`) wirken im Berechnungszeitpunkt als **temporäre gerichtete Kante `Bürge -> Herausgeber`** mit Standardgewicht $\gamma_{\text{bürge}} = 0.85$ (konfigurierbar). Danach wird im lokalen Ego-Graphen das Gesamtvertrauen zum Herausgeber (unter aktivem Nadelöhr-Schutz) berechnet.
    *Vorteil:* Eine vertraute Bürgin erhöht den Gutschein-Rückhalt sofort und vollständig offline, selbst wenn deren eigene WoT-Liste auf dem Endgerät noch gar nicht vorliegt.

---

## 4. Zusammenfassung des Ablaufs

1.  **Eintragen:** Jeder dokumentiert sein Vertrauen in *seiner eigenen Liste* mit diskreten Stufen `0..3` und signiert diese als SD-JWT mit `iat`, Versionsnummer `v` und Hop-Limits (siehe [ADR 4](./adr-04-sd-jwt-vertrauenslisten.md)).
2.  **Verteilen:** Man tauscht seine Liste mit Kontakten aus, sammelt im Gegenzug deren Listen (strikter Importfilter: nur Kanten ab Stufe 1) und reicht sie unter Beachtung der Hop-Limits und des reziproken Routings weiter (P2P oder über blinde Relays, siehe [ADR 5](./adr-05-reziprokes-routing-sd-jwt.md) und [ADR 6](./adr-06-asynchrones-gossip-protokoll.md)).
3.  **Pfadberechnung:** Die Wallet baut aus den gesammelten Listen einen lokalen Ego-Graphen auf und berechnet den exakten Vertrauenswert unter striktem Nadelöhr-Schutz (Shared-Edge Factoring, siehe [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) und [ADR 7](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).
4.  **Handeln & Gutscheine prüfen:** Beim Gutschein-Empfang werden Bürgen als Vertrauensbrücken einbezogen und bekannte Betrüger per Veto blockiert (siehe [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) und [ADR 7](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

---

**Hinweis zur Visualisierung:** Zum interaktiven Verständnis der Vertrauens-Propagation und Graphen-Mathematik existiert eine [grafische WoT-Simulation](../../wot-simulation/index.html). (Hinweis: Der frühe HTML-Prototyp nutzte noch eine vereinfachte Pfad-Union; für die Referenz-Implementierung in `humoco-wot` gilt verbindlich das Nadelöhr-sichere Shared-Edge Factoring gemäß [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).
