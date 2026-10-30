# ADR 1: Pfadberechnung und Vertrauenswahrscheinlichkeiten (Graph-Evaluierung)

**Status:** Akzeptiert  
**Aktualisiert:** Protokoll-Harmonisierung, Nadelöhr-Schutz (Shared-Edge Factoring) & Gutschein-Bewertung  
**Kontext:** Dezentrales Web of Trust (WoT) basierend auf `did:key`  
**Datum:** 6. April 2026 (Aktualisiert am 30. Oktober 2026)

## 1. Problemstellung

Nachdem Vertrauenslisten als SD-JWTs ([ADR 4](./adr-04-sd-jwt-vertrauenslisten.md)) im Netzwerk asynchron und transportunabhängig verteilt wurden ([ADR 6](./adr-06-asynchrones-gossip-protokoll.md)), liegen im lokalen Endgerät zahlreiche gerichtete Kanten (Vertrauensbeziehungen) zwischen verschiedenen Nutzern vor. Um diese Daten als belastbare Vertrauensbasis für das „Human Money“-System zu nutzen, muss der Client in der Lage sein, autonom und offline:
1. die Vertrauenswürdigkeit eines unbekannten Dritten zu evaluieren („Stranger Discovery“),
2. den Vertrauens- und Deckungsrückhalt von autonomen L1-Gutscheinen (Herausgeber und Bürgen) zu berechnen.

Dabei darf Vertrauen bei überlappenden Pfaden nicht naiv aufsummiert werden. Wenn mehrere Pfade durch dieselbe Zwischenstation (Bottleneck) verlaufen, würde eine unkorrigierte Union zu einer künstlichen Vertrauensinflation führen. Gleichzeitig müssen reine Existenzbestätigungen (Stufe 0) vor nutzlosem Daten-Ballast schützen und das Alter von Listen ohne starre Verfallsdaten berücksichtigt werden.

---

## 2. Getroffene Entscheidung

Die Vertrauensberechnung erfolgt vollständig lokal und offline auf dem Endgerät anhand des gecachten Ego-Graphen. Basis ist ein mathematisch exaktes Zuverlässigkeitsmodell (**Kanten-Zuverlässigkeit mit Nadelöhr-Schutz / Shared-Edge Factoring**).

### Technische Spezifikationen

#### A. Vertrauensstufen und Kanten-Zuverlässigkeit
Jede gerichtete Kante $e = (u, v)$ im lokalen Graphen repräsentiert ein stochastisches Zuverlässigkeitsereignis mit der Wahrscheinlichkeit $\gamma(e)$:

*   **Stufe 0 (Mensch-Existenz / Anti-Bot):** $\gamma = 0.0$  
    Bestätigt ausschließlich im direkten 1-Hop-Kontakt, dass hinter einem `did:key` ein realer Mensch steht.  
    **Wichtig (Keine Transit-Brücke):** Da mathematisch $0.0 \times \text{alles} = 0.0$ gilt, bildet Stufe 0 keine Transit-Brücke. Über reine Stufe-0-Kanten werden weder Pfade zu Dritten berechnet, noch nachgelagerte Vertrauenslisten gesammelt, importiert oder weitergeleitet. Dies schützt den lokalen Speicher vor Daten-Ballast.
*   **Stufe 1 (Bekannter):** $\gamma = 0.30$ (30 %)
*   **Stufe 2 (Guter Kontakt):** $\gamma = 0.60$ (60 %)
*   **Stufe 3 (Enger Vertrauter):** $\gamma = 0.85$ (85 %)

Für die Pfadberechnung und den Graph-Import zählen ausschließlich Kanten mit $\text{Stufe} \ge 1$.

#### B. Multiplikative Dämpfung entlang eines isolierten Pfades
Entlang eines einzelnen gerichteten Pfades $P = (v_0, v_1, \dots, v_k)$ von der Wurzel $v_0$ zum Ziel $v_k$ berechnet sich die Wahrscheinlichkeit zwingend multiplikativ:
$$P(P) = \prod_{i=0}^{k-1} \gamma(v_i, v_{i+1})$$

*Beispiel:* Vertraue ich Bob zu 85 % (Stufe 3) und vertraut Bob Carol zu 60 % (Stufe 2), beträgt das Vertrauen über genau diesen Pfad $0.85 \times 0.60 = 0.51$ (51 %). Die Dämpfung spiegelt den natürlichen Informations- und Kontrollverlust über Distanz wider.

#### C. Nadelöhr-sichere Pfadberechnung (Shared-Edge Factoring)
In dichten Netzwerken existieren häufig mehrere Pfade zum Ziel. Die bisherige naive Annahme, überlappende Pfade einfach als unabhängige Ereignisse über $1 - \prod (1 - P_k)$ zusammenzuführen, wird korrigiert, da sie geteilte Kanten mehrfach zählt.

1.  **Echte unabhängige Wege (Kantendisjunkte Pfade):**  
    Verlaufen Pfade über *verschiedene Erstkontakte* und teilen keine Kanten (z. B. `Ich -> Bob (30%) -> X` und `Ich -> Anna (60%) -> Tom (60%) -> X`), sind sie stochastisch unabhängig. Sie kombinieren sich über die Union unabhängiger Wahrscheinlichkeiten:
    $$\Pr(\text{Netzwerk-Rückhalt}) = 1 - \prod_{k} (1 - P(P_k))$$
    *Beispiel:* Bei zwei unabhängigen Pfaden mit $P_1 = 0.30$ und $P_2 = 0.60 \times 0.60 = 0.36$ ergibt sich:
    $$\Pr = 1 - (1 - 0.30)(1 - 0.36) = 1 - (0.70 \times 0.64) = 1 - 0.448 = 55{,}2\,\%$$
    Echte Mehrfachpfade über verschiedene Freunde steigern das Vertrauen somit substanziell und erreichen problemlos Werte weit über 30 %.

2.  **Gemeinsame Nadelöhre (Shared Bottlenecks / Shared-Edge Factoring):**  
    Teilen sich Pfade eine gemeinsame Kante (z. B. `Ich --30%--> Bob` und hinter Bob verzweigen sich 20 verschiedene Pfade `Bob -> K_1..K_20 -> X`), darf die Kante `(Ich, Bob)` nicht mehrfach in eine naive Union einfließen.  
    Stattdessen wird die gemeinsame Nadelöhr-Kante mathematisch faktorisiert (Shannon-Dekomposition):
    $$\Pr(\text{Ich} \leadsto X) = \gamma(\text{Ich}, \text{Bob}) \cdot \Pr(\text{Bob} \leadsto X)$$
    Selbst wenn die 20 redundanten Pfade hinter Bob dessen Vertrauen zu $X$ auf 99 % anheben ($\Pr(\text{Bob} \leadsto X) = 0.99$), gilt für mich:
    $$\Pr(\text{Ich} \leadsto X) = 0.30 \times 0.99 = 29{,}7\,\% \le 30\,\%$$
    **Sicherheitsgarantie:** Über einen Zwischenkontakt kann niemals mehr Vertrauen fließen, als man diesem Kontakt selbst entgegenbringt. Sybil-Cluster und Bot-Armeen hinter einer einzelnen Vertrauenskante verpuffen wirkungslos.

3.  **Allgemeine Berechnung (DAG / Graph):**  
    Für beliebige Netzwerktopologien wird die exakte Zuverlässigkeit (*Two-Terminal Reliability*) via Serien-Parallel-Reduktion und Shannon-Faktorisierung bezüglich geteilter Brückenkanten gelöst:
    $$\Pr(G) = \gamma(e) \cdot \Pr(G \mid e \text{ aktiv}) + (1 - \gamma(e)) \cdot \Pr(G \mid e \text{ inaktiv})$$
    Für Performanz-Garantien auf mobilen Endgeräten kann die Berechnung auf die $k$ vertrauensstärksten disjunkten Pfadkorridore beschränkt werden.

4.  **Hinweis zum HTML-Simulator (`wot-simulation/index.html`):**  
    Der frühe explorative HTML-Prototyp nutzte zur Veranschaulichung noch die vereinfachte ungedeckelte Pfad-Union. Für die produktive Referenz-Implementierung in der Rust-Bibliothek `humoco-wot` gilt verbindlich das hier spezifizierte Shared-Edge Factoring.

#### D. Lokale Alters-Gewichtung statt Zwangs-Ablaufdatum
Vertrauenslisten tragen im SD-JWT-Drahtformat **kein** fixes `exp`-Ablaufdatum.
*   **Pflichtfelder:** Jede Liste deklariert zwingend das Erstelldatum `iat` (Issued At, Unix-Sekunden) und eine monotone Versionsnummer `v`.
*   **Rationale:** Ein fixes Protokoll-Ablaufdatum würde im reinen Offline-P2P-Betrieb dazu führen, dass bei längerer Netzabwesenheit plötzlich das gesamte Vertrauensnetzwerk erlischt.
*   **Lokale Wallet-Souveränität:** Die auswertende Wallet entscheidet lokal, wie ältere Listen gewichtet werden:
    *   Anwendung eines optionalen Zeit-Dämpfungsfaktors $d_{\text{age}}(\Delta t) \in (0, 1]$ auf die Kanten einer Liste (z. B. lineare oder exponentielle Dämpfung nach mehreren Monaten ohne Update).
    *   Visueller Altershinweis in der Benutzeroberfläche (z. B. "Vertrauensbasis vor 5 Monaten aktualisiert").

---

## 3. Bewertung von Gutscheinen (Herausgeber & Bürgen)
(Schnittstellendefinition und Datenstrukturen siehe [ADR 7](./adr-07-datenstruktur-speicher-und-schnittstellen.md))

Beim Empfang eines autonomen Layer-1-Gutscheins (Human Money Voucher) ermittelt das WoT dessen Vertrauenswürdigkeit zweistufig über den lokalen Ego-Graphen:

```
                  +--------------------------------+
                  |  Gutschein-Herausgeber         |
                  |  (creator)                     |
                  +--------------------------------+
                     ^                          ^
                     |                          |
   temporäre Kante   | gamma = 0.85             | temporäre Kante
   (role: guarantor) |                          | (role: guarantor)
                     |                          |
            +-----------------+        +-----------------+
            | Bürge 1         |        | Bürge 2         |
            +-----------------+        +-----------------+
                     ^                          ^
                      \                        /
                       \  reguläre WoT-Pfade  /
                        \                    /
                       +----------------------+
                       | Ich (Lokale Wallet)  |
                       +----------------------+
```

### 3.1 Betrugs-Veto (`KnownOffender`)
Vor jeder Pfadberechnung prüft der lokale `TrustProvider`, ob für den Herausgeber (`creator`) ein kryptographischer Beweis für böswilliges Verhalten (z. B. ein Double-Spend-Konflikt über SST V4) im lokalen Konfliktspeicher vorliegt.
*   Ist der Herausgeber als `KnownOffender` markiert, wird der Vertrauenswert des Gutscheins **sofort auf 0 % gesetzt**.
*   Die Benutzeroberfläche zeigt eine unmissverständliche Betrugswarnung an.

### 3.2 Bürgen als temporäre Vertrauensbrücken
Besitzt der Gutschein gültige Bürgen-Signaturen (`role == "guarantor"`):
1.  Jeder verifizierte Bürge fügt für die Berechnung eine **temporäre gerichtete Kante `Bürge -> Herausgeber`** mit Standardgewicht $\gamma_{\text{bürge}} = 0.85$ (konfigurierbar) in den Graph ein.
2.  Das Gesamtsystem berechnet nun den Vertrauenswert von `Ich` zum `Herausgeber` unter voller Anwendung des Nadelöhr-Schutzes (Shared-Edge Factoring).
3.  **Offline-Sofortwirkung:** Vertraue ich einer Bürgin Berta (z. B. mit 60 %), so entsteht über die temporäre Kante `Berta --85%--> Herausgeber` ein Vertrauenswert von $0.60 \times 0.85 = 51\,\%$. Der Gutschein besitzt sofort belastbaren Rückhalt, selbst wenn Bertas persönliche WoT-Liste auf meinem Endgerät noch gar nicht synchronisiert wurde.
4.  **Mehrfachbürgen:** Mehrere unabhängige Bürgen wirken wie parallele Pfade und verstärken den Rückhalt redundant über die Wahrscheinlichkeits-Union.

---

## 4. Rationale & Konsequenzen

*   **Sybil-Resilienz by Design:** Angreifer können hinter einem kompromittierten Kontakt beliebig viele Fake-Knoten und Zyklen erzeugen; durch Shared-Edge Factoring ist der Maximalwert strikt durch die Kante zum echten Kontakt gedeckelt.
*   **Datensparsamkeit:** Durch den Ausschluss von Stufe-0-Transits wird das Weiterleiten und Speichern bedeutungsloser Kanten verhindert.
*   **Offline-Robustheit:** Ohne harte Verfallsdaten (`exp`) bleibt das Vertrauensnetzwerk auch in Krisensituationen oder bei mehrmonatiger Netzabwesenheit voll funktionsfähig.
*   **Nahtlose L1-Integration:** Der Gutschein-Vertrauenswert verbindet L1-Kryptographie (Bürgen-Signaturen, SST V4 Double-Spend-Beweise) transparent mit der lokalen WoT-Reputation.
