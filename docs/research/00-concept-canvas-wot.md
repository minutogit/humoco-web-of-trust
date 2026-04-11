# Concept Canvas: Dezentrales Web of Trust (WoT)

**Kontext:** Dieses Dokument beschreibt das übergeordnete Konzept für ein eigenständiges, dezentrales Reputations- und Vertrauenssystem. Es dient als "North Star" für die technische Implementierung in `human_money_core` und stellt sicher, dass Vertrauen in Transaktionen und Gutschein-Emittenten messbar und routingfähig wird.

---

## 1. Identität vs. Vertrauen (Die zwei Ebenen)

Ein robustes System muss strikt zwischen der physischen Existenz einer Entität und ihrer finanziellen Zuverlässigkeit unterscheiden.

### Ebene 0: Proof of Personhood (Kennen)
*   **Aussage:** "Ich bestätige, dass ID X einem echten, einzigartigen Menschen gehört."
*   **Zweck:** Sybil-Resistenz. Verhindert die massenhafte Erstellung von Bot-Accounts (Identitäts-Spam).

### Ebene 1: Finanzielles Vertrauen (Bewerten)
*   **Aussage:** "Ich vertraue Gutscheinen/Transaktionen von ID X zu Y %" (oder bis zu einem bestimmten Limit).
*   **UX-Pragmatismus:** Damit Nutzer nicht mit komplexen Prozent-Schiebereglern überfordert werden, mappt der Client einfache Kategorien (z. B. "Bekannter", "Enger Vertrauter") systemintern auf vordefinierte Werte (z. B. 30%, 90%).

---

## 2. Datenschutz-Strategien (PubKeys vs. Hashes)

Es gibt kein "One-Size-Fits-All" für Privatsphäre. Das System unterstützt hybride Ansätze je nach Rolle des Akteurs.

### Offene Public Keys (Transparenz)
*   **Szenario:** Gewerbetreibende (Bäcker, Dienstleister), NGOs oder Vereine.
*   **Nutzen:** Diese Akteure profitieren von einer öffentlichen Reputation. Eine offene Signatur stärkt ihre Auffindbarkeit und Vertrauenswürdigkeit im Netzwerk.

### Hashes / Blinded Keys (Privatsphäre)
*   **Szenario:** Privatpersonen, die ihr soziales Umfeld schützen möchten.
*   **Nutzen:** Verhindert Deanonymisierung durch Graphen-Analyse. Wenn A einen Hash von B signiert, bleibt die Verbindung für Außenstehende unsichtbar. B kann diese Verbindung jedoch gezielt peer-to-peer (z. B. gegenüber C) durch Offenlegung des Salts beweisen.

---

## 3. Spieltheorie & Haftung (Skin in the Game)

Vertrauen ist im Humoco-System eine knappe Ressource und darf nicht inflationär vergeben werden.

*   **Die Willenserklärung (Bürgschaft):** Das Aussprechen von Vertrauen ist ein vertragsähnlicher Akt. Wer Vertrauen ausspricht, geht eine (moralische oder systemische) Haftung ein.
*   **Haftungs-Konzept:** Bei hohem Vertrauen signiert A eine Erklärung: *"Sollte B seinen Verpflichtungen nicht nachkommen, hafte ich für X % des Ausfalls."*
*   **Reputationsschaden:** Bei Betrug eines Nutzers sinkt nicht nur sein Score auf Null, sondern auch der Score derjenigen, die für ihn gebürgt haben. Dies eliminiert "Spam-Vertrauen" und sorgt für ökonomische Stabilität.

---

## 4. Graphentheorie & Transitivität (Pfadberechnung)

Vertrauen muss über Zwischenstationen (Hops) delegierbar und berechenbar sein.

*   **Vertrauens-Dämpfung (Decay):** Jeder Hop in einer Kette (A -> B -> C) reduziert das abgeleitete Vertrauen (z. B. 0.9 * 0.9 = 0.81).
*   **Multipath-Kombination:** Wenn eine Person über mehrere unabhängige Pfade "erreicht" wird, erhöht sich das berechnete Gesamtvertrauen (Konvergenz von Beweisen).
*   **Schwellenwerte (Thresholds):** Client-Anwendungen nutzen Regeln wie: *"Akzeptiere Gutscheine unter 50 Einheiten automatisch, wenn der Trust-Score > 60% ist."*

---

## 5. Daten-Lebenszyklus & Netzwerkeffizienz

### Batching (Trust Manifests)
Anstatt jede Verbindung einzeln zu signieren, bündeln Nutzer ihre Vertrauensbeweise in Listen (Manifeste). Das spart Speicherplatz und reduziert den Rechenaufwand bei Signaturprüfungen.

### Time-to-Live (Ablaufdatum)
Jede Vertrauenssignatur hat ein zwingendes Ablaufdatum (z. B. 6 Monate). Dies bereinigt den Graphen von inaktiven "Karteileichen" und zwingt zur regelmäßigen Re-Evaluierung von Beziehungen.

### Widerruf (Revocation / Tombstones)
Bei Vertrauensbruch oder Schlüsselverlust können "Tombstone"-Nachrichten (Widerrufs-Attestierungen) mit höchster Priorität ins Netzwerk gesendet werden, um bestehende Bürgschaften sofort zu annullieren.
