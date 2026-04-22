# ADR 5: Reziprokes Routing und granulare Privatsphäre via SD-JWT

**Status:** Vorgeschlagen / Entwurf  
**Aktualisiert:** Protokoll-Harmonisierung & JWE/JWS Standards  
**Kontext:** Protokoll / Web of Trust / Privacy  
**Datum:** 6. April 2026 (Aktualisiert am 22. April 2026)

## 1. Kontext und Problemstellung
Um Zahlungsrouten über mehrere Hops berechnen zu können, müssen Vertrauenslisten (wer vertraut wem) im Netzwerk weitergegeben werden.

Wenn ein globaler `max_hops`-Wert vom Nutzer gesetzt wird, entsteht ein spieltheoretisches Ungleichgewicht (das "Schmarotzer-Problem"): Ein Nutzer stellt maximale Privatsphäre ein (Hop = 1), profitiert aber von Freunden, die ihre Listen weit ins Netzwerk fluten (Hop = 3).

Gleichzeitig: Wenn Listen unterwegs von Relay-Knoten gekürzt werden (weil Hops ablaufen), bricht die digitale Signatur der ursprünglichen Liste.

## 2. Getroffene Entscheidung
Wir implementieren ein reziprokes ("Tit-for-Tat") Hop-Limit-Protokoll basierend auf selektiver Offenlegung (Selective Disclosure):

*   **Per-Contact Limits:** Jeder Kontakt in der Vertrauensliste erhält ein individuelles Hop-Limit.
*   **Reaktive Spiegelung:** Es findet **keine** verdeckte Aushandlung statt. Sobald Nutzer B die Vertrauensliste von Nutzer A empfängt, liest er im Klartext das von A definierte Hop-Limit aus. Nutzer B speichert daraufhin A in seiner eigenen Liste mit exakt demselben (oder einem niedrigeren) Limit ab.
*   **Selective Disclosure (SD-JWT):** Die Vertrauensliste (Trust List) wird als SD-JWT signiert. Wenn ein Knoten die Liste an den nächsten Hop weiterreicht, zählt er den Zähler hoch. Erreicht ein Eintrag sein Limit, wird er vom Knoten "redigiert" (aus der Liste gelöscht). Durch die SD-JWT-Kryptographie bleibt die Signatur für den Rest der Liste weiterhin kryptographisch gültig, auch nach der Redaktions-Ausdünnung.

## 3. Das Anreizmodell (Game Theory)

Ein rein freiwilliges Hop-Limit birgt ein gefährliches spieltheoretisches Ungleichgewicht. Ohne einen ausgleichenden Mechanismus würden Nutzer dazu tendieren, aus Angst oder extremen Privatsphäre-Bedenken die Weitergabe ihrer eigenen Liste strikt zu limitieren (z. B. auf 1 Hop). 

Gleichzeitig würden diese "ängstlichen" Nutzer von "mutigen" Freunden profitieren, die ihre Listen weiträumig (z. B. 4 Hops) in das Netzwerk verteilen. Der Ängstliche partizipiert so an der Reichweite der Mutigen, blockiert aber selbst den Informationsfluss. Würden alle im Netzwerk diese egoistische Strategie fahren, würde das System buchstäblich vertrocknen – es gäbe nicht genug Daten (Graphen-Tiefe) für die Pfadberechnung, und Zahlungen zwischen Unbekannten würden fehlschlagen ("Tragik der Allmende").

Um das System am Leben zu erhalten, erfordert das reziproke Routing eine **Straf- und Belohnungslogik**:

*   **Identifikation der Limitierung:** Die "mutigen" Freunde sehen bei der initialen Synchronisation, wie weit der "ängstliche" Freund seine eigene Liste verteilt.
*   **Reziproke Spiegelung:** Der "mutige" Freund passt daraufhin zwingend den Eintrag für den "ängstlichen" Freund in seiner eigenen Liste an das niedrige Niveau an. Die Hop-Anzahl wird gespiegelt.
*   **Folge:** Wenn der mutige Freund nun via Gossip seine großen Listen ins Netzwerk pusht, wird der Eintrag des ängstlichen Freundes extrem schnell "geschwärzt" (aus dem SD-JWT redigiert).
*   **Reputationsverlust:** Da der Ängstliche somit schnell aus den weitergeleiteten Listen der anderen herausfällt, existiert er für den Großteil des Netzwerks nicht. Er hat keine indirekte Reputation. Andere können ihn bei Geschäften nicht finden.

### Die Lösung
Wenn der ängstliche Nutzer finanzielle Reichweite im Netzwerk (Reputation) aufbauen möchte, **muss** er seine eigenen Privatsphäre-Limits lockern und die Hop-Zahl seiner eigenen Liste erhöhen. Durch diese automatische Spiegelungsregel profitieren letztlich der mutige Freund, der ängstliche Freund und das gesamte Netzwerk von einer tieferen Datengrundlage.

## 4. Konsequenzen

*   **Positiv:** Löst das Schmarotzer-Problem. Es entsteht eine natürliche, spieltheoretisch stabile Balance zwischen Privatsphäre und Netzwerknutzen.
*   **Positiv:** Volle Souveränität des Nutzers über die Verbreitung seiner Daten auf granularer Basis – aber gepaart mit direkten Konsequenzen für seine Isolation / Reichweite.
*   **Positiv:** Erlaubt data-driven deep routing ohne künstliche globale Barrieren in der Client-Berechnung, da die Begrenzung bereits kryptographisch auf Daten-Ebene (SD-JWT) greift und das Netzwerk sich organisch skaliert.
*   **Negativ/Risiko:** Der Einsatz von SD-JWTs und die individuelle Aushandlung von Kantenparametern erhöhen die algorithmische Komplexität bei der Erstellung und Validierung der Umschläge erheblich.
