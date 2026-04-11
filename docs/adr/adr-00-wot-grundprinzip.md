# ADR 0: Grundprinzip des Humoco Web of Trust (MVP)

**Status:** Informational / Übersicht
**Kontext:** Dezentrales Web of Trust (WoT)
**Datum:** 10. April 2026

Diese Übersicht beschreibt den Kernmechanismus des Humoco (Human Money Core) Web of Trust, reduziert auf die essentiellen Schritte für den Austausch im direkten Umfeld (Freundeskreis) und den Aufbau des Vertrauensnetzwerks für den Handel.

**Architektur-Prämisse: Offline-First & Server-Unabhängigkeit**
Das primäre Designziel ist ein extrem schlankes, effizientes und einfaches Protokoll, das *komplett ohne Server* oder zentrale Infrastruktur zu 100 % funktionstüchtig ist (z.B. über reine P2P-Verbindungen wie NFC, Bluetooth oder direkte LAN-Syncs). 
Server (ob als Relays oder für verschlüsselte Zwischenspeicher) werden vom System jedoch keinesfalls ausgeschlossen! Sie sind im Gegenteil stark erwünscht, um den Komfort zu erhöhen, die asynchrone Datenverbreitung dramatisch zu beschleunigen und die allgemeine Akzeptanz zu steigern. Das architektonische Prinzip lautet lediglich: Fällt die Server-Infrastruktur weg, funktioniert das Protokoll in seiner Logik absolut identisch weiter, lediglich der Komfort (z.B. Ladezeiten oder Hintergrund-Synchronisation) sinkt.

## 1. Die Grundbausteine: Die eigene Vertrauensliste

*   **Eine signierte Liste pro Nutzer:** Um das System hocheffizient zu halten, dokumentiert jeder Teilnehmer sein ausgesprochenes Vertrauen gebündelt in **einer einzigen persönlichen Liste**. (Es gibt *keinen* gigantischen globalen Datensatz und auch nicht hunderte separat verschickte Einzel-Dateien (Einzelsignaturen) pro Freund).
*   **Asymmetrisches Vertrauen:** Vertrauen ist eine Einbahnstraße. Wenn Alice Bob vertraut, trägt sie Bob mit einer Vertrauensstufe in *ihre* Liste ein. Bobs eigene Liste ist davon völlig unabhängig.
*   **did:key als Identitätsbasis:** Jeder Teilnehmer wird durch einen kryptographischen Schlüssel (`did:key`) eindeutig identifiziert. Dies ermöglicht serverlose Authentifizierung und signierte Daten ohne zentrale Aussteller.
*   **SD-JWT als Listen-Format:** Diese eine Liste wird als **SD-JWT** (Selective Disclosure JWT) verpackt und von Alice einmalig signiert. Das Besondere daran: Die Liste ist fälschungssicher und Einträge darin lassen sich "schwärzen". Für maximale Effizienz werden Hashes auf 128 Bit gekürzt. (Siehe [ADR 4](./adr-04-sd-jwt-vertrauenslisten.md))

## 2. Der Austausch: Listen sammeln und weiterreichen

Damit das Netzwerk wächst, tauschen die Teilnehmer ihre Listen untereinander aus. **Man sammelt die Listen anderer Nutzer und gibt sie weiter.**

*   **Listen-Austausch (Gossip):** Wenn Alice und Bob interagieren, übergibt Alice ihre aktuelle signierte Liste an Bob, und Bob seine an Alice.
*   **Listen weitergeben:** Bob sammelt nicht nur Alices Liste für sich selbst. Er "gossipt" (verteilt) sie auch weiter. Trifft Bob auf Carol, gibt er ihr nicht nur *seine* Liste, sondern auch *Alices* Liste. So sammelt das Netzwerk dezentral das Wissen über die Vertrauensbeziehungen.
*   **Hop-Limits schützen die Privatsphäre und verhindern Schmarotzen:** 
    1.  **Limit der Liste (Globales Hop-Limit):** Jede Liste hat ein übergeordnetes Limit. Ist dieses erreicht, wird die Liste von einem Netzwerkknoten gar nicht erst weitergeschickt.
    2.  **Limit der Einträge (Individuelles Hop-Limit):** Wenn die Liste als Ganzes noch weitergegeben werden darf, wird jeder einzelne Kontakt in der Liste geprüft. Ist für eine bestimmte Person das Limit erreicht, wird nur dieser Eintrag "geschwärzt" (aus der Liste ausgeblendet). Die Magie der SD-JWTs sorgt dafür, dass die mathematische Signatur der restlichen Liste trotzdem gültig bleibt!
    3.  **Reziprokes Routing (Tit-for-Tat):** Um das "Schmarotzer-Problem" zu vermeiden (Nutzer profitieren von weit verbreiteten Listen, geben aber ihre eigenen nur eingeschränkt weiter), werden Hop-Limits automatisch gespiegelt. Wenn Carol Alices Liste empfängt und sieht, dass Alice Carol nur 1 Hop gibt, passt Carol ihren Eintrag für Alice ebenfalls auf 1 Hop an. Dies schafft eine spieltheoretisch stabile Balance zwischen Privatsphäre und Netzwerknutzen. (Siehe [ADR 5](./adr-05-reziprokes-routing-sd-jwt.md))
*   **Datensparsamkeit durch Deltas:** Da man viele Listen sammelt und den Datenaustausch etwas effizienter, merkt sich die App (Versand-Logbuch), welche Versionen welcher Listen man einem Freund bereits geschickt hat. Trifft man sich wieder, schickt man nur aktualisierte oder neue Listen weiter. (Siehe [ADR 6](./adr-06-asynchrones-gossip-protokoll.md))

## 3. Der Handel: Graphen durchstöbern und Pfade berechnen

Wenn Alice nun mit einer ihr (noch) unbekannten Person Carol handeln möchte, greift sie auf die lokal gesammelten Listen zurück. 

1.  **Suche in den gesammelten Listen:** Alice fragt ihre App: *"Finde ich in all den Listen, die ich gesammelt habe, eine Verbindung zu Carol?"*
2.  **Pfadfindung:** Die App stellt fest: Alice hat Bob in ihrer Liste. Bob hat ihr irgendwann mal *seine* Liste geschickt, und darin steht Carol. (Alice -> Bob -> Carol). Die Vertrauenskette ist gefunden.
3.  **Berechnung des Vertrauenswertes (Dämpfung):**
    *   **Vertrauensstufen mit Haftung:** Das System kennt vier Stufen, wobei **Stufe 0** (Mensch-Existenz) nur bestätigt, dass jemand ein Mensch ist, ohne Vertrauensbewertung. Die drei aktiven Vertrauensstufen entsprechen festen **Vertrauensfaktoren in Prozent** und **Haftungen in Arbeitszeit** (Skin in the Game). Die Haftungsstunden sind Vorschläge und können je nach Risikoanpassung variieren:
        *   **Stufe 0 (Mensch-Existenz):** Kein Vertrauenswert / Keine Haftung (Bestätigt nur Mensch-Sein)
        *   **Bekannter:** 30 % (0.30) / 0,5 Stunden Haftung
        *   **Guter Kontakt:** 60 % (0.60) / 1,0 Stunden Haftung
        *   **Enger Vertrauter:** 85 % (0.85) / 4,0 Stunden Haftung
    *   **Dämpfung über Distanz:** Dieser Prozentsatz wirkt bei der Pfadberechnung als Dämpfung. Je mehr Hops ein Pfad hat (Alice -> Bob -> Carol), desto stärker wird das ursprüngliche Vertrauen multiplikativ "gedämpft" (z.B. 85% * 60% = 51%).
    *   **Graphen-Mathematik:** Wenn es mehrere Pfade zu Carol gibt, können sich diese Wahrscheinlichkeiten verbinden und so einen insgesamt höheren Vertrauenswert ergeben. (Siehe [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md))

Diesen berechneten **Vertrauenswert** aus gemeinsamen gesammelten Listen zu kennen, ist das Fundament für den sicheren Handel. **Wichtig für den Start (MVP):** Aus diesem Prozentwert ergibt sich noch *kein automatisches finanzielles Limit*. Das System berechnet nur die Vertrauenswahrscheinlichkeit; das finanzielle Risiko muss jeder Nutzer beim Handel (noch) selbst bewerten.

### Zusammenfassung des Ablaufs

1.  **Eintragen:** Jeder dokumentiert sein Vertrauen ("Für jemanden einstehen") in *seiner eigenen Liste* mit den vier Stufen (Stufe 0: Mensch-Existenz, 30%/0,5h, 60%/1,0h, 85%/4,0h) und signiert diese als SD-JWT (mit Hop-Limits).
2.  **Verteilen:** Man tauscht seine Liste mit Freunden aus, sammelt im Gegenzug deren Listen und reicht diese (unter Beachtung der Hop-Limits und reziproker Spiegelung) im Netzwerk weiter.
3.  **Rechnen:** Die Wallet-App baut aus all diesen lokal gesammelten Listen einen Graphen und berechnet vollautomatisch den prozentualen Vertrauenswert zu anderen Teilnehmern.

---

**Tipp zur Visualisierung:** Zum besseren Verständnis der Vertrauens-Propagation und der Graphen-Mathematik gibt es eine grafische [WoT-Simulation](../../wot-simulation/index.html), in der diese Mechanismen interaktiv ausprobiert werden können.
