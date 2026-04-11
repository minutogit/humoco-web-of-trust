# WoT Glossar: Begriffe und Definitionen

Dieses Dokument definiert die wesentlichen Begriffe, die in der Architektur des Humoco Web of Trust (WoT) verwendet werden, um eine klare und einheitliche Terminologie sicherzustellen.

## 1. Identitäten

### did:key
Der dezentrale Identifier einer Person oder Entität. Er basiert direkt auf dem öffentlichen kryptographischen Schlüssel (Ed25519). Es gibt keine zentrale Registry; wer den privaten Schlüssel besitzt, kontrolliert die Identität.

---

## 2. Datenstrukturen

### Vertrauensliste (Trust List)
Die zentrale Datenstruktur, in der ein Nutzer (Aussteller) all seine Kontakte und deren Vertrauensstufen sammelt und diese Liste **genau einmal digital signiert**. Diese signierte Liste wird als Ganzes über das Netzwerk (via Vertrauens-Propagation) verteilt, damit andere den echten Vertrauensgraphen berechnen können.

### SD-JWT (Selective Disclosure JWT)
Das spezielle kryptographische Format, in dem die *Vertrauensliste* gespeichert und signiert wird. Das Besondere: Wenn Knotenpunkte (Peers) diese Liste weiterleiten, können sie gezielt einzelne Einträge (Schlüssel) daraus löschen bzw. verbergen (redigieren), **ohne dass die ursprüngliche Signatur des Ausstellers bricht**. Das sichert die Privatsphäre nach Ablauf des Hop-Limits.

### Lokales Vertrauensregister (Trust Register)
Der lokale Speicher auf dem Endgerät (Smartphone) des Nutzers. Hier werden die eigene Vertrauensliste sowie alle empfangenen, fremden Listen für die Offline-Pfadberechnung verwaltet.

---

## 3. Metriken & Kalkulation

### Vertrauensstufen (Trust Levels)
Das System nutzt ein Stufenmodell zur Qualifizierung von Verbindungen:
- **Level 0 (Existenz):** Bestätigung, dass es sich um einen Menschen handelt (keine finanzielle Haftung).
- **Level 1 (Bekannter):** Vertrauensfaktor 30 %.
- **Level 2 (Guter Kontakt):** Vertrauensfaktor 60 %.
- **Level 3 (Enger Vertrauter):** Vertrauensfaktor 85 %.

### Vertrauensfaktor (Trust Factor)
Ein prozentualer Wert, der beschreibt, wie verlässlich eine Empfehlung ist. Bei der Pfadberechnung führt dieser Faktor zu einer mathematischen Dämpfung des Vertrauens über jeden Verbindungsschritt (Hop) hinweg.

### Netzwerk-Vertrauen (Netzwerk-Rückhalt)
Die Stärke deiner Verbindung zu einer fremden Person, berechnet aus deinem persönlichen Netzwerk. Während ein einzelner Kontakt unsicher sein kann, ergibt die Summe vieler unabhängiger Empfehlungen über verschiedene Pfade ein belastbares Gesamtvertrauen (Netzwerk-Rückhalt). Mathematisch wird dies über eine Wahrscheinlichkeits-Union berechnet.

### Hop-Limit
Die Distanz (Anzahl der Weitergaben), die eine Information im Netzwerk wandern darf. Wird das Limit erreicht, wird der Eintrag beim nächsten Gossip via SD-JWT herausgelöscht.

---

## 4. Netzwerk & Prozesse

### Vertrauens-Propagation (Gossip)
Das Verfahren zur dezentralen Verbreitung der Vertrauenslisten. Wenn Nutzer A neue oder aktualisierte Vertrauenslisten besitzt, "pusht" er diese aktiv an seine direkten Kontakte weiter, ohne dass diese explizit danach fragen müssen.

### Delta-Sync
Der hoch-effiziente Abgleich zwischen zwei Clients. Dieser Vorgang agiert in enger Zusammenarbeit mit dem **Versand-Logbuch**: Um bei asynchronen Kanälen (Push) maximale Effizienz zu erzielen, muss der Sender nicht zwingend erst beim Empfänger anfragen, was diesem fehlt. Der Sender prüft stattdessen rein lokal in seinem Logbuch, welche Versionen er dem Empfänger in der Vergangenheit bereits geschickt hat, und sendet asynchron **strikt nur das neu berechnete Delta**. Das minimiert redundante Datenübertragungen drastisch. (Kann zukünftig durch noch effizientere P2P-Protokolle ergänzt werden).

### Versand-Logbuch (Sent-Log)
Das "Gedächtnis" des Handys: Der Client merkt sich, an welchen Kontakt er welche Version einer Vertrauensliste bereits geschickt hat, um unnötiges, doppeltes Senden beim nächsten Abgleich (Vertrauens-Propagation) von Vornherein zu blockieren.
