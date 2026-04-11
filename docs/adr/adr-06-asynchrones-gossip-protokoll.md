# ADR 6: Vertrauens-Propagation (Gossip) und lokales State-Tracking

**Status:** Vorgeschlagen / Entwurf
**Kontext:** Netzwerk / Datensynchronisation
**Datum:** 6. April 2026

## 1. Kontext und Problemstellung
Wenn Nutzer asynchron Vertrauenslisten ihrer Freunde (die SD-JWTs aus ADR 5) austauschen (z. B. asynchrone QR-Drops oder in Zukunft beim Vorbeigehen via Bluetooth/NFC), entsteht das Problem des "doppelten Sendens". Die Dateien können relativ groß werden.
Synchrone Abgleichverfahren (wie der bidirektionale Austausch von Filtern oder Epochen-Zählern) erfordern einen stabilen, zweiseitigen Handshake. Dies kann bei schnellen einseitigen Interaktionen (z.B. QR-Code scannen am Marktstand) oder asynchronen Nachrichten fehlschlagen.

## 2. Getroffene Entscheidung
Um auch asynchrone Kommunikationskanäle effizient zu nutzen, setzen wir ergänzend zu synchronen P2P-Delta-Syncs auf eine zustandsbehaftete (stateful) Vertrauens-Propagation (Gossip):

*   **Lokales Gedächtnis (Versand-Logbuch / Sent-Log):** Das Wallet merkt sich lokal für einen bestimmten Zeitraum (z.B. 180 Tage), welche Vertrauensliste (welchen Kontakt + Version) es bereits an welchen Empfänger gesendet hat.
*   **Datenstruktur des Caches:** Ein simples lokales Mapping: `Empfänger-DID -> [(Kontakt-DID_1, Version), (Kontakt-DID_2, Version)]`. Diese Struktur wird zwingend persistent gespeichert (z. B. via lokaler SQLite-Datenbank der App), um das "Gedächtnis" nach einem App-Neustart zu erhalten.
*   **Push-Logik:** Wenn Alice Daten an Bob vermitteln will (z.B. via verbindungsloser Schnittstelle), schaut Alice in ihren lokalen Cache. Sie filtert alle Einträge heraus, von denen sie weiß, dass sie Bob diese in der aktuellen Version bereits geschickt hat. Sie sendet (pusht) asynchron nur noch das berechnete Delta an Bob.
*   **Hop-Priorisierung:** Das zu sendende Delta wird nach "Nähe" im Vertrauensgraphen sortiert. Vertrauenslisten mit Hop = 1 (direkte Freunde) werden im Datenstrom zuerst gesendet. Listen mit höheren Hop-Werten kommen zuletzt. Bricht die asynchrone Verbindung (NFC, QR-Pagination) ab, wurden die wertvollsten Daten zuerst übertragen.
*   **Transaktions-Piggybacking (Integration mit Core):** Als zweiter Übertragungskanal nutzt das WoT-Gossip reguläre Transaktionen des `human-money-core`. Der Core agiert hier als reiner "Dumb Transporter" über Hook-Interfaces, die das berechnete WoT-Gossip-Delta als Byte-Payload anhängen. *(Konzeptionell: Es könnte bei Bedarf oder sogar immer die eigene direkte Vertrauensliste mit der eigenen Transaktion mitgeschickt werden – dies muss aber bezüglich des Datendurchsatzes noch im Detail durchdacht werden).*
*   **Klare architektonische Trennung:** Dieses Protokoll wird autark im WoT-Crate implementiert und teilt sich **nicht** das State-Tracking (`known_by_peers`) mit der Konflikt-Verteilung des Cores (Separation of Concerns).
*   **Zweigeteilte Datenspeicherung (Rohdaten vs. Graph):** Die Vertrauenslisten müssen permanent aufbewahrt werden: Einmal die vollständigen kryptographisch besiegelten "Rohdaten" (SD-JWTs), da genau diese mit ihren Signaturen weitergereicht werden. Gesondert davon benötigt die Laufzeit schnelle Speicherstrukturen (Graphen-Caches oder Vektordaten), aufweiche effiziente Graphenberechnungen stattfinden können, welche für Auswertungen und die besagte *Hop-Priorisierung* (Vertrauens-Propagation) erforderlich sind.

## 3. Konsequenzen

*   **Positiv:** Ermöglicht rein unidirektionale, effiziente Datenübertragungen (A sendet an B, ohne dass B mit einem Sync-Manifest antworten muss).
*   **Positiv:** Reduziert redundanten Traffic massiv, ohne komplexe kryptographische Mengenabgleiche on-the-fly durchführen zu müssen.
*   **Negativ/Risiko:** Bei Verlust der Datenbank oder erzwungener Speicherleerung durch den Benutzer verliert der Client das "Gedächtnis" und sendet beim nächsten Vorfall einmalig wieder ein großes, redundantes Delta.
*   **Architektonische Einordnung:** Die grundlegende Synchronisation erfolgt meist als direkter Handshake. Das hier beschriebene asynchrone Piggyback-Modell regelt ergänzend den ressourcenschonenden Transport über limitierte Kanäle.
