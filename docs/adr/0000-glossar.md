# WoT Glossar: Begriffe und Definitionen

**Status:** Lebendiges Dokument / Glossar  
**Aktualisiert:** 30. Oktober 2026  
**Kontext:** Dezentrales Web of Trust (WoT)  

Dieses Dokument definiert die wesentlichen Begriffe, die in der Architektur des Humoco Web of Trust (WoT) verwendet werden, um eine klare und einheitliche Terminologie sicherzustellen.

## 1. Identitäten

### did:key
Der dezentrale Identifier einer Person oder Entität. Er basiert direkt auf dem öffentlichen kryptographischen Schlüssel (Ed25519). Es gibt keine zentrale Registry; wer den privaten Schlüssel besitzt, kontrolliert die Identität.

---

## 2. Datenstrukturen

### Vertrauensliste (Trust List)
Die zentrale Datenstruktur, in der ein Nutzer (Aussteller / Issuer) all seine Kontakte und deren Vertrauensstufen sammelt und diese Liste **genau einmal digital signiert**. Sie besitzt im Drahtformat **kein** hartes `exp`-Ablaufdatum, sondern zwingend ein Pflicht-Erstelldatum `iat` (Issued At, Unix-Sekunden) und eine monotone Versionsnummer `v`. Die auswertende Wallet entscheidet lokal über Zeit-Dämpfung ($d_{\text{age}}(\Delta t)$) oder Altershinweise. Diese signierte Liste wird als Ganzes über das Netzwerk (via Vertrauens-Propagation) verteilt, damit andere den echten Vertrauensgraphen berechnen können (siehe [ADR 0004](./adr-04-sd-jwt-vertrauenslisten.md)).

### SD-JWT (Selective Disclosure JWT)
Das spezielle kryptographische Format nach IETF-Standard, in dem die *Vertrauensliste* gespeichert und signiert wird. Das Besondere: Wenn Knotenpunkte (Peers) diese Liste weiterleiten, können sie gezielt einzelne Einträge (Schlüssel) daraus löschen bzw. verbergen (redigieren), **ohne dass die ursprüngliche Signatur des Ausstellers bricht**. Zur Gewährleistung maximaler Dateneffizienz bei NFC-, BLE- und QR-Transfers werden Hashes innerhalb der Struktur auf 128 Bit (16 Bytes) gekürzt. Das sichert die Privatsphäre nach Ablauf des Hop-Limits (siehe [ADR 0004](./adr-04-sd-jwt-vertrauenslisten.md) und [ADR 0005](./adr-05-reziprokes-routing-sd-jwt.md)).

### Lokales Vertrauensregister (Trust Register)
Der lokale Speicher auf dem Endgerät (Smartphone) des Nutzers. Hier werden die eigene Vertrauensliste sowie alle empfangenen, fremden Listen für die Offline-Pfadberechnung verwaltet (Dual-Storage-Architektur aus `raw_list_store` und `EgoGraphCache`, siehe [ADR 0007](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

### Gutschein-Vertrauenswert
Das aus dem lokalen WoT-Ego-Graphen berechnete Gesamtvertrauen in die Einlösbarkeit eines Layer-1-Gutscheins (Human Money Voucher), abgeleitet aus dem Vertrauen in dessen Herausgeber (`creator`) und eventuelle Bürgen (`guarantors`, siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) und [ADR 0007](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

### Bürge (Guarantor) als Vertrauensbrücke
Gültige Bürgen-Signaturen (`role == "guarantor"`) auf einem L1-Gutschein fügen für die lokale Vertrauensberechnung eine temporäre gerichtete Kante `Bürge -> Herausgeber` (Standardgewicht $\gamma = 0.85$) in den Ego-Graphen ein. Dadurch stärkt ein vertrauter Bürge den Gutschein-Rückhalt sofort offline, selbst wenn dessen eigene WoT-Liste noch nicht synchronisiert wurde (siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).

### Betrugs-Veto (KnownOffender)
Veto-Mechanismus im `TrustProvider`: Ist der Herausgeber eines Gutscheins im lokalen Konfliktspeicher als überführter Betrüger (z. B. nachgewiesener Double-Spend via SST V4) registriert, wird der Gutschein-Vertrauenswert sofort und unwiderruflich auf 0 % gesetzt (siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) und [ADR 0007](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

### Dienstleister-Prüfsiegel (Provider Filter)
Ein von Organisationen, Verbänden oder Kammern signiertes Dokument (`typ: "wot-provider-filter+v1"`), das tausende Mitglieder und deren Zertifizierungsstufe kompakt via Binary Fuse Filter bündelt, ohne Megabytes an Einzeldaten übertragen zu müssen (siehe [ADR 0008](./adr-08-dienstleister-pruefsiegel-binary-fuse.md)).

### 64-Bit Binary Fuse Filter (BinaryFuse64)
Hocheffiziente, statische Filter-Datenstruktur nach Graf & Lemire mit 3-Wege-XOR-Peeling und 64-Bit-Fingerabdrücken ($\epsilon \approx 5{,}4 \times 10^{-20}$), die mathematisch jedes Key-Grinding verhindert und $O(1)$-Mitgliedschaftsabfragen ermöglicht (siehe [ADR 0008](./adr-08-dienstleister-pruefsiegel-binary-fuse.md)).

### Schlüsselnachfolge-Attestierung (`KeySuccessorAttestation`)
Dual signierte (`old_key_signature` + `new_key_signature` unter `HUMOCO_KEY_SUCCESSOR_V1`) oder im Verlustfall über `recovery_pub`/Bürgen autorisierte Nachfolge-Urkunde `old_did -> new_did`. Verhindert *Vampire Attacks* (Kaltstart ohne Attestierung bei 0 % Vertrauen) und steuert die `CardStore`-Auflösung über maximal 8 Hops (siehe [ADR 09](./adr-09-schluesselnachfolge-key-successor-attestation.md)).

### Server-Sanktionsliste (`ServerOffenderList`)
Kryptographisches Sperrregister für kompromittierte `humoco-sync`-Lock-Server auf Basis eines verifizierbaren `EquivocationProof` (zwei widersprüchliche `FirstWrite`-Quittungen auf demselben Slot), das mit optionaler `HUMOCO-LOCK-DELEGATE-V1`-Delegation sowohl `lock_pub` als auch `admin_pub` dauerhaft aus `trusted_servers` entwertet (siehe [ADR 10](./adr-10-server-sanktionsliste-server-offender-list.md)).

---

## 3. Metriken & Kalkulation

### Vertrauensstufen (Trust Levels)
Das System nutzt ein diskretes Stufenmodell (`0..3`) zur Qualifizierung von Verbindungen (siehe [ADR 0003](./adr-03-ui-design-vertrauen-haftung.md)):
- **Stufe 0 (Mensch-Existenz / Anti-Bot):** Bestätigung für direkte Nachbarn, dass hinter einem `did:key` ein echter Mensch steht ($\gamma = 0.0$, keine finanzielle Haftung). **Wichtig (Keine Transit-Brücke):** Da $0.0 \times \text{alles} = 0.0$ gilt, ist Stufe 0 keine Transit-Brücke. Über reine Stufe-0-Kanten werden weder Pfade zu Dritten berechnet, noch nachgelagerte Vertrauenslisten gesammelt, importiert oder weitergeleitet (verhindert nutzlosen Daten-Ballast).
- **Stufe 1 (Bekannter):** Vertrauensfaktor 30 % ($\gamma = 0.30$, Richtwert 0,5 h Haftung).
- **Stufe 2 (Guter Kontakt):** Vertrauensfaktor 60 % ($\gamma = 0.60$, Richtwert 1,0 h Haftung).
- **Stufe 3 (Enger Vertrauter):** Vertrauensfaktor 85 % ($\gamma = 0.85$, Richtwert 4,0 h Haftung).

Für Pfadberechnung und Graph-Import zählen ausschließlich Kanten mit $\text{Stufe} \ge 1$.

### Vertrauensfaktor (Trust Factor / Gamma)
Ein prozentualer Wert ($\gamma \in \{0.30, 0.60, 0.85\}$), der beschreibt, wie verlässlich eine Kante ist. Bei der Pfadberechnung führt dieser Faktor zu einer multiplikativen Dämpfung des Vertrauens über jeden Verbindungsschritt (Hop, siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).

### Netzwerk-Vertrauen (Netzwerk-Rückhalt)
Die Stärke der Verbindung zu einer fremden Person, berechnet aus dem persönlichen Ego-Graphen. Während ein einzelner Pfad durch Dämpfung unsicher sein kann, stärken mehrere echt unabhängige Pfade (über verschiedene Erstkontakte) das Vertrauen signifikant ($1 - \prod (1 - P_k)$). Laufen Pfade jedoch über gemeinsame Zwischenknoten, verhindert der Nadelöhr-Schutz eine künstliche Aufblähung (siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).

### Nadelöhr-Schutz (Shared-Edge Factoring)
Mathematisches Verfahren (Shannon-Faktorisierung / Serien-Parallel-Reduktion) zur exakten Pfadberechnung bei überlappenden Kanten. Laufen mehrere Pfade durch dieselbe Kante (z. B. `Ich --30%--> Bob`), wird diese gemeinsame Kante mathematisch ausgeklammert: $\Pr(\text{Ich} \leadsto X) = \gamma(\text{Ich}, \text{Bob}) \cdot \Pr(\text{Bob} \leadsto X)$. Auch wenn Bob zu $X$ über 20 Pfade 99 % Vertrauen aufbaut, können bei mir über Bob allein niemals mehr als 30 % ankommen ($0.30 \times 0.99 = 29{,}7\,\%$). Macht Sybil-Cluster hinter Einzelkontakten wirkungslos (siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).

### Hop-Limit
Die Distanz (Anzahl der Weitergaben), die eine Information im Netzwerk wandern darf. Wird das Limit erreicht, wird der Eintrag beim nächsten Gossip via SD-JWT herausgelöscht bzw. redigiert (siehe [ADR 0004](./adr-04-sd-jwt-vertrauenslisten.md) und [ADR 0005](./adr-05-reziprokes-routing-sd-jwt.md)).

### Lokale Alters-Gewichtung (Age Damping)
Lokal in der Wallet angewendeter Dämpfungsfaktor $d_{\text{age}}(\Delta t) \in (0, 1]$, mit dem ältere Vertrauenslisten anhand des `iat`-Zeitstempels gewichtet werden können, ohne ein fixes Verfallsdatum im Drahtformat zu erzwingen (siehe [ADR 0001](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md) und [ADR 0004](./adr-04-sd-jwt-vertrauenslisten.md)).

---

## 4. Netzwerk & Prozesse

### Vertrauens-Propagation (Gossip)
Das Verfahren zur dezentralen Verbreitung der Vertrauenslisten. Wenn Nutzer A neue oder aktualisierte Vertrauenslisten besitzt, "pusht" er diese aktiv an seine direkten Kontakte weiter, ohne dass diese explizit danach fragen müssen (siehe [ADR 0006](./adr-06-asynchrones-gossip-protokoll.md)).

### Delta-Sync
Der hoch-effiziente Abgleich zwischen zwei Clients. Dieser Vorgang agiert in enger Zusammenarbeit mit dem **Versand-Logbuch**: Um bei asynchronen Kanälen (Push) maximale Effizienz zu erzielen, muss der Sender nicht zwingend erst beim Empfänger anfragen, was diesem fehlt. Der Sender prüft stattdessen rein lokal in seinem Logbuch, welche Versionen er dem Empfänger in der Vergangenheit bereits geschickt hat, und sendet asynchron **strikt nur das neu berechnete Delta**. Das minimiert redundante Datenübertragungen drastisch (siehe [ADR 0006](./adr-06-asynchrones-gossip-protokoll.md)).

### Versand-Logbuch (Sent-Log)
Das "Gedächtnis" des Handys: Der Client merkt sich, an welchen Kontakt er welche Version einer Vertrauensliste bereits geschickt hat, um unnötiges, doppeltes Senden beim nächsten Abgleich (Vertrauens-Propagation) von Vornherein zu blockieren (siehe [ADR 0006](./adr-06-asynchrones-gossip-protokoll.md) und [ADR 0007](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

### Transport-Entkopplung & Zero-Trust Transport
Das Datenformat des `humoco-wot` ist 100 % transportunabhängig. Es funktioniert vollständig offline P2P (QR, BLE, NFC, Dateitransfer, JWE-Transaktions-Huckepack) und erlaubt gleichzeitig den Transport über beliebige Online-Infrastruktur (z. B. blinde Relays oder optionale Community-/Regional-Server zur Pfadsuche). Die Wallet vertraut niemals blind dem Transportweg oder einem Server, sondern verifiziert stets ausschließlich die kryptographischen Ed25519-Nutzersignaturen der SD-JWTs (Zero-Trust, siehe [ADR 0000](./adr-00-wot-grundprinzip.md) und [ADR 0007](./adr-07-datenstruktur-speicher-und-schnittstellen.md)).

### Blinde Relays & Community-Server (Optionale Helfer-Infrastruktur)
Optionale Server-Infrastruktur zur Zwischenspeicherung verschlüsselter Nachrichten oder zur Indizierung signierter SD-JWTs zur Beschleunigung von asynchronem Gossip oder Pfadsuchen. Sie besitzen keinerlei private Schlüssel, können Inhalte weder manipulieren noch unbemerkt fälschen und sind für den Kernbetrieb des Protokolls niemals zwingend erforderlich (siehe [ADR 0000](./adr-00-wot-grundprinzip.md) und [ADR 0006](./adr-06-asynchrones-gossip-protokoll.md)).
