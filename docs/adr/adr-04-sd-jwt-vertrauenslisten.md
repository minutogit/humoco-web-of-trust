# ADR 0004: Vertrauenslisten als Selective Disclosure JWT (SD-JWT)

**Status:** Akzeptiert  
**Aktualisiert:** 30. Oktober 2026 (Drahtformat-Spezifikation, 128-Bit-Salts, Decoy-Padding, Transport-Entkopplung)  
**Kontext:** Dezentrales Web of Trust (WoT) basierend auf `did:key`  

---

## 1. Problemstellung

Im dezentralen Web of Trust (WoT) von HuMoCo müssen Nutzer ihre lokalen Vertrauenseinstufungen (wer vertraut wem mit welcher Intensität) mit Kontakten und über mehrere Stationen (Hops) im Netzwerk austauschen. Hierbei treten fundamentale Spannungsfelder zwischen **Privatsphäre**, **Kryptographischer Integrität** und **Offline-Fähigkeit** auf:

1. **Selektive Sichtbarkeit (Distanz-Redaktion):** Nutzer möchten selbst bestimmen, wie weit ihre Kontakte im Netzwerk sichtbar sind (z. B. ein enger Partner 3 Hops weit, ein flüchtiger Bekannter nur 1 Hop weit). Wenn eine Liste von Zwischenknoten weitergeleitet wird und abgelaufene Hops entfernt werden müssen, darf die digitale Signatur des ursprünglichen Ausstellers dabei nicht brechen.
2. **Offline-Widerstandsfähigkeit & Seed-Wiederherstellung:** Nutzer können ihr Smartphone verlieren und ihr Wallet rein aus einer 12-Wörter-Seedphrase wiederherstellen. Eine neue Vertrauensliste muss im asynchronen P2P-Netzwerk verlässlich ältere Versionen ablösen, ohne dass globale Zeit-Server oder zentrale Registrierungsstellen existieren.
3. **Schutz vor De-Anonymisierung (GPU-Brute-Force):** Da DIDs in regionalen Gemeinschaften oft bekannt sind und Vertrauensstufen (`0..3`) sowie Hop-Limits nur winzige Wertebereiche umfassen, droht bei unzureichendem Zufall die vollständige De-Anonymisierung („Entschwärzung“) redigierter Kontakte.
4. **Metadaten-Privatsphäre & Größen-Tracking:** Die schiere Anzahl von Vertrauenseinträgen oder das Entfernen einzelner Kontakte darf nicht anhand der Token-Länge für Dritte nachvollziehbar sein.
5. **Transport-Agnostizismus:** Das Vertrauenslisten-Format muss über extrem bandbreitenarme Kanäle (QR-Code-Scans, BLE, NFC) ebenso übertragbar sein wie als verschlüsseltes Paket im `SecureContainer` von `human-money-core` oder als Huckepack-Payload in regulären Zahlungen.

---

## 2. Getroffene Entscheidung

Wir spezifizieren die dezentrale Vertrauensliste (*Trust List*) als kompaktes, selbsttragendes **Selective Disclosure JWT (SD-JWT)** gemäß IETF-Prinzipien, optimiert für ressourcenarme Offline-Systeme.

Das Crate `humoco-wot` erzeugt und validiert eigenständige SD-JWT-Strings der kanonischen Form:
```text
<jws_protected_header>.<jws_payload>.<signature>~<disclosure_1>~<disclosure_2>~...~
```

### A. JWS Protected Header

Der Header legt den Algorithmus und den spezifischen Medientyp fest:
```json
{
  "alg": "EdDSA",
  "typ": "wot-trustlist+sd-jwt"
}
```
*   `alg`: Zwingend `EdDSA` (Ed25519 nach RFC 8037).
*   `typ`: `wot-trustlist+sd-jwt` stellt die eindeutige semantische Zuordnung sicher und verhindert Cross-Protocol-Verwechslungen.

### B. JWS Payload (Kanonische Claims)

Die signierte Payload enthält ausschließlich aggregierte Metadaten und die Hash-Digests der selektiv offenlegbaren Vertrauenseinträge:

```json
{
  "iss": "did:key:z6MkuV8...kanonisch",
  "v": 1793376000,
  "iat": 1793376000,
  "max_hops": 4,
  "_sd": [
    "3f79bb7b435b05321651da",
    "8a2b3c4d5e6f708192a3b4",
    "b94d27b9934d3e08a52e52",
    "d1e2f3a4b5c6d7e8f90123"
  ]
}
```

#### Spezifikation der Felder:
*   `iss` (Issuer): Der kanonische `did:key:z6Mk...` des Ausstellers. Eventuelle Adress-Präfixe aus `human-money-core` (wie z. B. `name:chk@did:key:z6Mk...`) werden vor der Einbettung und Signatur zwingend auf die reine, standardisierte `did:key`-Repräsentation normalisiert.
*   `v` (Version): Monotone Versionsnummer als 64-Bit-Ganzzahl (`u64`), deterministisch berechnet als:
    $$\mathbf{v} = \max(\text{last\_v} + 1, \text{current\_unix\_seconds})$$
    *   **Begründung:** Verliert ein Nutzer sein Mobilgerät und stellt seine Identität rein aus der 12-Wörter-Seedphrase wieder her, startet seine lokale Datenbank bei `last_v = 0`. Durch den Fallback auf den aktuellen Unix-Zeitstempel in Sekunden ist garantiert, dass die neu ausgestellte Version sofort echt größer ist als jede vor dem Verlust im P2P-Netzwerk zirkulierende Liste. Dies verhindert das fatale Einfrieren des Web of Trust („Replay-Lockout“), ganz ohne Blockchain, Konsensrunden oder zentrale Server.
*   `iat` (Issued At): Erstellungszeitpunkt in Unix-Sekunden (`u64`).
*   **Kein Pflicht-`exp`-Feld:** Im Drahtformat existiert **kein** verpflichtendes Ablaufdatum (`exp`). Vertrauensbeziehungen verfallen nicht schlagartig nach einem starren Kalenderdatum. Neuere Versionen `v` ersetzen ältere Versionen atomar. Ob und wie stark eine empfangene Liste im Zeitverlauf an Gewicht verliert (Altersdämpfung / Freshness-Decay), entscheidet die empfangende Wallet autonom anhand ihrer lokalen Auswertungs-Policy.
*   `max_hops`: Globales Weitergabelimit dieser Vertrauensliste als `u8` (Bereich $1..8$, typischer Standard: $3..4$).
*   `_sd`: Lexikographisch sortiertes Array aus **22-stelligen Base64URL-Strings** (ohne `=` Padding). Es enthält die 128-Bit-Digests aller echten Kontakt-Disclosures **sowie zusätzliche Decoy-Digests** zur Längenverschleierung.

---

### C. Exaktes Disclosure-Format & Krypto-Sicherheit

Jeder einzelne Kontakt wird als eigenständige, selektiv offenlegbare Disclosure kodiert. Eine Disclosure ist ein kompaktes, unformatiertes JSON-Array (ohne Whitespace):

```json
["<salt_b64url>","<target_did>",<level>,<contact_max_hops>]
```

#### 1. Die Felder der Disclosure:
*   `salt_b64url`: **Zwingend 128 Bit (16 Bytes) kryptographischer Zufall (`OsRng`)**, kodiert als exakt 22 Base64URL-Zeichen (ohne Padding).
    *   > [!IMPORTANT]
        > **Warum zwingend 128-Bit-Salts?**
        > In regionalen Wirtschaftskreisen ist die Menge potenzieller Handelspartner (`target_did`) überschaubar. Die Parameter `level` ($0..3$) und `contact_max_hops` ($0..8$) umfassen zusammen nur 36 mögliche Wertekombinationen. Wäre das Salt kurz (z. B. 32 oder 64 Bit), könnte ein Zwischenknoten mit Standard-Consumer-GPUs mittels Rainbow-Tables oder Wörterbuchangriffen redigierte Kontakte in Millisekunden „entschwärzen“. 128 Bit kryptographischer Entropie bieten vollständigen mathematischen Schutz vor Brute-Force- und Pre-Computation-Angriffen.
*   `target_did`: Der kanonische `did:key:z6Mk...` des Kontakts. **Streng verboten:** Klartextnamen, Adressbuch-Aliase, Notizen oder Personenbezeichner. Die Privatsphäre dritter Personen wird gewahrt.
*   `level`: Die zugeordnete Vertrauensstufe als `u8` ($0..3$, siehe [Glossar](./0000-glossar.md) & [ADR 0003](./adr-03-ui-design-vertrauen-haftung.md)):
    *   `0`: Existenzbestätigung (F2F menschliche Existenz, 0 % Haftung, keine Transit-Brücke für Pfade oder Listen-Import).
    *   `1`: Bekannter (30 % Vertrauensfaktor).
    *   `2`: Guter Kontakt (60 % Vertrauensfaktor).
    *   `3`: Enger Vertrauter (85 % Vertrauensfaktor).
*   `contact_max_hops`: Das individuelle Weitergabelimit für diesen spezifischen Kontakt als `u8` ($0..8$).

#### 2. Kanonische Digest-Berechnung:
Die Berechnung des 128-Bit-Digests für das `_sd`-Array folgt einem deterministischen Verfahren:
1. Das JSON-Array wird als unformatierter UTF-8-String serialisiert:
   $$\text{raw\_json} = \text{UTF8}(\texttt{["<salt>","<target\_did>",<level>,<contact\_max\_hops>]})$$
2. Der String wird Base64URL (nopad) kodiert:
   $$\text{disc\_b64} = \text{Base64URL\_nopad}(\text{raw\_json})$$
3. Es wird der SHA-256-Hash gebildet:
   $$H = \text{SHA-256}(\text{ASCII}(\text{disc\_b64}))$$
4. Der Hash wird auf die ersten 16 Bytes (128 Bit) trunkiert:
   $$\text{digest}_{128} = H[0..16]$$
5. Der Digest wird als 22-stelliger Base64URL-String (nopad) in das `_sd`-Array eingefügt:
   $$\text{sd\_entry} = \text{Base64URL\_nopad}(\text{digest}_{128})$$

---

### D. Frische Salts & Decoy-Padding bei Versions-Updates

Um Tracking über Zeiträume hinweg und differenzielle Graphanalysen durch Relay-Knoten zu verhindern, gelten zwei strikte Sicherheitsregeln:

1. **Vollständige Salt-Neuverteilung (Ephemeral Salting):**
   Bei jeder Aktualisierung der Vertrauensliste (Inkrement von `v`) **müssen alle Salts sämtlicher Kontakte mit `OsRng` neu gewürfelt werden**. Dadurch ändert sich jeder Disclosure-String und jeder resultierende 128-Bit-Digest im `_sd`-Array vollständig. Ein externer Beobachter kann zwei aufeinanderfolgende Versionen derselben Liste nicht vergleichen, um festzustellen, welche Kontakte unverändert geblieben sind.
2. **Decoy-Padding (Verschleierung der Kontaktanzahl):**
   Das `_sd`-Array wird mit kryptographisch zufälligen 128-Bit-Digests („Decoys“ / Nebelkerzen) aufgefüllt, für die absichtlich **keine** Disclosure existiert.
   *   Das Array wird auf standardisierte Blockgrößen aufgerundet (z. B. nächste Zweierpotenz oder Vielfache von 8: $8, 16, 24, 32, 48, 64, 96, 128, \dots$).
   *   **Effekt:** Ein Angreifer kann weder die exakte Anzahl realer Kontakte eines Nutzers ablesen noch erkennen, ob beim Update auf eine neue Version Kontakte hinzugefügt oder gelöscht wurden. Für Weiterleiter sind Decoys ununterscheidbar von redigierten Kontakten mit abgelaufenem Hop-Limit.

---

### E. Transport-Agnostizismus & Entkopplung

Das Crate `humoco-wot` ist eine reine, zustandsfähige Rust-Bibliothek ohne Bindung an ein spezifisches Netzwerkprotokoll. 

*   **Autarkes Format:** Ein serialisiertes SD-JWT ist eine in sich geschlossene Textsequenz (`<Header>.<Payload>.<Sig>~<Disc1>~<Disc2>~...~`).
*   **Transporter:**
    *   **In Transaktionen:** Kann direkt als Byte-Payload in den verschlüsselten `SecureContainer` von `human-money-core` (RFC 7516 JWE General Serialization, DIDComm v2 kompatibel) eingebettet werden (Piggybacking).
    *   **Im Nahfeld:** Kann in QR-Codes (unter Ausnutzung der 128-Bit-Kompaktheit), über BLE-GATT-Charakteristiken oder NFC übertragen werden.
    *   **Im Ruhezustand:** Wird im verschlüsselten App-Profil der `human-money-app` persistiert.
*   **Ausschluss von W3C-VC / JSON-LD:** Die Verwendung von W3C Verifiable Credentials (VCs) mit JSON-LD Contexts bleibt verboten. Der damit verbundene Byte-Overhead (mehrere Kilobyte schema-Metadaten) würde QR-Codes und Offline-Gossip lahmlegen.

---

## 3. Rationale & Sicherheitsbewertung

*   **Mathematische Kollisionssicherheit bei 128 Bit:** Ein 128-Bit-Digest bietet einen Zustandsraum von $2^{128} \approx 3{,}4 \times 10^{38}$. Selbst bei $10^9$ Knotenpunkten und $10^{12}$ gleichzeitigen Kontakten im Gesamtsystem liegt die Wahrscheinlichkeit einer zufälligen Kollision unter $10^{-15}$. Die Ersparnis von 16 Bytes pro Kontakt halbiert den Hash-Overhead im Vergleich zu ungeschnittenen 256-Bit-Hashes.
*   **Unbrechbare Signaturen bei Hop-Redaktion:** Wenn Bob die Liste von Alice an Carol weitergibt und Carol weiter entfernt ist als Alices Freigabe für einen Kontakt, lässt Bob einfach die zugehörige Disclosure-Zeichenkette weg. Da der JWS-Körper (`iss`, `v`, `iat`, `max_hops`, `_sd`) unverändert bleibt, prüft Carol die Ed25519-Signatur von Alice weiterhin fehlerfrei gegen Alices `did:key`.

---

## 4. Konsequenzen

### Positiv
*   **Maximale Privatsphäre:** Echte Anonymität für entfernte Kontakte bei 100 % mathematischer Verifizierbarkeit verbleibender Pfade.
*   **Kollisionsfreier Recovery-Mechanismus:** $v = \max(\text{last\_v} + 1, \text{current\_unix\_seconds})$ löst das Seedphrase-Wiederherstellungsproblem dezentral und elegant.
*   **Keine Netzwerk-Blockaden:** Schutz vor GPU-Brute-Force durch 128-Bit-Salts und Schutz vor Differenz-Tracking durch Decoys.

### Zu beachten bei der Implementierung
*   **Parsing-Geschwindigkeit:** Validatoren müssen Base64URL-Strings und SHA-256-Digests effizient verarbeiten. In Rust ist hierfür `sha2::Sha256` in Kombination mit `base64ct` (Constant Time) oder `subtle` optimal.
*   **Decoys verwerfen:** Empfänger dürfen Decoy-Digests nicht als Fehler werten; unaufgelöste Hashes sind der Normalfall für redigierte Einträge.
