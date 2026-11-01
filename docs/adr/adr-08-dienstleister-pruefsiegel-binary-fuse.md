# ADR 08: Dienstleister-Prüfsiegel & Mitgliedsfilter via 64-Bit Binary Fuse Filter

**Status:** Akzeptiert / Spezifikation  
**Aktualisiert:** November 2026  
**Kontext:** Dezentrales Web of Trust (WoT) & L1-Gutschein-Bewertung  

---

## 1. Problemstellung & Motivation

Im HuMoCo-Ökosystem (*"Trust people, verify math"*) erfolgt die Vertrauensbewertung von Layer-1-Gutscheinen primär subjektiv über den lokalen Ego-Graphen aus persönlichen Kontakten und Bürgschaften. In der Praxis existieren jedoch reale Institutionen und Zusammenschlüsse, die hunderte oder tausende Teilnehmer zertifizieren:

* **Bio- und Erzeugerverbände** (z. B. Demeter, Bioland, regionale Solidarische Landwirtschaften).
* **Handwerkskammern und Innungen** (z. B. regionale Meisterbetriebe).
* **Genossenschaften und Tauschringe** (z. B. Minuto-Initiativen, FreeTaler-Kreise).

Würde eine solche Institution ihre 10.000 Mitglieder als konventionelle SD-JWT-Vertrauensliste veröffentlichen, entstünde ein Datenvolumen von mehreren Megabytes. Auf ressourcenbeschränkten Offline-Übertragungswegen (QR-Codes, BLE, NFC) sowie in mobilen Endgeräten würde dies die Speicherkapazitäten und Übertragungszeiten sprengen.

Zusätzlich erfordert der Zero-Trust- und Offline-Ansatz von HuMoCo:
1. **Kein Key-Grinding:** Angreifer dürfen nicht in der Lage sein, durch Generieren vieler Schlüsselpaare absichtlich Falsch-Positiv-Treffer in einem Verbandsfilter zu erzwingen.
2. **Kompaktheit & Geschwindigkeit:** Schnelle Überprüfbarkeit ($O(1)$) bei minimaler Dateigröße.
3. **Nadelöhr-Schutz (Shared-Edge Factoring):** Ein Verbandssiegel darf niemals das Vertrauen des Nutzers in die Organisation selbst übersteigen, selbst wenn Herausgeber und Bürgen alle im selben Filter zertifiziert sind.

---

## 2. Architektur & Drahtformat: `wot-provider-filter+v1`

Das Prüfsiegel wird als eigenständiges, signiertes Dokument modelliert. Zur Gewährleistung vollständiger Formatierungs- und Whitespace-Invarianz über unterschiedliche Plattformen (Rust, TypeScript, Mobile) hinweg verwendet HuMoCo ein geschütztes JWS-inspiriertes Hüllenformat:

```json
{
  "typ": "wot-provider-filter+v1",
  "payload_b64": "<Base64URL(no pad) des kanonischen ProviderFilterPayload-JSON>",
  "signature_b64": "<Base64URL(no pad) der 64-Byte Ed25519-Signatur über payload_b64.as_bytes()>"
}
```

### 2.1 Payload-Struktur (`ProviderFilterPayload`)

```rust
pub const PROVIDER_FILTER_TYP: &str = "wot-provider-filter+v1";

pub struct ProviderFilterPayload {
    pub typ: String,
    pub iss: Did,
    pub name: String,
    pub v: u64,
    pub iat: u64,
    pub source_url: Option<String>,
    pub member_count: u32,
    /// Vertrauensstufe (1..=3) -> Kodierter 64-Bit Binary Fuse Filter
    pub level_filters: BTreeMap<u8, EncodedBinaryFuse64>,
}
```

* `iss`: Der kryptographische `did:key:z...` des Ausstellers (Verband, Organisation).
* `name`: Klarschriftname der Organisation (z. B. `"Bio-Verband Deutschland"`).
* `v`: Monotone Versionsnummer (Anti-Rollback-Schutz).
* `iat`: Ausstellungszeitpunkt in Unix-Sekunden (für Altersdämpfung).
* `member_count`: Anzahl der enthaltenen zertifizierten Identitäten.
* `level_filters`: Getrennte Filter für die jeweiligen HuMoCo-Vertrauensstufen (1 = 30 %, 2 = 60 %, 3 = 85 %).

---

## 3. 64-Bit Binary Fuse Filter (`BinaryFuse64`)

Um extreme Falsch-Positiv-Resistenz mit maximaler Kompaktheit zu vereinen, implementiert `humoco-wot` einen reinen, sicheren Rust-Filter nach dem 3-Wege-XOR-Peeling-Algorithmus von **Graf & Lemire (2022)**.

### 3.1 Mathematische Anti-Key-Grinding-Garantie

Klassische Bloom- oder Xor8-Filter haben eine Falsch-Positiv-Rate von $\approx 1\,\%$ bis $0{,}4\,\%$. Bei $10^6$ zufällig generierten Schlüsseln fände ein Angreifer tausende gefälschte Treffer.

`BinaryFuse64` verwendet **64-Bit-Fingerabdrücke**:
$$\epsilon = \frac{1}{2^{64}} \approx 5{,}42 \times 10^{-20}$$

Selbst mit einem weltweiten Cluster, der Milliarden Schlüssel pro Sekunde berechnet, ist es mathematisch unmöglich, eine Kollision zu erzwingen. Die Mitgliedschaft ist kryptographisch fälschungssicher.

### 3.2 Domänen-getrenntes Key-Hashing

Die Ableitung des 64-Bit-Schlüssels erfolgt mit vollständiger Domänentrennung über SHA-256:

$$\text{key} = \text{SHA-256}\Big(\text{"HUMOCO\_PROVIDER\_FILTER\_V1\textbackslash 0"} \,\|\, \text{iss} \,\|\, v_{\text{be64}} \,\|\, [\text{level}] \,\|\, \text{target\_did}\Big)[0..8]$$

Der Fingerabdruck wird mit dem 64-Bit-Mixer MurmurHash3 finalisiert:
$$\text{fp} = \text{mix64}(\text{key})$$
Ist $\text{fp} == 0$, wird $\text{fp} = 1$ gesetzt. Dadurch können leere (mit 0 initialisierte) Slots niemals zufällig matchen.

### 3.3 Peeling-Konstruktion & Segmentierung

Der Filter arbeitet mit 3 disjunkten Hash-Positionen $h_0, h_1, h_2$ über Segmente der Länge $L$:
* Kleine Sets ($1 \le n \le 64$): Feste Segmentlänge $L = 32$, Kapazität $4 \cdot L = 128$ Slots.
* Große Sets ($n > 64$): Dynamische Segmentlänge $L = 2^{\lfloor \log_{3.33}(n) + 2.25 \rfloor}$ mit Größenfaktor $s_f = \max(1.125, 0.875 + 0.25 \frac{\ln(10^6)}{\ln(n)})$.
* Bei Fehlschlägen im Peeling-Zyklus wird der Seed deterministisch bis zu 100-mal inkrementiert.

### 3.4 Wire-Serialisierung (`EncodedBinaryFuse64`)

Die Fingerprints werden als kompakte Little-Endian-Bytefolge Base64URL-kodiert:
```json
{
  "seed": 8245192837192,
  "segment_length": 32,
  "segment_length_mask": 31,
  "segment_count_length": 64,
  "fingerprints_b64": "A3k...9Fw"
}
```
Bei 1.000 Mitgliedern benötigt ein Filter lediglich ca. 9 Kilobyte.

---

## 4. Integration in den Ego-Graphen & Shannon Nadelöhr-Schutz

### 4.1 Subjektive Vertrauenszuordnung

Ein Prüfsiegel entfaltet nur dann Wirkung, wenn der lokale Nutzer der Organisation vertraut. Der Nutzer setzt lokal eine Vertrauensstufe für den `iss`:
$$\text{user\_level} = \max(\text{prov.local\_trust\_level}, \text{own\_contacts}[\text{iss}].\text{level})$$
Ist $\text{user\_level} == 0$, wird der Provider-Filter bei der Pfadberechnung vollständig ignoriert.

### 4.2 Kanten-Injektion bei der Gutschein-Bewertung

Wird ein L1-Gutschein evaluiert, prüft das `TrustRegister`:
1. Eine direkte Kante `0 -> Provider` mit Gewicht $\gamma(\text{user\_level})$ wird im Ego-Graphen etabliert.
2. Der Herausgeber (`creator`) wird gegen `prov.certified_level(creator)` geprüft. Bei Erfolg entsteht eine Kante `Provider -> Creator` mit Stufe $\text{cert\_level}$ und Erstelldatum `prov.payload.iat`.
3. Jeder Gutschein-Bürge (`guarantor`) wird gegen `prov.certified_level(guarantor)` geprüft. Bei Erfolg entsteht eine Kante `Provider -> Guarantor`. Zusammen mit der temporären Bürgschaftsbrücke `Guarantor -> Creator` (Gewicht 0.85) entsteht ein 3-Hop-Pfad `Nutzer -> Provider -> Bürge -> Herausgeber`.

### 4.3 Mathematische Nadelöhr-Garantie (Shared-Edge Factoring)

Dank der Shannon-Zerlegung im Pfad-Scorer gilt der Nadelöhr-Schutz uneingeschränkt:

$$\Pr(\text{Nutzer} \leadsto \text{Herausgeber via Provider}) \le \gamma(\text{user\_level})$$

Selbst wenn ein Verband den Herausgeber und 10 Bürgen auf Höchststufe 3 (85 %) zertifiziert, kann das Gesamtergebnis **niemals** das Vertrauen übersteigen, das der Nutzer dem Verband persönlich einräumt (z. B. Stufe 1 = 30 %). Sybil-Cluster oder Korruption innerhalb des Verbands sind auf die persönliche Vertrauensgrenze des Nutzers gedeckelt.

---

## 5. Altersdämpfung mit 1-jähriger Schonfrist (Grace Period)

Im Unterschied zu kurzlebigen Web-Zertifikaten arbeiten menschliche Vertrauensbeziehungen und Verbandsmitgliedschaften mit realistischen Zeiträumen.

### 5.1 Zeitkurve

Für alle Fremdlisten und Provider-Filter gilt:
$$\Delta t = \text{now} - \text{iat}$$

1. **Schonfrist ($\Delta t \le T_{\text{grace}} = 365 \text{ Tage}$):**
   Keine Dämpfung. Der Vertrauensfaktor beträgt 100 % der Grundstufe:
   $$p(t) = \gamma$$

2. **Halbwertszeit-Zerfall ($\Delta t > T_{\text{grace}}$, mit $T_{\text{half}} = 365 \text{ Tage}$):**
   $$p(t) = \gamma \cdot 2^{-\frac{\Delta t - T_{\text{grace}}}{T_{\text{half}}}}$$

* Nach 364 Tagen: 100 % der ursprünglichen Stärke.
* Nach 2 Jahren (1 Jahr Schonfrist + 1 Jahr Halbwertszeit): exakt 50 % der Stärke.
* Nach 3 Jahren: exakt 25 % der Stärke.

Eigene Direktkontakte (`edge.from == 0`) altern nicht automatisch, da sie vom Nutzer lokal verwaltet werden.

---

## 6. Globales Hop-Management & Bürgenbrücken-Sicherheit

Nutzer können ihr Weiterleitungs-Limit für eigene Kontakte über `set_own_list_max_hops(hops, now)` global anpassen:
* Aktualisiert alle direkten Kontakte mit `level >= 1` auf `desired_hops = hops`.
* Markiert die eigene Liste als dirty (`own_list_dirty = true`).
* **Sicherheits-Invariante:** `max_eval_depth` und `max_import_depth` werden **niemals verkleinert** (bleiben mindestens 5).

Dadurch ist garantiert, dass selbst bei einem restriktiven Weiterleitungslimit von `1 Hop` mehrgliedrige Bürgschafts- und Verbandsbrücken (2 bis 3 Hops) lokal fehlerfrei und ohne Unterbrechung ausgewertet werden.
