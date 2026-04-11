# 01 — WoT Data Structures & Privacy: Eine Tiefenanalyse

> **Projekt:** `human_money_core`
> **Autor:** Lead System Architect
> **Stand:** 2026-04-04
> **Status:** Forschungsdokument / Architektur-Entwurf

---

## 1. Problemstellung: Das Datentechnische Trilemma

Jede Datenstruktur, die den sozialen Graphen eines Nutzers repräsentiert, steht in einem dreifachen Spannungsfeld:

| Dimension | Beschreibung |
|---|---|
| **Graph-Berechenbarkeit** | Kann ein Dritter aus der Struktur Kanten extrahieren und Pfade berechnen? |
| **Datenschutz** | Wie viel erfährt ein Angreifer, der die Struktur abfängt, über das Netzwerk? |
| **Dateneffizienz** | Wie groß ist die Struktur (Bytes on the wire / in storage)? |

Keine einzelne Struktur kann alle drei Dimensionen gleichzeitig maximieren. Das Ziel ist ein **hybrides Modell**, das für jede Distanzstufe die optimale Struktur wählt.

---

## 2. Evaluierung der Kandidaten

### 2.1 Klartext Trust Manifests (Baseline)

```
Signierer: did:key:z6Mk...Alice
Kontaktliste:
  - did:key:z6Mk...Bob    → Stufe 3
  - did:key:z6Mk...Carol  → Stufe 2
  - did:key:z6Mk...Dave   → Stufe 1
  - did:key:z6Mk...Eve    → Stufe 0
Signatur: Ed25519(...)
```

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★★★★★ — Perfekt. Jede Kante ist direkt extrahierbar. |
| Datenschutz | ★☆☆☆☆ — Katastrophal. Voller sozialer/finanzieller Graph offen. |
| Dateneffizienz | ★★☆☆☆ — Linear in `n` (Kontakte). ~40 Bytes pro `did:key` + Metadaten. |
| Revokation | ★★★☆☆ — Neue signierte Liste publizieren; alte wird ungültig. |
| Offline-Tauglichkeit | ★★★★★ — Trivial, alles ist selbstbeschreibend. |

**Urteil:** Unverzichtbar für **direkte Freundschaften** (Distanz 1), da nur hier die volle Graphenberechenbarkeit benötigt wird und der Datenschutz-Trade-off akzeptabel ist (man teilt seine direkten Kontakte ohnehin mit denen, denen man vertraut). Aber **niemals** für den erweiterten Graphen geeignet.

---

### 2.2 Bloom Filter

Ein Bloom-Filter ist ein Bit-Array fester Größe `m` mit `k` Hash-Funktionen. Ein Element wird eingefügt, indem die `k` Positionen auf `1` gesetzt werden. Membership-Queries liefern "definitiv nein" oder "wahrscheinlich ja" (False-Positive-Rate `ε`).

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★☆☆☆☆ — Nur Membership-Queries, keine Enumeration. |
| Datenschutz | ★★★★☆ — Keine Enumeration, aber anfällig für Dictionary-Attacken bei bekanntem Universum. |
| Dateneffizienz | ★★★★★ — Bei ε=1% und n=150: ~180 Bytes. Extrem kompakt. |
| Revokation | ★☆☆☆☆ — **Keine Löschung möglich.** Gesamten Filter neu bauen. |
| Offline-Tauglichkeit | ★★★★★ — Selbstbeschreibend, keine Netzwerkabhängigkeit. |

**Kritische Schwäche für human_money:** Die fehlende Löschung ist ein KO-Kriterium. Wenn Alice Bob von Stufe 3 auf 0 degradiert, muss sie den gesamten Filter neu berechnen und neu signieren. Da wir **getrennte Filter pro Stufe** benötigen (Stufe 0–3 haben unterschiedliche Semantik), verstärkt sich dieses Problem.

**Urteil:** Abgelehnt zugunsten von Cuckoo-Filtern, die dieselben Vorteile bieten plus nativer Löschung.

---

### 2.3 Cuckoo Filter

Ein Cuckoo-Filter speichert `f`-Bit Fingerprints in Buckets à `b` Slots, adressiert über Cuckoo-Hashing (zwei Kandidaten-Buckets). Löschen funktioniert durch Entfernen des passenden Fingerprints.

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★☆☆☆☆ — Nur Membership-Queries. |
| Datenschutz | ★★★★☆ — Fingerprints sind nicht invertierbar; Dictionary-Attacken möglich (s. unten). |
| Dateneffizienz | ★★★★★ — Bei ε<3% *besser* als Bloom. n=150, ε=0.1%: ~300 Bytes. |
| Revokation | ★★★★☆ — **Native Löschung.** Fingerprint entfernen, Filter neu signieren. |
| Offline-Tauglichkeit | ★★★★★ — Selbstbeschreibend, kompakt, ideal für Offline. |

**Dictionary-Attacken-Mitigation:**
Das Universum der `did:key`s ist zwar theoretisch riesig (2^256), aber ein Angreifer könnte die `did:key`s aller ihm bekannten Nutzer gegen den Filter testen. Gegenmaßnahmen:

1. **Pepper (geheimes Salz):** Filter-Einträge sind `H(did:key || pepper)`. Der Pepper wird **nur** bei dem interaktiven Handshake enthüllt — nie im Filter selbst. Ein statischer Angreifer, der den Filter abfängt, kann ohne Pepper keine Queries durchführen.
2. **Rotierende Filter-Versionen:** Der Pepper wird periodisch gewechselt. Alte Filter-Versionen werden ungültig.

> **Architektur-Entscheidung:** Cuckoo-Filter sind die primäre probabilistische Struktur für `human_money_core`.

**Key-Value Cuckoo Filter Design:**
Anstatt separate Filter pro Tier zu pflegen (was Speicherplatz und Rechenzeit verschwenden würde), nutzen wir einen einzigen **Key-Value Cuckoo Filter**. Die Vertrauensstufe wird als 2-Bit-Payload direkt in jedem Slot mit dem Fingerabdruck verknüpft.

```
┌─────────────────────────────────────┐
│        IdentityEnvelope             │
│  (signiert von did:key:Alice)       │
│                                     │
│  ┌───────────────────────────────┐  │
│  │   Key-Value Cuckoo Filter     │  │
│  │   - Fingerprint: 25 Bit       │  │
│  │   - Trust Level: 2 Bit        │  │
│  │   - Total Precision: 99.9999% │  │
│  └───────────────────────────────┘  │
│                                     │
│  metadata: { version, pepper_hint, │
│    max_propagation_depth, epoch }   │
│  signature: Ed25519(...)            │
└─────────────────────────────────────┘
```

> **Wichtig:** Eine einzige Abfrage liefert sofort die Existenz **und** die höchste Vertrauensstufe zurück.

---

### 2.4 RSA Accumulator

Ein RSA-Accumulator komprimiert eine Menge von Elementen in einen einzigen Wert fester Größe (256 Bytes / 2048-Bit Modulus). Für jedes Element kann ein individueller Membership-Proof erstellt werden, der von Dritten verifizierbar ist.

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★★☆☆☆ — Nur Membership-Proofs für *bekannte* Elemente. |
| Datenschutz | ★★★★★ — Akkumulator-Wert verrät nichts. Proofs sind elementspezifisch. |
| Dateneffizienz (Akkumulator) | ★★★★★ — Konstant: 256 Bytes. |
| Dateneffizienz (Proofs) | ★★☆☆☆ — Jeder Proof: ~256 Bytes. Für Pfade mit `k` Hops: `k × 256` Bytes. |
| Revokation | ★★★★☆ — Element entfernen und neuen Akkumulator-Wert publizieren. Alte Proofs ungültig. |
| Offline-Tauglichkeit | ★★★☆☆ — Proof-Verifikation: ja. Proof-Erstellung erfordert Trapdoor oder Online-Manager. |
| Rechenaufwand | ★★☆☆☆ — Modulare Exponentiation mit großen Primzahlen. Auf mobilen Geräten: 50–200ms pro Verify. |

**Kritische Schwächen für human_money:**

1. **Trusted Setup / Trapdoor:** Der RSA-Modulus `N = p × q` erfordert, dass *jemand* `p` und `q` kennt, um Elemente hinzuzufügen/zu entfernen. In einem dezentralen System gibt es keinen solchen vertrauenswürdigen Dritten. *Class-Group-basierte Akkumulatoren* (Schwierigkeitsannahme: Klassen-Gruppen unbekannter Ordnung) lösen dies, sind aber signifikant langsamer.
2. **Proof-Größe pro Pfad:** Für einen 5-Hop-Pfad müssen 5 separate Membership-Proofs à 256 Bytes ausgetauscht werden (1.280 Bytes nur für die Akkumulator-Beweise, ohne Metadaten). Das ist zwar noch handhabbar, addiert sich aber zu den restlichen Protokoll-Daten.
3. **Kein Batch-Query:** Man kann nicht effizient fragen: "Welche meiner 150 Kontakte sind in deinem Akkumulator?" — man müsste 150 einzelne Proofs erstellen oder prüfen.

**Urteil:** RSA-Akkumulatoren sind **nicht** die primäre Struktur, aber sie spielen eine Rolle als **optionale Upgrade-Schicht** für hochsichere Kontexte (z.B. Transaktionen > 1.000€), wo die Rechenzeit akzeptabel und der individuelle, kryptographisch bindende Proof gewünscht ist.

---

### 2.5 Zero-Knowledge Proofs (zk-SNARKs / zk-STARKs)

ZK-Proofs erlauben es, eine Aussage ("Ich bin Mitglied der Menge S") zu beweisen, ohne das Mitglied oder die Menge zu offenbaren.

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★☆☆☆☆ — Keine Enumeration, nur Verifikation von Claims. |
| Datenschutz | ★★★★★ — Per Definition: "Zero Knowledge". |
| Dateneffizienz (Proof) | ★★★★☆ — zk-SNARK: ~130–300 Bytes. zk-STARK: ~45–200 KB (!). |
| Rechenaufwand (Prover) | ★☆☆☆☆ — zk-SNARK: Sekunden bis Minuten auf mobilen Geräten. zk-STARK: noch teurer. |
| Rechenaufwand (Verifier) | ★★★★★ — zk-SNARK: < 10ms. zk-STARK: ~100ms. |
| Trusted Setup | zk-SNARK: ★★☆☆☆ (benötigt CRS). zk-STARK: ★★★★★ (transparent). |
| Offline-Tauglichkeit | ★★★☆☆ — Proofs können vorab generiert werden, aber die Prover-Seite braucht erhebliche Rechenzeit. |

**Analyse für human_money:**

Das fundamentale Problem ist das **Prover-Budget auf Mobilgeräten.** Ein Offline-Handshake zwischen Alice und Bob findet typischerweise über Bluetooth oder NFC statt. Wenn Bob einen zk-SNARK-Proof in Echtzeit generieren muss, der beweist "Mein `did:key` ist in Carol's Trust-Menge, und Carol ist in Dave's Trust-Menge, und Dave ist in Alices Trust-Menge" (ein 3-Hop-Pfad), dann:

- Der Circuit müsste die gesamte Pfadlogik kodieren (Tiefe variabel!).
- Die Prover-Zeit auf einem Mittelklasse-Smartphone wäre **10–60 Sekunden** pro Hop.
- Für einen 4-Hop-Pfad: potenziell Minuten.

Das ist für eine spontane Offline-Transaktion **inakzeptabel**.

**Vorberechnung:** Bob könnte Proofs für seine häufigsten Vertrauenspfade vorberechnen (z.B. nachts, wenn das Gerät am Ladekabel hängt). Aber:
- Vorberechnung setzt voraus, dass Bob weiß, *wem* gegenüber er den Proof braucht. Bei "Stranger Discovery" ist das per Definition unbekannt.
- Vorberechnete Proofs für *alle möglichen* Zielpersonen sind nicht machbar (kombinatorische Explosion).

**Urteil:** Vollständige zk-SNARKs für die Pfadberechnung werden als **zu teuer** für den Standardfall verworfen. Sie bleiben eine Option für:
- **Statische Attestierungen** ("Ich bin Mensch" / Stufe-0-Beweis), die einmalig generiert und oft wiederverwendet werden.
- **Hochsicherheits-Transaktionen**, bei denen die Latenz akzeptabel ist.

---

### 2.6 SD-JWT (Selective Disclosure JWT)

SD-JWTs sind signierte JWTs (JSON Web Tokens), bei denen einzelne Claims vom Inhaber selektiv offengelegt werden können. Nicht offengelegte Claims sind als SHA-256-Hashes im Token enthalten — der Verifier sieht nur, dass sie existieren, nicht ihren Inhalt.

| Kriterium | Bewertung |
|---|---|
| Graph-Berechenbarkeit | ★★★☆☆ — Nur die offengelegten Claims bilden Kanten. |
| Datenschutz | ★★★★☆ — Holder kontrolliert, welche Kontakte sichtbar werden. |
| Dateneffizienz | ★★★☆☆ — Ein SD-JWT mit 5 selektiven Claims: ~800–1200 Bytes. |
| Revokation | ★★★☆☆ — Status-Listen (Bitstring) oder Short-Lived Tokens. |
| Offline-Tauglichkeit | ★★★★★ — Perfekt: `did:key` ist im `cnf`-Claim, keine Online-Resolution nötig. |
| Rechenaufwand | ★★★★★ — Nur Ed25519-Signaturen und SHA-256 — ideal für mobile Geräte. |

**Analyse für human_money:**

SD-JWTs sind die ideale Struktur für **einzelne, gerichtete Vertrauensbeweise** (Trust Attestations). Anstatt dass Alice eine komplette Kontaktliste publiziert, erstellt sie für jeden Kontakt ein individuelles SD-JWT:

```
SD-JWT erstellt von Alice für Bob:
{
  "iss": "did:key:z6Mk...Alice",       // Issuer
  "sub": "did:key:z6Mk...Bob",         // Subject
  "iat": 1743724800,                    // Issued At (Unix)
  "exp": 1775260800,                    // Expires At
  "trust_level": 3,                     // [SELEKTIV OFFENLEGBAR]
  "cnf": { "kid": "did:key:z6Mk...Bob" },
  "_sd": ["sha256_hash_of_trust_level_disclosure"]
}
```

Bob kann dieses SD-JWT nun als **Beweisstück** in seinem Wallet mitführen. Wenn Bob Alice' Vertrauen gegenüber einem Dritten beweisen will, legt er selektiv die `trust_level`-Disclosure offen. Wenn er nur beweisen will, dass Alice ihn *überhaupt* kennt, legt er nichts offen — der Dritte sieht trotzdem die gültige Signatur von Alice.

**Key Binding:** Bob muss bei der Präsentation beweisen, dass er der Inhaber des `did:key:z6Mk...Bob` ist, indem er eine Challenge mit seinem Ed25519-Private-Key signiert. Das verhindert, dass gestohlene SD-JWTs missbraucht werden.

**Urteil:** SD-JWTs sind die **primäre Struktur für Proof Attachment** (Beweisübergabe). Sie lösen das Problem der gerichteten, selektiv offenlegbaren Vertrauensbeweise mit minimalem Rechenaufwand und perfekter Offline-Tauglichkeit.

---

## 3. Vergleichende Übersicht

| Struktur | Graphen-Berechenb. | Datenschutz | Dateneffizienz | Revokation | Offline | Rechenaufwand |
|---|---|---|---|---|---|---|
| **Klartext-Manifest** | ★★★★★ | ★☆☆☆☆ | ★★☆☆☆ | ★★★☆☆ | ★★★★★ | ★★★★★ |
| **Bloom Filter** | ★☆☆☆☆ | ★★★★☆ | ★★★★★ | ★☆☆☆☆ | ★★★★★ | ★★★★★ |
| **Cuckoo Filter** | ★☆☆☆☆ | ★★★★☆ | ★★★★★ | ★★★★☆ | ★★★★★ | ★★★★★ |
| **RSA Accumulator** | ★★☆☆☆ | ★★★★★ | ★★★★★/★★☆☆☆ | ★★★★☆ | ★★★☆☆ | ★★☆☆☆ |
| **zk-SNARK** | ★☆☆☆☆ | ★★★★★ | ★★★★☆ | N/A | ★★★☆☆ | ★☆☆☆☆ (Prover) |
| **SD-JWT** | ★★★☆☆ | ★★★★☆ | ★★★☆☆ | ★★★☆☆ | ★★★★★ | ★★★★★ |

---

## 4. Das Hybride Datenmodell: Drei Schichten

Die Analyse ergibt ein dreischichtiges Modell, das für jede Distanz die optimale Struktur wählt:

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Schicht 1: DIREKTE KANTEN (Distanz = 1)                    │
│  Struktur: SD-JWT Trust Attestations                         │
│  Sichtbarkeit: Bilateral (nur Issuer ↔ Subject)             │
│  Zweck: Beweisbares, gerichtetes Vertrauen. Der Subject     │
│         trägt den Beweis in seinem Wallet.                   │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Schicht 2: NACHBARSCHAFTS-SIGNAL (Distanz = 1, aggregiert) │
│  Struktur: Tiered Cuckoo Filter (gepeppert, signiert)        │
│  Sichtbarkeit: Öffentlich propagierbar (bis max_depth)       │
│  Zweck: Effiziente Membership-Queries bei Stranger Discovery.│
│         "Ist Key X in meinem Vertrauensnetzwerk?"            │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Schicht 3: KRYPTOGRAPHISCHE HOCHSICHERHEIT (optional)       │
│  Struktur: RSA-Accumulator oder vorberechnete zk-SNARKs      │
│  Sichtbarkeit: Nur bei Bedarf, punktuell                     │
│  Zweck: Unwiderlegbare Beweise für High-Value Transaktionen. │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 4.1 Interaktion der Schichten

1. **Alltag (< 100€ Gutschein):** Bob will bei Alice bezahlen. Er prüft zunächst seinen lokalen Graphen. Findet er keinen Pfad, initiiert er das **Stranger Discovery Protocol** (→ Dokument 02). Dort nutzt er Schicht 2 (Cuckoo-Filter) für schnelle Membership-Checks und Schicht 1 (SD-JWTs) als konkreten Beweis.

2. **High-Value (> 1.000€):** Zusätzlich zu Schicht 1+2 fordert Alice einen Schicht-3-Beweis. Bob generiert (oder präsentiert einen vorberechneten) RSA-Accumulator-Proof oder zk-SNARK, der den Vertrauenspfad kryptographisch bindet.

3. **Revokation:** Details in Dokument 03. Kernidee: SD-JWTs haben ein `exp`-Datum (Short-Lived, z.B. 30 Tage). Cuckoo-Filter haben eine `epoch`-Nummer. Filter mit alter `epoch` werden verworfen. Sofortige Revokation erfolgt über **Revocation-Attestations** (negative SD-JWTs).

---

## 5. Metadaten zur Steuerung der Ausbreitung

Jedes `IdentityEnvelope` (= der signierte Container mit Cuckoo-Filtern) enthält kritische Metadaten:

| Feld | Typ | Beschreibung |
|---|---|---|
| `version` | `u32` | Monoton steigende Versionsnummer. Ältere Versionen sind ungültig. |
| `epoch` | `u64` | Unix-Timestamp der Erstellung. Filter mit `epoch` > 90 Tage gelten als stale. |
| `pepper_commitment` | `[u8; 32]` | SHA-256(pepper). Ermöglicht spätere Verifikation, ohne den Pepper zu enthüllen. |
| `max_propagation_depth` | `u8` | Maximale Hops, die dieser Envelope propagiert werden darf. Typisch: 3–5. |
| `contact_count_range` | `(u16, u16)` | Ungefährer Bereich der Kontaktanzahl (z.B. (50, 200)). Verhindert, dass die exakte Anzahl bekannt wird, gibt aber eine Größenordnung für die Filter-Bewertung. |
| `issuer_did` | `String` | `did:key` des Erstellers. |
| `signature` | `[u8; 64]` | Ed25519-Signatur über den gesamten Envelope-Inhalt. |

---

## 6. Theoretical Rust Structs

### 6.1 Trust Attestation (SD-JWT basiert)

```rust
use serde::{Serialize, Deserialize};

/// Eine individuelle, gerichtete Vertrauens-Attestierung.
/// Implementiert als SD-JWT mit selektiver Offenlegung des trust_level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAttestation {
    /// Der signierte SD-JWT Token (kompakte Serialisierung).
    /// Enthält: iss, sub, iat, exp, cnf, _sd (Hash des trust_level).
    pub sd_jwt_compact: String,

    /// Die Disclosure für den trust_level (Base64url-kodiert).
    /// Wird nur bei Bedarf an den Verifier weitergegeben.
    /// Format: Base64url(JSON([salt, "trust_level", <0|1|2|3>]))
    pub trust_level_disclosure: Option<String>,

    /// Optionale Disclosures für zusätzliche Claims
    /// (z.B. "context": "business", "max_voucher_value": 500).
    pub additional_disclosures: Vec<String>,
}

/// Trust Levels gemäß dem 4-Stufen-Modell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustLevel {
    /// Stufe 0: "Ich bestätige, dass dies ein echter Mensch ist."
    /// Keine finanzielle Haftung.
    Existence = 0,

    /// Stufe 1: Bekannter. Niedriges finanzielles Limit.
    Acquaintance = 1,

    /// Stufe 2: Kontakt. Standard-Freundschaft, mittleres Vertrauen.
    Contact = 2,

    /// Stufe 3: Enger Vertrauter. Quasi-Bürgschaft.
    Confidant = 3,
}

impl TrustLevel {
    /// Dämpfungsfaktor pro Hop für diese Vertrauensstufe.
    /// Höheres Vertrauen → weniger Dämpfung.
    pub fn damping_factor(&self) -> f64 {
        match self {
            TrustLevel::Existence  => 0.0,  // Keine finanzielle Propagation
            TrustLevel::Acquaintance => 0.30, // 30% - Starke Dämpfung nach 1 Hop
            TrustLevel::Contact    => 0.60,      // 60% - Moderate Dämpfung
            TrustLevel::Confidant   => 0.85,    // 85% - Sehr durchlässig, fast wie man selbst
        }
    }

    /// Maximales Gutschein-Akzeptanz-Limit für direkte Kanten (in Cent).
    /// Wird über Distanz weiter gedämpft.
    pub fn base_acceptance_limit_cents(&self) -> u64 {
        match self {
            TrustLevel::Existence  => 0,
            TrustLevel::Acquaintance => 5_000,    // 50€
            TrustLevel::Contact    => 50_000,     // 500€
            TrustLevel::Confidant   => 500_000,    // 5.000€
        }
    }
}
```

### 6.2 Tiered Cuckoo Filter

```rust
/// Ein hocheffizienter Key-Value Cuckoo-Filter-Container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValueCuckooFilter {
    /// Anzahl der Buckets (2^n).
    pub num_buckets: u32,

    /// Slots pro Bucket (typisch: 4).
    pub slots_per_bucket: u8,

    /// Bits pro Eintrag (25 Bit Fingerprint + 2 Bit TrustLevel = 27 Bit).
    pub bits_per_item: u8,

    /// Die bit-gepackten Filter-Daten.
    pub data: Vec<u8>,
}

impl KeyValueCuckooFilter {
    /// Prüft ob ein `did:key` (mit Pepper) enthalten ist.
    /// Gibt das gespeicherte TrustLevel zurück, falls gefunden.
    pub fn query(&self, did_key: &str, pepper: &[u8; 32]) -> Option<TrustLevel> {
        let tag = self.compute_fingerprint(did_key, pepper);
        let (bucket1, bucket2) = self.compute_buckets(did_key, pepper);

        // Suche in beiden möglichen Buckets
        if let Some(level_bits) = self.read_tag_at(bucket1, tag) {
            return TrustLevel::from_bits(level_bits);
        }
        if let Some(level_bits) = self.read_tag_at(bucket2, tag) {
            return TrustLevel::from_bits(level_bits);
        }
        None
    }

    /// Nutzt XXHash64 für extrem schnelle Bucket-Indizierung auf Mobilgeräten.
    fn compute_buckets(&self, did_key: &str, pepper: &[u8; 32]) -> (u64, u64) {
        // Implementierung von Cuckoo-Hashing (Partial-Key Cuckoo Hashing)
        // ...
        (0, 0) // Placeholder
    }

    /// Nutzt SHA-256 (abgeschnitten auf 25 Bit) für den Fingerabdruck.
    fn compute_fingerprint(&self, did_key: &str, pepper: &[u8; 32]) -> u32 {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(did_key.as_bytes());
        hasher.update(pepper);
        let result = hasher.finalize();
        // Nimm die ersten 25 Bit des Hashes
        u32::from_be_bytes([result[0], result[1], result[2], result[3]]) >> 7
    }
}
```

### 6.3 Identity Envelope (Gesamtcontainer)

```rust
/// Der signierte Gesamtcontainer, den jeder Nutzer publiziert
/// und der durch das Netzwerk propagiert wird.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEnvelope {
    /// DID des Erstellers.
    pub issuer_did: String,

    /// Monoton steigende Versionsnummer.
    /// Ältere Versionen werden ignoriert.
    pub version: u32,

    /// Unix-Timestamp der Erstellung (Sekunden).
    pub epoch: u64,

    /// SHA-256 Commitment auf den Pepper.
    /// Pepper wird nur während des interaktiven Handshakes enthüllt.
    pub pepper_commitment: [u8; 32],

    /// Maximale Propagationstiefe.
    /// Empfänger dekrementiert diesen Wert bei Weitergabe.
    pub max_propagation_depth: u8,

    /// Grober Bereich der Kontaktanzahl (min, max).
    /// Verhindert exakte Inferenz, erlaubt aber Filter-Dimensionierung.
    pub contact_count_range: (u16, u16),

    /// Der hocheffiziente Key-Value Cuckoo-Filter.
    pub filters: KeyValueCuckooFilter,

    /// Ed25519-Signatur über alle obigen Felder (kanonisches CBOR).
    pub signature: [u8; 64],
}

impl IdentityEnvelope {
    /// Prüft die Gültigkeit des Envelopes:
    /// 1. Signatur verifizieren
    /// 2. Epoch nicht zu alt (< MAX_ENVELOPE_AGE)
    /// 3. Version ist die höchste bekannte
    pub fn verify(&self, known_max_version: u32) -> Result<(), EnvelopeError> {
        // 1. Signatur prüfen
        let public_key = self.resolve_public_key()?;
        let payload = self.canonical_payload();
        ed25519_verify(&public_key, &payload, &self.signature)
            .map_err(|_| EnvelopeError::InvalidSignature)?;

        // 2. Frische prüfen
        let age = current_unix_timestamp() - self.epoch;
        if age > MAX_ENVELOPE_AGE_SECONDS {
            return Err(EnvelopeError::Stale);
        }

        // 3. Version prüfen (Replay-Schutz)
        if self.version < known_max_version {
            return Err(EnvelopeError::SupersededVersion);
        }

        Ok(())
    }

    /// Dekrementiert die Propagationstiefe für die Weitergabe.
    /// Gibt None zurück, wenn max_propagation_depth bereits 0 ist.
    pub fn propagation_copy(&self) -> Option<Self> {
        if self.max_propagation_depth == 0 {
            return None;
        }
        let mut copy = self.clone();
        copy.max_propagation_depth -= 1;
        // Signatur bleibt gültig, da max_propagation_depth
        // NICHT Teil der signierten Payload ist (Design-Entscheidung!).
        // Stattdessen signieren wir die URSPRÜNGLICHE max_depth,
        // und der aktuelle Hop-Counter ist ein unsigniertes Metadatum.
        Some(copy)
    }
}

/// Fehler bei der Envelope-Verifikation.
#[derive(Debug)]
pub enum EnvelopeError {
    InvalidSignature,
    Stale,
    SupersededVersion,
    KeyResolutionError,
}
```

### 6.4 Lokaler Vertrauensgraph

```rust
use std::collections::HashMap;

/// Der lokale In-Memory-Graph eines Wallet-Nutzers.
/// Wird aus empfangenen Envelopes und Attestations aufgebaut.
pub struct LocalTrustGraph {
    /// Eigene DID.
    pub self_did: String,

    /// Direkte Kanten: did -> (TrustLevel, TrustAttestation).
    /// Dies sind die Stufe-1-Daten (Schicht 1).
    pub direct_edges: HashMap<String, (TrustLevel, TrustAttestation)>,

    /// Empfangene IdentityEnvelopes anderer Nutzer.
    /// Indiziert nach issuer_did, nur die neueste Version.
    pub envelopes: HashMap<String, IdentityEnvelope>,

    /// Cache: Berechnete Vertrauenswerte für entfernte DIDs.
    /// (did_key → computed_trust_score)
    pub trust_cache: HashMap<String, CachedTrustScore>,

    /// Empfangene Revocation-Attestierungen.
    pub revocations: Vec<RevocationAttestation>,
}

#[derive(Debug, Clone)]
pub struct CachedTrustScore {
    /// Berechneter Trust-Score (0.0 – 1.0).
    pub score: f64,

    /// Der beste gefundene Pfad (Liste von DIDs).
    pub path: Vec<String>,

    /// Die akkumulierte Dämpfung entlang des Pfades.
    pub accumulated_damping: f64,

    /// Zeitpunkt der Berechnung.
    pub computed_at: u64,

    /// Das effektive Akzeptanzlimit in Cent
    /// (basierend auf der schwächsten Kante im Pfad).
    pub effective_limit_cents: u64,
}
```

---

## 7. Größenabschätzungen

Für einen typischen Nutzer mit ~150 Kontakten:

| Komponente | Geschätzte Größe |
|---|---|
| `key_value_filter` (n=150, p=0.0001%) | ~610 Bytes |
| Metadaten + Signatur | ~200 Bytes |
| **IdentityEnvelope gesamt** | **~810 Bytes** |

Vergleich:
- Klartext-Manifest (150 Kontakte): ~6.000 Bytes (7.4× größer)
- Einzelnes SD-JWT (Trust Attestation): ~800–1.200 Bytes
- RSA-Accumulator-Proof (pro Element): ~256 Bytes

> **Fazit:** Der Key-Value Cuckoo Filter ist die effizienteste Struktur für die Netzwerk-Propagation. Er verbindet extrem hohe Präzision (99,9999%) mit minimalem Speicherbedarf und erlaubt die Abfrage von Existenz und Vertrauensstufe in einem einzigen Schritt.

---

## 8. Offene Design-Entscheidungen

| # | Entscheidung | Empfehlung | Alternativ |
|---|---|---|---|
| 1 | Pepper-Sharing-Mechanismus beim Handshake | Diffie-Hellman Key Exchange über X25519 (abgeleitet vom Ed25519-Keypair) → shared secret → Pepper wird mit XOR maskiert übertragen | Pepper im Klartext übertragen (einfacher, aber MITM-anfällig) |
| 2 | Canonical Serialization für Signatur | CBOR (RFC 8949) mit deterministischer Sortierung | JSON Canonicalization Scheme (JCS, RFC 8785) |
| 3 | Max Envelope Age | 90 Tage (Kompromiss Frische vs. Offline-Dauer) | 30 Tage (sicherer) oder 180 Tage (Offline-freundlicher) |
| 4 | SD-JWT Expiry | 30 Tage (erfordert regelmäßige Erneuerung) | 90 Tage (weniger Aufwand, höheres Revokations-Risiko) |
| 5 | Filter-Kompression | zstd (bessere Kompression) | LZ4 (schnellere Dekompression auf schwachen Geräten) |

---

## 9. Zusammenfassung

Das hybride Datenmodell von `human_money_core` kombiniert drei Strukturen für unterschiedliche Zwecke:

1. **SD-JWT Trust Attestations** → Individuelle, kryptographisch bindende Vertrauensbeweise mit selektiver Offenlegung. Getragen vom Subject (Receiver Principle). Ideal für den interaktiven Handshake.

2. **Tiered Cuckoo Filter (IdentityEnvelope)** → Kompakte, gepepperte, signierte Filter für effiziente Membership-Queries. Propagierbar durch das Netzwerk mit kontrollierter Tiefe. Löst das Bandbreiten- und Privatsphäre-Problem.

3. **RSA-Accumulator / zk-SNARKs (optional)** → Kryptographisch unwiderlegbare Beweise für hohe Transaktionswerte. Nur bei Bedarf, nicht im Standardpfad.

Dieses Design vermeidet die Extreme (volle Transparenz vs. völlige Opazität) und bietet stattdessen ein **nuanciertes Spektrum an Datenschutz**, das zur jeweiligen Situation passt.
