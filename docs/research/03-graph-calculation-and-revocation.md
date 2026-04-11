# 03 — Graph Calculation & Revocation

> **Projekt:** `human_money_core`
> **Autor:** Lead System Architect
> **Stand:** 2026-04-04
> **Status:** Forschungsdokument / Berechnungsmodell
> **Abhängigkeiten:** Dokument 01 (Datenstrukturen), Dokument 02 (Protokoll)

---

## 1. Lokale Graphen-Berechnung: Grundmodell

### 1.1 Der Graph als gewichteter Digraph

Der Vertrauensgraph eines Nutzers ist ein **gerichteter, gewichteter Graph** `G = (V, E, w)`:

- **V:** Menge aller bekannten `did:key`s (Knoten).
- **E:** Gerichtete Kanten `(A → B)`, wobei A dem B Vertrauen ausspricht.
- **w(A → B):** Kantengewicht, bestimmt durch die Vertrauensstufe (0–3).

> **Asymmetrie:** `w(A → B) ≠ w(B → A)`. Alice kann Bob Stufe 3 geben, während Bob Alice nur Stufe 1 gibt. Die Richtung der Kante kodiert: "Wer bürgt für wen?"

### 1.2 Semantik der Kantengewichte

```
Vertrauensstufe →  Kantengewicht  →  Dämpfungsfaktor γ  →  Basis-Limit (Cent)
─────────────────────────────────────────────────────────────────────────────
Stufe 0 (Kennen)       0.0              0.00                     0
Stufe 1 (Bekannter)    0.3              0.30                  5.000 (50€)
Stufe 2 (Kontakt)      0.6              0.60                 50.000 (500€)
Stufe 3 (Vertrauter)   0.85             0.85                500.000 (5.000€)
```

### 1.3 Stufe 0: Die Sonderrolle

**Stufe 0 hat einen Dämpfungsfaktor von 0.0.** Das bedeutet:
- Stufe-0-Kanten tragen **kein finanzielles Vertrauen** weiter.
- Sie dienen ausschließlich dem **Sybil-Schutz**: "Ich bestätige, dass hinter diesem Key ein realer Mensch steckt."
- Ein Vertrauenspfad, der über eine Stufe-0-Kante läuft, hat ein **effektives Limit von 0 Cent** — egal, wie stark die restlichen Kanten sind.

> **Konsequenz:** Stufe-0-Kanten erscheinen im Graphen, werden aber beim finanziellen Trust-Routing **ignoriert**. Sie sind relevant für:
> - Sybil-Resistenz-Metriken (wie viele unabhängige Stufe-0-Attestierungen hat ein Knoten?)
> - Bootstrapping (ein neuer Nutzer hat zunächst nur Stufe-0-Kanten)
> - Soziale Discovery (wer kennt wen, unabhängig von Finanzen)

---

## 2. Trust-Score-Berechnung über Distanz

### 2.1 Das Dämpfungsmodell

Für einen Pfad `P = (v₀ → v₁ → ... → vₖ)` mit `k` Kanten berechnet sich der **Trust-Score** als:

```
                    k
T(P) =  ∏  γ(level(vᵢ₋₁ → vᵢ))
                   i=1

Wobei:
  γ(level) = Dämpfungsfaktor der Vertrauensstufe (s. Tabelle oben)
  level(A → B) = Die Vertrauensstufe, die A dem B zugewiesen hat
```

**Beispiel: Pfad Bob → Carol → Dave → Alice**

```
Kante 1: Carol vertraut Bob mit Stufe 3    → γ = 0.85
Kante 2: Dave vertraut Carol mit Stufe 2   → γ = 0.60
Kante 3: Alice vertraut Dave mit Stufe 2   → γ = 0.60

T(P) = 0.85 × 0.60 × 0.60 = 0.306

→ Trust-Score: 30.6%
```

### 2.2 Das Bottleneck-Prinzip (Min-Edge Rule)

Zusätzlich zum multiplikativen Trust-Score gilt das **Bottleneck-Prinzip**: Das effektive Limit eines Pfades wird durch die **schwächste Kante** bestimmt:

```
EffectiveLimit(P) = min(BaseLimitᵢ) × T(P)
                     i∈P

Wobei:
  BaseLimitᵢ = base_acceptance_limit_cents(level(vᵢ₋₁ → vᵢ))
```

**Beispiel (fortgesetzt):**

```
Kante 1: Stufe 3 → BaseLim = 500.000 ct (5.000€)
Kante 2: Stufe 2 → BaseLim =  50.000 ct  (500€)    ← Minimum!
Kante 3: Stufe 2 → BaseLim =  50.000 ct  (500€)

EffectiveLimit = min(500.000, 50.000, 50.000) × 0.306
               = 50.000 × 0.306
               = 15.300 ct (153€)

→ Bob kann bei Alice Gutscheine bis 153€ einlösen.
```

### 2.3 Warum Multiplikation statt Addition?

Die multiplikative Dämpfung wurde bewusst gewählt:

1. **Exponentieller Verfall:** Trust fällt bei länger Pfade rapide ab. Bei Stufe-2-Kanten (γ=0.6):
   ```
   1 Hop: 60%    → 300€
   2 Hops: 36%   → 180€
   3 Hops: 21.6% → 108€
   4 Hops: 13%   → 65€
   5 Hops: 7.8%  → 39€
   ```
   Das spiegelt die Realität wider: Man traut einem Freund eines Freundes deutlich weniger als einem direkten Freund.

2. **Resistent gegen Pfad-Inflation:** Ein Angreifer, der viele schwache Pfade konstruiert, kann deren Scores nicht sinnvoll addieren — jeder einzelne Pfad hat seinen eigenen, unabhängigen Score.

3. **Min-Edge-Bottleneck schützt weiter:** Selbst wenn ein Pfad über drei Stufe-3-Kanten und dann eine Stufe-1-Kante läuft, wird das Limit auf 50€-Basis gedeckelt.

---

## 3. Multi-Path Trust Aggregation

### 3.1 Mehrere Pfade zwischen A und B

Wenn es **mehrere** unabhängige Pfade zwischen Bob und Alice gibt, stellt sich die Frage: Werden deren Trust-Scores addiert?

**Nein. Wir verwenden den besten Pfad, nicht die Summe.**

Begründung:

1. **Additive Aggregation ist spieltheoretisch gefährlich:** Ein Angreifer könnte viele schwache Pfade konstruieren (z.B. über Sybil-Knoten), die sich addieren und einen starken Gesamtscore ergeben. Davids Klassiker "Vertrauen ist nicht Geld — man kann es nicht beliebig aufteilen und addieren" gilt hier.

2. **Pragmatische Alternative: Top-2-Weighted-Max**

```rust
/// Berechnet den aggregierten Trust-Score aus mehreren Pfaden.
/// Verwendet den besten Pfad plus einen Bonus für Pfad-Redundanz.
fn aggregate_trust_scores(paths: &[VerifiedPath]) -> AggregatedTrust {
    let mut sorted = paths.to_vec();
    sorted.sort_by(|a, b| b.effective_limit_cents.cmp(&a.effective_limit_cents));

    let best = &sorted[0];

    // Redundanz-Bonus: Wenn ein zweiter, unabhängiger Pfad existiert,
    // steigt das Vertrauen um bis zu 20% des zweitbesten Pfad-Scores.
    let redundancy_bonus = if sorted.len() >= 2 {
        let second_best = &sorted[1];
        // Nur wenn die Pfade disjunkt sind (keine gemeinsamen Zwischenknoten)
        if paths_are_disjoint(best, second_best) {
            (second_best.effective_limit_cents as f64 * 0.20) as u64
        } else {
            0 // Nicht-disjunkte Pfade geben keinen Bonus
        }
    } else {
        0
    };

    AggregatedTrust {
        primary_path: best.clone(),
        total_effective_limit: best.effective_limit_cents + redundancy_bonus,
        path_count: sorted.len(),
        has_disjoint_backup: redundancy_bonus > 0,
    }
}
```

### 3.2 Unabhängigkeitsprüfung (Disjoint Paths)

Zwei Pfade gelten als **disjunkt**, wenn sie keine gemeinsamen Zwischenknoten teilen (Start- und Endknoten ausgenommen):

```rust
fn paths_are_disjoint(a: &VerifiedPath, b: &VerifiedPath) -> bool {
    let intermediates_a: HashSet<_> = a.path[1..a.path.len()-1].iter().collect();
    let intermediates_b: HashSet<_> = b.path[1..b.path.len()-1].iter().collect();
    intermediates_a.is_disjoint(&intermediates_b)
}
```

Dies verhindert, dass ein zentraler Knoten (z.B. ein Sybil-Kontrolleur) durch seine Position in vielen Pfaden künstlich hohe Scores erzeugt.

---

## 4. Pathfinding-Algorithmus

### 4.1 Modifizierter Dijkstra

Da wir den Pfad mit dem **höchsten** Trust-Score suchen (nicht den kürzesten), invertieren wir die Gewichte und verwenden Dijkstra mit negativen Log-Gewichten:

```rust
use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
struct PathCandidate {
    current_node: String,
    accumulated_log_trust: f64,  // -Σ ln(γᵢ), minimieren = maximaler Trust
    accumulated_trust: f64,      // Π γᵢ, der tatsächliche Trust-Score
    min_base_limit: u64,         // Bottleneck
    path: Vec<String>,
    hop_count: u32,
}

impl Ord for PathCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-Heap auf accumulated_log_trust (kleinerer Wert = höherer Trust)
        other.accumulated_log_trust
            .partial_cmp(&self.accumulated_log_trust)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for PathCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PathCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.accumulated_log_trust == other.accumulated_log_trust
    }
}

impl Eq for PathCandidate {}

/// Findet den besten Vertrauenspfad von `source` zu `target`
/// im lokalen Graphen.
fn find_best_trust_path(
    graph: &LocalTrustGraph,
    source: &str,
    target: &str,
    max_hops: u32,
) -> Option<VerifiedPath> {
    let mut heap = BinaryHeap::new();
    let mut best_scores: HashMap<String, f64> = HashMap::new();

    // Startknoten
    heap.push(PathCandidate {
        current_node: source.to_string(),
        accumulated_log_trust: 0.0,
        accumulated_trust: 1.0,
        min_base_limit: u64::MAX,
        path: vec![source.to_string()],
        hop_count: 0,
    });

    while let Some(candidate) = heap.pop() {
        // Ziel erreicht?
        if candidate.current_node == target {
            let effective_limit = (candidate.min_base_limit as f64
                                  * candidate.accumulated_trust) as u64;
            return Some(VerifiedPath {
                path: candidate.path,
                min_trust_level: TrustLevel::Existence, // wird unten korrekt gesetzt
                accumulated_damping: candidate.accumulated_trust,
                effective_limit_cents: effective_limit,
                hop_count: candidate.hop_count as usize,
            });
        }

        // Hop-Limit erreicht?
        if candidate.hop_count >= max_hops {
            continue;
        }

        // Bereits besseren Pfad zu diesem Knoten gefunden?
        if let Some(&best) = best_scores.get(&candidate.current_node) {
            if candidate.accumulated_log_trust > best {
                continue;
            }
        }
        best_scores.insert(candidate.current_node.clone(),
                          candidate.accumulated_log_trust);

        // Nachbarn expandieren
        // Kombination aus: direkten Kanten UND Cuckoo-Filter-Ergebnissen
        let neighbors = get_trusted_neighbors(graph, &candidate.current_node);

        for (neighbor_did, trust_level) in neighbors {
            if trust_level == TrustLevel::Existence {
                continue; // Stufe 0: Keine finanzielle Pfad-Expansion
            }

            let gamma = trust_level.damping_factor();
            if gamma <= 0.0 {
                continue;
            }

            let log_weight = -(gamma.ln()); // -ln(γ), positiv da γ < 1
            let new_log_trust = candidate.accumulated_log_trust + log_weight;
            let new_trust = candidate.accumulated_trust * gamma;
            let new_min_limit = candidate.min_base_limit
                .min(trust_level.base_acceptance_limit_cents());

            let mut new_path = candidate.path.clone();
            new_path.push(neighbor_did.clone());

            heap.push(PathCandidate {
                current_node: neighbor_did,
                accumulated_log_trust: new_log_trust,
                accumulated_trust: new_trust,
                min_base_limit: new_min_limit,
                path: new_path,
                hop_count: candidate.hop_count + 1,
            });
        }
    }

    None // Kein Pfad gefunden
}

/// Gibt die vertrauenswürdigen Nachbarn eines Knotens zurück.
/// Kombiniert direkte Kanten und bekannte Envelope-Daten.
fn get_trusted_neighbors(
    graph: &LocalTrustGraph,
    node_did: &str,
) -> Vec<(String, TrustLevel)> {
    let mut neighbors = Vec::new();

    // 1. Direkte Kanten aus dem lokalen Graphen
    if node_did == graph.self_did {
        for (did, (level, _)) in &graph.direct_edges {
            neighbors.push((did.clone(), *level));
        }
    }

    // 2. Kanten aus bekannten Envelopes (Distanz 2+)
    // ACHTUNG: Aus Cuckoo-Filtern können wir nur testen,
    // ob ein BEKANNTER Key drin ist — nicht enumerieren!
    // Daher: Wir testen alle uns bekannten DIDs gegen
    // den Envelope des aktuellen Knotens.
    if let Some(envelope) = graph.envelopes.get(node_did) {
        if let Some(pepper) = graph.pepper_cache.get(node_did) {
            // Teste alle in unserem Graphen bekannten DIDs
            for known_did in graph.all_known_dids() {
                if let Some(level) = envelope.filters.query(known_did, pepper) {
                    if level != TrustLevel::Existence {
                        neighbors.push((known_did.to_string(), level));
                    }
                }
            }
        }
    }

    neighbors
}
```

### 4.2 Komplexitätsanalyse

| Parameter | Typischer Wert |
|---|---|
| `\|V\|` (bekannte DIDs) | ~500–2000 |
| `\|E\|` (bekannte Kanten + Filter-Treffer) | ~2000–10.000 |
| Maximum Hops | 5 |
| Dijkstra-Laufzeit | O((V + E) × log V) ≈ O(12.000 × 11) ≈ ~130.000 Operationen |
| Geschätzte Zeit (Smartphone) | < 10ms |

---

## 5. Revocation: Vertrauen entziehen

### 5.1 Die drei Revokationsmechanismen

Das System verwendet drei komplementäre Mechanismen, die zusammen ein robustes Revokationsmodell bilden:

```
┌───────────────────────────────────────────────────────────────────┐
│                    REVOCATION MECHANISMS                          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  1. NATURAL DECAY (Passive Revocation)                      │  │
│  │     SD-JWTs haben ein exp-Datum (30-90 Tage).               │  │
│  │     Wenn nicht erneuert → automatisch ungültig.              │  │
│  │     Kein aktives Handeln nötig.                              │  │
│  │     Latenz: Bis zu 90 Tage.                                 │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  2. EXPLICIT REVOCATION ATTESTATION (Active Revocation)     │  │
│  │     Ein negatives SD-JWT, das ein bestehendes widerruft.     │  │
│  │     Propagiert durch das Netzwerk wie eine Trust Attestation. │  │
│  │     Latenz: Stunden bis Tage (Gossip-Propagation).           │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  3. EPOCH-BASED FILTER REFRESH (Periodic Revocation)        │  │
│  │     IdentityEnvelopes werden periodisch neu erstellt.        │  │
│  │     Der neue Envelope enthält die aktuellen Kontakte.        │  │
│  │     Alte Envelopes werden nach MAX_AGE verworfen.            │  │
│  │     Latenz: Bis zu MAX_AGE (90 Tage).                       │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### 5.2 Mechanismus 1: Natural Decay (Passive Revocation)

**Prinzip:** Jede Trust Attestation (SD-JWT) hat ein eingebautes Verfallsdatum (`exp`). Wird sie nicht erneuert, stirbt sie automatisch.

```
┌──────────────────────────────────────────────────────────┐
│  Zeitachse einer Trust Attestation                       │
│                                                          │
│  t=0d        t=25d       t=30d       t=35d               │
│  │           │           │           │                   │
│  ▼           ▼           ▼           ▼                   │
│  [GÜLTIG]────[WARN]──────[ABGELAUFEN]──────────────── ►  │
│  ↑           ↑           ↑                               │
│  Ausgestellt  Wallet       Nicht                          │
│               warnt:       erneuert                       │
│               "Erneuern!"  → ungültig                     │
└──────────────────────────────────────────────────────────┘
```

**Erneuerungsprozess:**

```rust
/// Wird vom Wallet automatisch ausgelöst, wenn eine
/// Attestation innerhalb von 5 Tagen abläuft.
async fn renew_attestation(
    issuer_did: &str,
    subject_did: &str,
    current_level: TrustLevel,
) -> Result<TrustAttestation, RenewalError> {
    // 1. Prüfe ob der Issuer noch online/erreichbar ist
    // 2. Issuer erstellt neues SD-JWT mit aktuellem trust_level
    // 3. Das neue SD-JWT ersetzt das alte im Wallet des Subjects

    // WICHTIG: Der Issuer kann beim Renewal die Stufe ändern!
    // Alice kann Bob bei der Erneuerung von Stufe 3 auf Stufe 1 setzen.
    // Das ist eine "sanfte Degradierung" ohne explizite Revocation.
}
```

**Vorteile:**
- Völlig asynchron, kein spezieller Revokationsmechanismus nötig.
- "Vergesslichkeit" ist der Default — man muss aktiv erneuern, um Vertrauen aufrechtzuerhalten.
- Ideal für das Offline-First-Design: Kein Netzwerk-Broadcast nötig.

**Nachteile:**
- Latenz: Bis zu 30–90 Tage, bis eine nicht-erneuerte Attestation verfällt.
- Für akute Vertrauensverluste (Betrug, Key-Kompromittierung) zu langsam.

---

### 5.3 Mechanismus 2: Explicit Revocation Attestation

**Prinzip:** Alice erstellt eine signierte **Revocation Attestation**, die eine bestehende Trust Attestation explizit widerruft.

```rust
/// Eine Revocation Attestation — das "Gegenstück" zu einer TrustAttestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationAttestation {
    /// DID des Widerrufenden (= Issuer der ursprünglichen Attestation).
    pub revoker_did: String,

    /// DID der widerrufenen Person.
    pub revoked_did: String,

    /// Hash der widerrufenen SD-JWT (SHA-256 über den kompakten Token).
    /// Ermöglicht exakte Identifikation der widerrufenen Attestation.
    pub revoked_attestation_hash: [u8; 32],

    /// Neues Vertrauenslevel (typisch: Stufe 0 oder None für vollständigen Entzug).
    pub new_trust_level: Option<TrustLevel>,

    /// Grund des Widerrufs (optional, für Audit-Zwecke).
    pub reason: RevocationReason,

    /// Zeitstempel des Widerrufs.
    pub revoked_at: u64,

    /// Ed25519-Signatur des Revokers über alle obigen Felder.
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Vertrauensverlust (generisch).
    TrustLoss,
    /// Verdacht auf Key-Kompromittierung.
    KeyCompromise,
    /// Degradierung auf niedrigere Stufe (nicht vollständiger Entzug).
    Downgrade,
    /// Kein Grund angegeben.
    Unspecified,
}
```

**Propagation durch das Netzwerk:**

Revocation Attestations werden wie reguläre Trust Attestations durch das Gossip-Netzwerk verbreitet. Allerdings mit **Priorität**: Ein Wallet, das eine Revocation empfängt, behandelt sie mit höherer Dringlichkeit als eine neue Trust Attestation.

```rust
/// Verarbeitung einer empfangenen Revocation im lokalen Graphen.
fn process_revocation(
    graph: &mut LocalTrustGraph,
    revocation: &RevocationAttestation,
) -> Result<RevocationEffect, RevocationError> {
    // 1. Signatur der Revocation verifizieren
    let revoker_pk = resolve_ed25519_pubkey(&revocation.revoker_did)?;
    verify_ed25519(&revoker_pk, &revocation.canonical_payload(), &revocation.signature)?;

    // 2. Ist die widerrufene Attestation bekannt?
    let attestation_key = (&revocation.revoker_did, &revocation.revoked_did);

    // 3. Lokalen Graphen aktualisieren
    match revocation.new_trust_level {
        Some(new_level) => {
            // Degradierung: Kante bleibt, aber mit niedrigerem Gewicht
            if let Some(edge) = graph.direct_edges.get_mut(&revocation.revoked_did) {
                let old_level = edge.0;
                edge.0 = new_level;
                Ok(RevocationEffect::Downgraded {
                    from: old_level,
                    to: new_level,
                })
            } else {
                Ok(RevocationEffect::NoLocalEffect) // Kante war nicht im Graphen
            }
        },
        None => {
            // Vollständiger Entzug: Kante entfernen
            graph.direct_edges.remove(&revocation.revoked_did);
            Ok(RevocationEffect::EdgeRemoved)
        }
    }

    // 4. Trust-Cache invalidieren
    // Alle gecachten Trust-Scores, die über die widerrufene
    // Person als Zwischenknoten laufen, müssen neu berechnet werden.
    graph.trust_cache.retain(|_, cached| {
        !cached.path.contains(&revocation.revoked_did)
    });

    // 5. Revocation weiterleiten (Gossip)
    // → An alle direkten Kontakte senden
}
```

**Timing-Diagramm: Revocation-Propagation**

```
Zeitpunkt 0:    Alice widerruft Bobs Stufe 3 → Stufe 0
                Alice publiziert RevocationAttestation

Zeitpunkt +1h:  Carol (Alices Kontakt) empfängt die Revocation
                Carol invalidiert ihren Trust-Cache für Bob
                Carol leitet die Revocation an Dave weiter

Zeitpunkt +3h:  Dave empfängt die Revocation
                Dave invalidiert seinen Trust-Cache

Zeitpunkt +6h:  Die meisten Knoten im 3-Hop-Radius haben die
                Revocation empfangen

Zeitpunkt +24h: 99% des relevanten Netzwerks ist aktualisiert
                (angenommen: typische Gossip-Latenz bei
                 regelmäßiger Wallet-Nutzung)

ABER:

Zeitpunkt 0–24h: Eve (offline) hat die Revocation NICHT empfangen.
                  Eve akzeptiert Bobs Gutschein auf Basis des
                  alten Trust-Scores.

                  → Das ist der unvermeidliche Trade-off in
                    einem Offline-First-System!
```

**Eve's Risiko-Mitigation:**

Eve verlässt sich auf die **Frische der Attestations**:
- Wenn Bobs SD-JWT von Alice ein `iat` (issued-at) hat, das älter als 7 Tage ist, und es keine neuere Version gibt, kann Eve stutzig werden.
- Eve kann einen "Freshness-Discount" anwenden: Ältere Attestierungen werden automatisch abgewertet.

```rust
/// Freshness-Discount: Ältere Attestationen werden abgewertet.
fn freshness_discount(attestation_age_days: u64) -> f64 {
    match attestation_age_days {
        0..=7    => 1.00,  // Frisch: 100%
        8..=14   => 0.95,  // Leicht abgewertet: 95%
        15..=30  => 0.85,  // Deutlich abgewertet: 85%
        31..=60  => 0.60,  // Stark abgewertet: 60%
        61..=90  => 0.30,  // Sehr alt: 30%
        _        => 0.00,  // Abgelaufen: 0%
    }
}
```

---

### 5.4 Mechanismus 3: Epoch-Based Filter Refresh

**Prinzip:** IdentityEnvelopes (die Cuckoo-Filter-Container) werden periodisch neu erstellt. Ein neuer Envelope hat eine höhere `version`-Nummer und eine frischere `epoch`. Ältere Envelopes werden vom Netzwerk verworfen.

```
┌──────────────────────────────────────────────────────────┐
│  Epoch-Refresh-Zyklus                                    │
│                                                          │
│  Envelope v1          Envelope v2          Envelope v3   │
│  epoch: Jan 1         epoch: Apr 1          epoch: Jul 1 │
│  ┌──────────┐         ┌──────────┐         ┌──────────┐  │
│  │ Bob: ✓   │   ──►   │ Bob: ✗   │   ──►   │ Bob: ✗   │  │
│  │ Carol: ✓ │         │ Carol: ✓ │         │ Carol: ✓ │  │
│  │ Dave: ✓  │         │ Dave: ✓  │         │ Eve: ✓   │  │
│  └──────────┘         └──────────┘         └──────────┘  │
│                                                          │
│  Bob wurde in v2 entfernt (widerrufen).                  │
│  Eve wurde in v3 hinzugefügt (neuer Kontakt).            │
│  Pepper wurde in v2 rotiert → v1-Queries sind ungültig.  │
└──────────────────────────────────────────────────────────┘
```

**Konsistenzregeln:**

1. **Version-Monotonie:** `version(v_new) > version(v_old)`. Wallets speichern nur den Envelope mit der höchsten bekannten Version.
2. **Epoch-Maximum:** Envelopes mit `epoch` älter als 90 Tage werden verworfen (`MAX_ENVELOPE_AGE`).
3. **Pepper-Rotation:** Bei jedem Refresh wird der Pepper gewechselt. Das invalidiert alle Query-Ergebnisse basierend auf dem alten Pepper.

```rust
/// Entscheidungslogik beim Empfang eines neuen Envelopes.
fn handle_received_envelope(
    store: &mut EnvelopeStore,
    new_envelope: IdentityEnvelope,
) -> EnvelopeAction {
    let issuer = &new_envelope.issuer_did;

    match store.get(issuer) {
        Some(existing) => {
            if new_envelope.version > existing.version {
                // Neuere Version → ersetzen
                store.insert(issuer.clone(), new_envelope);
                EnvelopeAction::Updated
            } else if new_envelope.version == existing.version {
                // Gleiche Version → ignorieren (Duplikat)
                EnvelopeAction::Duplicate
            } else {
                // Ältere Version → potenzielle Replay-Attacke
                EnvelopeAction::Rejected("Older version than stored")
            }
        },
        None => {
            // Erster Envelope von diesem Issuer
            let age = current_timestamp() - new_envelope.epoch;
            if age > MAX_ENVELOPE_AGE_SECONDS {
                EnvelopeAction::Rejected("Envelope too old")
            } else {
                store.insert(issuer.clone(), new_envelope);
                EnvelopeAction::NewlyStored
            }
        }
    }
}
```

---

## 6. Konsistenz in asynchronen Netzen

### 6.1 Das CAP-Theorem für Trust-Graphen

In einem dezentralen, asynchronen System gilt eine Variante des CAP-Theorems:

- **Consistency:** Alle Knoten haben denselben Trust-Graphen.
- **Availability:** Jeder Knoten kann jederzeit Trust-Entscheidungen treffen.
- **Partition Tolerance:** Das System funktioniert auch bei Netzwerkpartitionen (Offline-Knoten).

**human_money wählt: AP (Availability + Partition Tolerance) mit Eventual Consistency.**

Das bedeutet: Verschiedene Knoten können *vorübergehend* unterschiedliche Trust-Scores für denselben Pfad berechnen, konvergieren aber über Zeit zum selben Ergebnis.

### 6.2 Konflikterkennung und -auflösung

**Szenario:** Eve hat Alices Envelope v3, aber Franks Wallet hat noch Envelope v1 (Eve war schlecht vernetzt).

| Situation | Verhalten von Franks Wallet |
|---|---|
| Frank empfängt v3 | Ersetzt v1 durch v3. Trust-Cache für Alice' Nachbarn wird invalidiert. |
| Frank empfängt eine Revocation, die v1 betrifft | Verarbeitet die Revocation, obwohl v3 die Situation bereits korrekt widerspiegeln könnte. Kein Schaden — die Revocation bestätigt nur den aktuellen Stand. |
| Frank empfängt v2 und v3 gleichzeitig | Nimmt v3 (höchste Version). v2 wird ignoriert. |
| Frank empfängt eine SD-JWT Attestation mit `iat` > v1.epoch aber < v3.epoch | Akzeptiert die SD-JWT, fragt aber beim nächsten Online-Moment nach dem aktuellen Envelope. |

### 6.3 Stale-Data-Risiko und Mitigation

```
                    STALE-DATA-RISIKO-MATRIX

    Datentyp          │ Max. Alter  │ Risiko bei   │ Mitigation
                      │             │ Stale Data   │
    ──────────────────┼─────────────┼──────────────┼────────────────
    SD-JWT Attestation │ 30-90 Tage  │ Hoch         │ exp + Freshness-
                      │             │ (Vertrauen   │ Discount
                      │             │  evtl. wider-│
                      │             │  rufen)      │
    ──────────────────┼─────────────┼──────────────┼────────────────
    IdentityEnvelope  │ 90 Tage     │ Mittel       │ epoch + Version
                      │             │ (Kontakt     │ + Pepper-Rotation
                      │             │  evtl. ent-  │
                      │             │  fernt)      │
    ──────────────────┼─────────────┼──────────────┼────────────────
    RevocationAttest. │ Unbegrenzt  │ Niedrig      │ Revocations sind
                      │             │ (Revocation  │ monoton: einmal
                      │             │  ist bin.)   │ widerrufen =
                      │             │              │ immer widerrufen
    ──────────────────┼─────────────┼──────────────┼────────────────
    Trust-Cache       │ Variabel    │ Niedrig      │ Neuberechnung
                      │             │ (Nur Perf.-  │ bei jedem Graph-
                      │             │  Optimierung)│ Update
```

---

## 7. Automatische Graph-Wartung

### 7.1 Hintergrund-Tasks im Wallet

Das Wallet führt periodisch Wartungsaufgaben durch:

```rust
/// Periodische Graph-Wartung (z.B. einmal täglich oder bei Wallet-Start).
fn graph_maintenance(graph: &mut LocalTrustGraph) -> MaintenanceReport {
    let now = current_timestamp();
    let mut report = MaintenanceReport::default();

    // 1. Abgelaufene SD-JWTs entfernen
    graph.direct_edges.retain(|did, (_, attestation)| {
        let still_valid = attestation.expiry() > now;
        if !still_valid {
            report.expired_attestations.push(did.clone());
        }
        still_valid
    });

    // 2. Abgelaufene Envelopes entfernen
    graph.envelopes.retain(|did, envelope| {
        let age = now - envelope.epoch;
        let still_valid = age <= MAX_ENVELOPE_AGE_SECONDS;
        if !still_valid {
            report.expired_envelopes.push(did.clone());
        }
        still_valid
    });

    // 3. Verarbeitete Revocations aufräumen
    // Revocations, die sich auf bereits entfernte Attestations beziehen,
    // können gelöscht werden (sofern sie älter als 90 Tage sind).
    graph.revocations.retain(|rev| {
        now - rev.revoked_at <= MAX_ENVELOPE_AGE_SECONDS
    });

    // 4. Trust-Cache invalidieren
    // Alle Cache-Einträge älter als 24h oder die über entfernte
    // Knoten laufen, werden gelöscht.
    let stale_threshold = now - 86400; // 24 Stunden
    graph.trust_cache.retain(|_, cached| {
        if cached.computed_at < stale_threshold {
            report.stale_cache_entries += 1;
            return false;
        }
        // Prüfe ob der Pfad noch über existierende Knoten läuft
        for did in &cached.path {
            if !graph.direct_edges.contains_key(did)
               && !graph.envelopes.contains_key(did)
               && did != &graph.self_did
            {
                report.invalidated_cache_entries += 1;
                return false;
            }
        }
        true
    });

    // 5. Attestation-Erneuerungswarnungen generieren
    for (did, (level, attestation)) in &graph.direct_edges {
        let days_until_expiry = (attestation.expiry() - now) / 86400;
        if days_until_expiry <= 5 {
            report.renewal_warnings.push(RenewalWarning {
                contact_did: did.clone(),
                trust_level: *level,
                days_remaining: days_until_expiry as u32,
            });
        }
    }

    report
}
```

### 7.2 Envelope-Erneuerung des eigenen Envelopes

```rust
/// Erstellt einen neuen IdentityEnvelope mit aktuellen Daten.
/// Sollte alle 60-90 Tage oder bei signifikanten Änderungen aufgerufen werden.
fn refresh_own_envelope(
    self_did: &str,
    self_sk: &Ed25519SecretKey,
    current_contacts: &HashMap<String, TrustLevel>,
    old_envelope: Option<&IdentityEnvelope>,
) -> IdentityEnvelope {
    // 1. Neuen Pepper generieren
    let new_pepper: [u8; 32] = random_bytes();

    // 2. Neue Cuckoo-Filter bauen
    let filters = build_tiered_filters(current_contacts, &new_pepper);

    // 3. Version inkrementieren
    let new_version = old_envelope.map(|e| e.version + 1).unwrap_or(1);

    // 4. Envelope zusammenbauen und signieren
    let envelope = IdentityEnvelope {
        issuer_did: self_did.to_string(),
        version: new_version,
        epoch: current_timestamp(),
        pepper_commitment: sha256(&new_pepper),
        max_propagation_depth: 4,
        contact_count_range: quantize_count(current_contacts.len()),
        filters,
        signature: [0u8; 64], // Platzhalter
    };

    // 5. Signatur berechnen
    let payload = envelope.canonical_payload();
    let signature = ed25519_sign(self_sk, &payload);

    IdentityEnvelope { signature, ..envelope }
}

/// Quantisiert die Kontaktanzahl in Bereiche (Datenschutz).
fn quantize_count(exact: usize) -> (u16, u16) {
    match exact {
        0..=10     => (0, 15),
        11..=25    => (10, 30),
        26..=50    => (25, 75),
        51..=100   => (50, 150),
        101..=200  => (100, 250),
        201..=500  => (200, 600),
        _          => (500, 1000),
    }
}
```

---

## 8. Zusammenfassung der Berechnungslogik

| Aspekt | Mechanismus |
|---|---|
| **Trust-Score** | Multiplikatives Dämpfungsmodell: `T(P) = Π γᵢ` |
| **Effektives Limit** | Bottleneck-Prinzip: `min(BaseLimits) × T(P)` |
| **Pathfinding** | Modifizierter Dijkstra mit `-ln(γ)` Gewichten |
| **Multi-Path** | Bester Pfad + 20% Redundanz-Bonus für disjunkte Backup-Pfade |
| **Stufe 0** | Finanziell neutral (`γ = 0.0`), nur Sybil-Schutz |
| **Passive Revocation** | SD-JWT `exp`-Datum (30–90 Tage) |
| **Aktive Revocation** | RevocationAttestation (negatives SD-JWT), Gossip-Propagation |
| **Periodische Revocation** | Envelope-Epoch-Refresh (90 Tage), Pepper-Rotation |
| **Konsistenzmodell** | AP (Eventual Consistency), Freshness-Discount |
| **Graph-Wartung** | Tägliche Bereinigung: abgelaufene Attestations, stale Cache |
