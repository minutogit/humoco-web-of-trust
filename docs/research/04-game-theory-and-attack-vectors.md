# 04 — Game Theory & Attack Vectors

> **Projekt:** `human_money_core`
> **Autor:** Lead System Architect
> **Stand:** 2026-04-04
> **Status:** Forschungsdokument / Spieltheoretische Analyse
> **Abhängigkeiten:** Dokument 01–03

---

## 1. Das Netzwerk als Ökonomisches System

### 1.1 Der `did:key` als wirtschaftliches Asset

In `human_money_core` ist ein etablierter `did:key` kein bloßer kryptographischer Schlüssel — er ist ein **wirtschaftliches Asset** mit kumulativem Wert:

```
Wert eines did:key = f(Anzahl_Attestierungen, Tiefe_der_Stufen,
                       Netzwerk_Position, Alter, Transaktions_Historie)
```

| Asset-Dimension | Wertquelle |
|---|---|
| **Vertrauenskapital** | Mehr und höhere Trust-Attestierungen → höhere effektive Limits bei mehr Gegenparteien |
| **Netzwerk-Zentralität** | Eine zentrale Position im Graphen (Brückenperson zwischen Communities) → macht diesen Key zum bevorzugten Transitknoten |
| **Historische Reputation** | Ältere Keys mit langer, betrugsfreier Historie → Freshness-Discount wirkt sich weniger aus |
| **Haftungskapital** | Wer viele Stufe-3-Attestierungen vergeben hat, hat sich implizit für viele andere verbürgt → sozialer Druck, dieses Netzwerk zu schützen |

> **Kernthese:** Die Kosten, dieses Asset aufzubauen (Monate bis Jahre ehrlicher Netzwerkarbeit), sind **enorm höher** als die Kosten, einen neuen Key zu generieren (Millisekunden). Dieses Ungleichgewicht ist der **fundamentale Sybil-Schutz** des Systems.

### 1.2 Payoff-Matrix: Ehrliches vs. Unehrliches Verhalten

```
                         ┌────────────────────┬────────────────────┐
                         │  Netzwerk ist       │  Netzwerk ist      │
                         │  größtenteils       │  größtenteils      │
                         │  EHRLICH             │  UNEHRLICH          │
    ┌────────────────────┼────────────────────┼────────────────────┤
    │  Akteur handelt    │  HOHER PAYOFF       │  MODERATER PAYOFF  │
    │  EHRLICH           │  - Zugang zu großem │  - Eingeschränkter │
    │                    │    Markt (viele      │    Markt, aber     │
    │                    │    Akzeptanten)      │    eigenes Netzwerk│
    │                    │  - Wachsendes Asset  │    bleibt stabil   │
    │                    │  - Langfristiger     │                    │
    │                    │    Compound-Effekt   │                    │
    ├────────────────────┼────────────────────┼────────────────────┤
    │  Akteur handelt    │  KURZFR. GEWINN,   │  NIEDRIGER PAYOFF  │
    │  UNEHRLICH         │  LANGFR. VERLUST   │  - Niemand traut   │
    │                    │  - Einmalige Beute  │    niemandem        │
    │                    │  - Permanenter       │  - System kollabiert│
    │                    │    Verlust des       │  - Kein Markt      │
    │                    │    did:key-Assets   │                    │
    │                    │  - Soziale Isolation │                    │
    └────────────────────┴────────────────────┴────────────────────┘
```

**Nash-Gleichgewicht:** In einem Netzwerk mit überwiegend ehrlichen Teilnehmern ist *ehrliches Verhalten die dominante Strategie*, da:

1. Der Langfristgewinn aus Netzwerkzugang den kurzfristigen Betrugsgewinn übersteigt (solange die Trust-Limits die Betrugsbeute begrenzen).
2. Betrug zum Verlust des gesamten kumulierten `did:key`-Kapitals führt (Revocations propagieren, Reputation ist zerstört).
3. Ein neuer `did:key` nach einem Betrug praktisch bei Null beginnt (Cold Start).

---

## 2. Bootstrapping: Das Cold-Start-Problem

### 2.1 Das Dilemma

Ein neuer, ehrlicher Nutzer hat ein frisches `did:key` ohne jegliche Attestierungen. Er hat:
- Keine Trust Attestations in seinem Wallet
- Kein IdentityEnvelope (bzw. einen leeren)
- Ein effektives Limit von 0€ gegenüber allen

**Gleichzeitig** darf das Bootstrapping nicht so einfach sein, dass ein Angreifer massenweise neue Identitäten "bootstrappen" kann.

### 2.2 Die Vertrauensleiter (Graduated Trust Ladder)

Das Bootstrapping folgt einer strikten, zeitgesteuerten Stufenlogik:

```
┌─────────────────────────────────────────────────────────────────┐
│                    VERTRAUENSLEITER                              │
│                                                                 │
│  Stufe 3 ────── ▲ ── Nur durch langfristige Beziehung          │
│  (Vertrauter)   │    Mindestens 180 Tage seit Stufe 2           │
│                 │    + Mindestens 10 erfolgreiche Transaktionen  │
│                 │                                                │
│  Stufe 2 ────── ▲ ── Upgrade von Stufe 1 möglich                │
│  (Kontakt)      │    Mindestens 60 Tage seit Stufe 1            │
│                 │    + Mindestens 3 erfolgreiche Transaktionen   │
│                 │    + Issuer hat selbst ≥ 3 Stufe-2-Kanten     │
│                 │                                                │
│  Stufe 1 ────── ▲ ── Upgrade von Stufe 0 möglich                │
│  (Bekannter)    │    Mindestens 14 Tage seit Stufe 0            │
│                 │    + Mindestens 1 erfolgreiche Transaktion     │
│                 │    + Issuer hat selbst ≥ 5 Stufe-1-Kanten     │
│                 │                                                │
│  Stufe 0 ────── ▲ ── Face-to-Face Attestierung                  │
│  (Mensch)       │    Durch bestehenden Netzwerk-Teilnehmer       │
│                 │    Begrenzt auf MAX_STUFE0_PRO_MONAT           │
│                 │                                                │
│  Kein           │                                                │
│  Vertrauen ─────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Stufe 0: Der Einstiegspunkt

**Mechanismus:** Ein bestehender Netzwerk-Teilnehmer attestiert face-to-face: "Hinter diesem `did:key` steckt ein echter Mensch."

**Sicherungsmaßnahmen:**

1. **Rate Limiting:** Jeder Nutzer kann maximal `MAX_STUFE0_PRO_MONAT = 5` Stufe-0-Attestierungen pro Monat vergeben. Dies verhindert, dass ein einzelner Nutzer massenweise Identitäten "eintauchen" kann.

2. **Soziale Kosten der Stufe-0-Vergabe:** Wer Stufe 0 vergibt, bürgt implizit dafür, dass es sich um einen echten Menschen handelt. Wenn sich herausstellt, dass ein Stufe-0-Attestierter ein Bot ist:
   - Der Attestierer riskiert *sein eigenes* Reputationskapital.
   - Andere Netzwerk-Teilnehmer können den Attestierer herabstufen.
   - Das ist die spieltheoretische Kernmechanik: Stufe 0 "kostet" nichts an sich, aber das **Risiko der Falschattestierung ist nicht-trivial**.

3. **Multi-Source-Requirement:** Für den Aufstieg von Stufe 0 auf Stufe 1 benötigt man Stufe-0-Attestierungen von **mindestens 2 unabhängigen** Netzwerk-Teilnehmern. "Unabhängig" bedeutet: Die Attestierer haben keine gegenseitige Stufe-3-Verbindung (sie sind keine engsten Vertrauten — das verhindert, dass ein Ring seine eigenen Fake-IDs hochzieht).

```rust
/// Prüft ob ein Upgrade von Stufe 0 auf Stufe 1 erlaubt ist.
fn can_upgrade_to_level_1(
    subject_did: &str,
    graph: &LocalTrustGraph,
) -> Result<(), UpgradeBlocker> {
    // 1. Wie viele Stufe-0-Attestierungen hat der Subject?
    let level_0_attestors: Vec<&str> = graph.all_attestations_for(subject_did)
        .filter(|a| a.trust_level == TrustLevel::Existence)
        .map(|a| a.issuer_did.as_str())
        .collect();

    if level_0_attestors.len() < 2 {
        return Err(UpgradeBlocker::InsufficientAttestors {
            required: 2,
            actual: level_0_attestors.len(),
        });
    }

    // 2. Sind die Attestierer unabhängig?
    for i in 0..level_0_attestors.len() {
        for j in (i + 1)..level_0_attestors.len() {
            if are_intimate_contacts(level_0_attestors[i], level_0_attestors[j], graph) {
                return Err(UpgradeBlocker::AttestorsNotIndependent {
                    a: level_0_attestors[i].to_string(),
                    b: level_0_attestors[j].to_string(),
                });
            }
        }
    }

    // 3. Zeitgate: Mindestens 14 Tage seit der ersten Stufe-0-Attestierung
    let oldest_attestation = graph.all_attestations_for(subject_did)
        .filter(|a| a.trust_level == TrustLevel::Existence)
        .map(|a| a.issued_at)
        .min()
        .ok_or(UpgradeBlocker::NoAttestations)?;

    let age_days = (current_timestamp() - oldest_attestation) / 86400;
    if age_days < 14 {
        return Err(UpgradeBlocker::TimeGateNotMet {
            required_days: 14,
            actual_days: age_days as u32,
        });
    }

    // 4. Mindestens 1 erfolgreiche Transaktion
    let tx_count = graph.transaction_count_for(subject_did);
    if tx_count < 1 {
        return Err(UpgradeBlocker::InsufficientTransactions {
            required: 1,
            actual: tx_count,
        });
    }

    Ok(())
}

/// Prüft ob zwei DIDs Stufe-3-Kontakte sind (nicht unabhängig).
fn are_intimate_contacts(did_a: &str, did_b: &str, graph: &LocalTrustGraph) -> bool {
    graph.direct_edges.get(did_a)
        .map(|(level, _)| *level == TrustLevel::Confidant)
        .unwrap_or(false)
    || graph.direct_edges.get(did_b)
        .map(|(level, _)| *level == TrustLevel::Confidant)
        .unwrap_or(false)
}
```

### 2.4 Bootstrapping-Kosten für einen Angreifer

| Aktion | Kosten für Angreifer |
|---|---|
| `did:key` erstellen | ~0 (Millisekunden) |
| Stufe-0 erhalten | Physische Anwesenheit + Überzeugung eines echten Nutzers (oder Bestechung/Collusion mit einem bestehenden Nutzer) |
| Stufe-0 → Stufe-1 | 14 Tage warten + 2 unabhängige Attestierer + 1 echte Transaktion |
| Stufe-1 → Stufe-2 | 60 weitere Tage + 3 erfolgreiche Transaktionen + der Attestierer braucht selbst ≥ 3 Stufe-2-Kanten |
| Stufe-2 → Stufe-3 | 180 weitere Tage + 10 erfolgreiche Transaktionen |
| **Gesamtzeit: Null → Stufe 3** | **≥ 254 Tage** (~8.5 Monate) |

> **Fazit:** Ein einzelner Angreifer benötigt **8.5 Monate**, um einen einzigen Stufe-3-`did:key` aufzubauen — und das nur, wenn er reale Transaktionen durchführt und reale Menschen überzeugt. Das macht industriellen Sybil-Betrug extrem teuer.

---

## 3. Sybil-Attacken: Detailanalyse

### 3.1 Definition

Eine Sybil-Attacke in `human_money` bedeutet: Ein Angreifer erstellt viele `did:key`s und versucht, sie im Vertrauensnetzwerk zu platzieren, um:
1. Künstlich hohe Trust-Scores zu erzeugen
2. Gutscheine einzulösen, die er nie einlösen sollte
3. Das Netzwerk mit Fake-Knoten zu "verdünnen"

### 3.2 Sybil-Kosten-Analyse

Betrachten wir einen Angreifer, der `S` Sybil-Identitäten erstellen will:

```
KOSTEN-MODELL:

Für EINE Sybil-Identität mit Stufe 1:
  - 1× Face-to-Face mit einem echten Nutzer (physisch!)     → Zeitkosten: ~1h
  - Überzeugung/Bestechung des echten Nutzers                → Soziale/monetäre Kosten
  - 14 Tage Wartezeit                                        → Opportunitätskosten
  - 1× echte Transaktion                                     → Finanzielle Kosten
  - 2. unabhängiger Attestierer überzeugen                   → Verdopplung der sozialen Kosten

Für S Sybil-Identitäten:
  - S × physische Meetings mit VERSCHIEDENEN echten Nutzern
    (da jeder echte Nutzer nur 5 Stufe-0/Monat vergeben kann)
  - Mindestens S/5 verschiedene "Eintrittspaten" (echte Nutzer, die kolludieren)
  - S × 14 Tage Wartezeit (aber parallelisierbar → min. 14 Tage gesamt)
  - S echte Transaktionen

NUTZEN für den Angreifer:
  - S Sybil-IDs mit Stufe 1 → S × 50€ Basis-Limit
  - ABER: Diese Sybil-IDs können sich NICHT gegenseitig hochstufen
    (da sie keine Pfade ins ehrliche Netzwerk haben, die über sie selbst hinausgehen)
  - Effektiver Gewinn: S × 50€ × γ^(Distanz zum Opfer)
  - Bei Distanz 3: S × 50€ × 0.3³ = S × 1.35€ (!!!)
```

### 3.3 Break-Even-Analyse

```
Angenommen:
  - Kosten pro Sybil-ID (Stufe 1): 200€ (Zeitaufwand, Bestechung, etc.)
  - Gewinn pro Sybil-ID (einmaliger Betrug): 50€ × Dämpfung zum Opfer

Break-Even bei Stufe 1, Distanz 1:
  Gewinn = 50€
  Kosten = 200€
  → VERLUSTGESCHÄFT (4:1 gegen den Angreifer)

Break-Even bei Stufe 1, Distanz 3:
  Gewinn = 50€ × 0.3² = 4.50€  (nur 2 Hops Dämpfung, 
          da 1. Hop = direkt)
  Kosten = 200€
  → MASSIVES VERLUSTGESCHÄFT (44:1 gegen den Angreifer)

Für Break-Even müsste der Angreifer:
  Stufe 3, Distanz 1:
  Gewinn = 5.000€
  Kosten = 200€ + 254 Tage Zeitinvestment
  → Theoretisch profitabel, ABER:
    - 254 Tage Aufbauzeit (in denen der Angreifer auffliegen kann)
    - Die Revocation nach dem Betrug zerstört das gesamte
      8-Monate-Investment sofort
    - Der Betrogene (= der Stufe-3-Attestierer) wird zukünftig
      vorsichtiger → Netzwerk-Immunisierung
```

### 3.4 Wie Stufe 0 das Netzwerk schützt

Stufe 0 bildet eine **Firewall** zwischen dem Sybil-Netzwerk und dem echten Netzwerk:

```
                    ECHTES NETZWERK
          ┌────────────────────────────────┐
          │                                │
          │  Alice ──(3)── Bob ──(2)── Carol│
          │    │                    │       │
          │   (2)                  (1)      │
          │    │                    │       │
          │  Dave ──(3)── Eve ──(2)── Frank │
          │                                │
          └─────────────┬──────────────────┘
                        │
                    Stufe 0 (γ = 0.0)
                    ══════════════════
                    FIREWALL
                    ══════════════════
                        │
          ┌─────────────┴──────────────────┐
          │       SYBIL-NETZWERK           │
          │                                │
          │  Sybil_1 ─(3)─ Sybil_2         │
          │     │                │         │
          │    (3)              (3)         │
          │     │                │         │
          │  Sybil_3 ─(3)─ Sybil_4         │
          │                                │
          └────────────────────────────────┘

  Sybil-IDs können sich gegenseitig Stufe 3 geben,
  aber die Verbindung zum echten Netzwerk läuft
  IMMER über eine Stufe-0-Kante (γ = 0.0).

  → Effektives Limit für Sybil-zu-Echt: 0€
  → Die Sybil-IDs sind finanziell VOLLSTÄNDIG isoliert.
```

**Warum funktioniert das?**

1. Ein echter Nutzer wird einem Fremden nur Stufe 0 geben (nicht Stufe 1+), es sei denn, er kennt ihn länger.
2. Die Zeitgates verhindern ein schnelles Upgrade.
3. Selbst wenn ein Sybil-Knoten Stufe 1 erreicht, ist der Zugewinn marginal (50€ Basis × massive Dämpfung).

---

## 4. Collusion & Trust-Farming

### 4.1 Das Angriffsszenario

Eine Gruppe von `C` Betrügern erstellt echte Identitäten und baut über Monate hinweg gegenseitig hohes Vertrauen auf (Stufe 3). Dann versuchen sie, als scheinbar gut vernetzte Gruppe ins echte Netzwerk einzusickern.

```
COLLUSION RING (4 Angreifer):

    Mallory ──(3)── Victor ──(3)── Walter ──(3)── Trudy
       │                                           │
       └──────────────(3)──────────────────────────┘

Jeder Angreifer hat 3 Stufe-3-Kanten → sieht "gut vernetzt" aus.
```

### 4.2 Warum Collusion begrenzt wirkt

**1. Der Bottleneck-Effekt:**

Der Collusion-Ring ist intern stark vernetzt, aber seine Verbindung zum echten Netzwerk hängt an wenigen "Brücken-Kanten":

```
ECHTES NETZWERK                  COLLUSION RING
                                   
Alice ──(2)── Bob ──(1)── Mallory ──(3)── Victor
                          ↑
                    EINZIGE BRÜCKE
                    Stufe 1 (γ = 0.3)

Effektives Limit für Victor →→→ Alice:
  = min(50.000, 5.000, 500.000) × (0.6 × 0.3 × 0.85)
  = 5.000 × 0.153 = 765 ct (7.65€)

  Victors 3 Stufe-3-Kanten innerhalb des Rings helfen ihm
  NICHT — der Bottleneck ist die Stufe-1-Brücke zu Bob!
```

**2. Cluster-Detection-Heuristiken:**

Das Wallet kann verdächtige Cluster erkennen:

```rust
/// Erkennt verdächtige Clustering-Muster im lokalen Graphen.
fn detect_suspicious_clusters(graph: &LocalTrustGraph) -> Vec<SuspiciousCluster> {
    let mut clusters = Vec::new();

    // Heuristik 1: "Inzucht-Erkennung"
    // Suche nach Gruppen, die fast ausschließlich sich selbst
    // Stufe-3-Vertrauen geben und wenig Verbindungen nach außen haben.
    for (did_a, _, _) in graph.all_edges() {
        let neighbors_a = graph.neighbors_at_level(did_a, TrustLevel::Confidant);

        for neighbor_b in &neighbors_a {
            let neighbors_b = graph.neighbors_at_level(neighbor_b, TrustLevel::Confidant);

            // Überlappung berechnen
            let overlap: HashSet<_> = neighbors_a.intersection(&neighbors_b).collect();

            // Wenn > 80% der Stufe-3-Kontakte überlappen → verdächtig
            let overlap_ratio = overlap.len() as f64
                / neighbors_a.len().max(1) as f64;

            if overlap_ratio > 0.8 && neighbors_a.len() >= 3 {
                clusters.push(SuspiciousCluster {
                    members: overlap.into_iter().cloned().collect(),
                    overlap_ratio,
                    external_connections: count_external_edges(&overlap, graph),
                    risk_level: if overlap_ratio > 0.95 {
                        RiskLevel::High
                    } else {
                        RiskLevel::Medium
                    },
                });
            }
        }
    }

    clusters
}

/// Zählt die Kanten eines Clusters nach außen.
fn count_external_edges(
    cluster: &HashSet<&String>,
    graph: &LocalTrustGraph,
) -> usize {
    cluster.iter()
        .flat_map(|did| graph.all_edges_from(did))
        .filter(|(_, target, _)| !cluster.contains(target))
        .count()
}
```

**3. Die "Ratio of External Connections" (REC) Metrik:**

```
REC = Anzahl externer Kanten / Anzahl interner Kanten

Gesundes Netzwerk:
  - 150 Kontakte, davon 140 mit unterschiedlichen Communities verbunden
  - REC ≈ 140/10 = 14.0

Collusion Ring (4 Personen):
  - 6 interne Kanten (4 Personen × 3 Kanten / 2)
  - 1-2 externe Kanten
  - REC ≈ 1.5/6 = 0.25

→ REC < 1.0 ist ein starker Indikator für Collusion.
```

**4. Trust-Discount für verdächtige Cluster:**

Wenn ein Wallet einen verdächtigen Cluster erkennt, kann es einen **automatischen Discount** anwenden:

```rust
fn cluster_discount(cluster: &SuspiciousCluster) -> f64 {
    match cluster.risk_level {
        RiskLevel::Low    => 1.0,   // Kein Discount
        RiskLevel::Medium => 0.5,   // 50% Abwertung
        RiskLevel::High   => 0.1,   // 90% Abwertung
        RiskLevel::Critical => 0.0, // Vollständige Ablehnung
    }
}
```

### 4.3 Trust-Farming: Die langfristige Variante

**Szenario:** Ein raffinierter Angreifer baut über 12+ Monate eine echte Identität auf, erreicht Stufe 2–3 bei mehreren ehrlichen Nutzern, und schlägt dann einmal groß zu.

**Kosten des Trust-Farming:**

```
12 Monate × Zeitinvestment (~4h/Woche für Transaktionen, Meetings):
  = ~200h Zeitinvestment
  → Opportunitätskosten: ~5.000€ (bei Mindestlohn)

Plus:
  - Echte Transaktionen über 12 Monate (eigenes Geld einsetzen)
  - Soziale Beziehungen aufbauen und pflegen

MAXIMALER EINMALIGER GEWINN:
  - Stufe-3-Limit: 5.000€ pro Attestierer
  - Bei 5 Stufe-3-Attestierern: 5 × 5.000€ = 25.000€

  ABER: Nur wenn alle 5 Attestierer gleichzeitig
  betrogen werden, bevor die Revocations propagieren
  (~24h Fenster)

NET PAYOFF:
  25.000€ (Betrug) - 5.000€ (Zeitkosten) = 20.000€ einmalig
  VERSUS
  Permanenter Verlust des did:key-Assets
  + Soziale Ächtung
  + Alle zukünftigen Erträge aus dem Netzwerk = 0
```

**Spieltheoretische Analyse:**

Für einen rationalen Akteur, der plant, das System langfristig zu nutzen, ist der Erwartungswert des ehrlichen Verhaltens (unbegrenzte zukünftige Erträge) **immer höher** als der einmalige Betrugsgewinn — sofern die Trust-Limits nicht absurd hoch sind.

> **Designregel:** Die Trust-Limits (`base_acceptance_limit_cents`) müssen so kalibriert sein, dass der maximal mögliche einmalige Betrugsgewinn **deutlich unter** dem kumulierten Wert des `did:key`-Assets liegt.

### 4.4 Die dämpfende Wirkung der Haftung

Wenn Mallory betrügt und Alice den Schaden trägt, dann ist Alice motiviert:

1. **Sofort:** Mallory's Attestation widerrufen (→ Revocation propagiert).
2. **Indirekt:** Wer hat Mallory attestiert? Bob hat Mallory Stufe 1 gegeben. Alice kann Bob's Stufe herabsetzen (von 2 auf 1), da Bob einen Betrüger ins Netzwerk gelassen hat.
3. **Transitiv:** Bob ist jetzt motiviert, seine Attestierungs-Praxis zu verschärfen (er hat Reputationskapital verloren).

```
VOR BETRUG:
  Alice ──(2)── Bob ──(1)── Mallory
                                     └── (Betrug!)

NACH BETRUG:
  1. Alice widerruft: Mallory → REVOKED
  2. Alice degradiert: Bob: Stufe 2 → Stufe 1
     (Bob hat Mallory eingeführt, also hat Bob schlecht geurteilt)
  3. Bob lernt: "Nächstes Mal gebe ich Stufe 0 statt 1 an Unbekannte"

NETZWERK-IMMUNISIERUNG:
  - Mallory ist isoliert
  - Bob ist vorsichtiger
  - Alice' Verlust ist auf 50€ × γ gedeckelt
  - Das Netzwerk hat "gelernt", ähnliche Muster zu erkennen
```

**Dieses Muster ist analog zum biologischen Immunsystem:**
- **Erstinfektion:** Ein Angreifer richtet begrenzten Schaden an.
- **Immunantwort:** Das Netzwerk erkennt den Angriff und isoliert den Angreifer.
- **Immunisierung:** Die Attestierer, die den Angreifer eingeführt haben, werden selbst abgewertet → zukünftige Angreifer haben es schwerer.

---

## 5. Spezielle Angriffsvektoren

### 5.1 Eclipse Attack

**Angriff:** Ein Angreifer umgibt ein Opfer mit Sybil-Knoten, sodass alle Trust-Pfade des Opfers über Angreifer-kontrollierte Knoten laufen.

**Mitigation in human_money:**
- Trust-Attestierungen sind bilateral signiert. Der Angreifer müsste das Opfer davon überzeugen, *ihm* Stufe 2+ zu geben — nicht nur andersherum.
- Das Opfer hat seine eigenen, vorher etablierten Kontakte. Diese lassen sich nicht einfach "ersetzen".
- Die bidirektionale Intersection (Dok. 02) prüft Pfade von beiden Seiten. Wenn Alice' Seite des Graphen "echt" ist, kann kein Angreifer auf Bobs Seite das Ergebnis fälschen.

### 5.2 Replay Attack

**Angriff:** Ein Angreifer fängt ein gültiges SD-JWT ab und versucht, es als eigenes zu verwenden.

**Mitigation:**
- **Key Binding:** Jede SD-JWT-Präsentation erfordert eine frische Signatur mit dem privaten Schlüssel des Subjects. Ohne den privaten Schlüssel von Bob kann ein Angreifer Bobs SD-JWT nicht verwenden.
- **Nonce-basierte Challenge:** Die Nonces aus Phase 1 (Beacon) verhindern, dass alte Handshakes wiederholt werden.

### 5.3 Guilt-by-Association (Kettenreaktion)

**Angriff:** Nachdem Mallory betrügt, degradiert ihr gesamtes Netzwerk. Unschuldige Kontakte von Mallory verlieren Reputationskapital.

**Mitigation:**
- Die Degradierung ist **nicht automatisch** — sie ist eine bewusste Entscheidung des Geschädigten (Alice).
- **Proportionalität:** Best Practice: Die Degradierung des Attestierers (Bob) ist maximal 1 Stufe. Blindes "Guilt by Association" über 2+ Hops wird nicht empfohlen und läuft dem Eigeninteresse entgegen (man isoliert sich selbst).
- **Natürliche Erholung:** Durch das `exp`-System können degradierte Kontakte über Zeit ihre Stufe wiederherstellen, wenn sie sich weiterhin ehrlich verhalten.

### 5.4 Vampire Attack (Key Rotation Abuse)

**Angriff:** Ein Nutzer generiert einen neuen `did:key`, bittet alle Kontakte um erneute Attestierung, und hat so zwei "Identitäten" — die alte und die neue.

**Mitigation:**
- **Key Rotation Protocol:** Bei einer legitimen Key-Rotation signiert der alte Key ein "Successor Attestation" für den neuen Key. Alle bestehenden Attestierungen werden auf den neuen Key übertragen.
- **Ohne Successor Attestation:** Der neue Key beginnt bei Null. Das macht den "Vampire Attack" zum reinen Cold-Start-Problem.

```rust
/// Successor-Attestierung für Key-Rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySuccessorAttestation {
    /// Der alte, zu ersetzende DID.
    pub old_did: String,
    /// Der neue DID.
    pub new_did: String,
    /// Grund der Rotation.
    pub reason: KeyRotationReason,
    /// Signatur mit dem ALTEN privaten Schlüssel.
    pub old_key_signature: [u8; 64],
    /// Signatur mit dem NEUEN privaten Schlüssel.
    pub new_key_signature: [u8; 64],
    /// Zeitstempel.
    pub rotated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRotationReason {
    /// Reguläre Rotation (Sicherheitshygiene).
    Routine,
    /// Verdacht auf Kompromittierung des alten Schlüssels.
    Compromise,
    /// Gerätewechsel.
    DeviceMigration,
}
```

### 5.5 Long-Range Attack (Zombie Attestations)

**Angriff:** Ein Angreifer sammelt über Jahre alte (aber noch nicht abgelaufene) SD-JWTs und nutzt sie in einer einzigen Transaktionssitzung.

**Mitigation:**
- **Freshness-Discount** (Dok. 03): Attestierungen, die älter als 7 Tage sind, werden progressiv abgewertet.
- **Short-Lived Tokens:** Empfehlung: `exp` auf 30 Tage setzen. SD-JWTs, die älter als 30 Tage sind, werden grundsätzlich nicht akzeptiert.
- **Epoch-Check:** Der Verify-Algorithmus prüft, ob der `iat`-Zeitstempel des SD-JWTs zum aktuellen Epoch des Issuer-Envelopes passt. Wenn der Issuer seinen Envelope seit dem `iat` aktualisiert hat (neuer Pepper), ist das SD-JWT suspekt.

---

## 6. Ökonomische Gleichgewichtsanalyse

### 6.1 Das Grundmodell

Wir modellieren das Verhalten eines rationalen Akteurs als wiederholtes Spiel (Infinite Iterated Game):

```
In jeder Runde t:
  - Der Akteur wählt: EHRLICH oder BETRÜGEN
  - Ehrlich: Gewinn = V_t (wachsender Netzwerkzugang, V_t > V_{t-1})
  - Betrügen: Gewinn = B (einmaliger Betrugsgewinn) - C (Reputation zerstört)
  - Nach Betrug: Alle zukünftigen V_t = 0 (Isolation)

Ehrlicher Erwartungswert:
  E[EHRLICH] = Σ (t=0..∞) δᵗ × V_t
             = V₀ / (1 - δ)  (für konstantes V)
             wobei δ = Diskontfaktor (< 1)

Betrügerischer Erwartungswert:
  E[BETRÜGEN in Runde T] = Σ (t=0..T-1) δᵗ × V_t + δᵀ × B
                         = "Ehrliche Erträge bis T" + "Einmaliger Betruggeinn"

Ehrlichkeit ist dominant, wenn für alle T:
  E[EHRLICH] > E[BETRÜGEN in T]
  ⟺ Σ (t=T+1..∞) δᵗ × V_t > δᵀ × B
  ⟺ Die diskontierten zukünftigen Erträge > der diskontierte Betrugsgewinn
```

### 6.2 Kalibriering der Trust-Limits

Die Trust-Limits müssen so gewählt werden, dass die obige Ungleichung für realistische Diskontfaktoren (δ ≈ 0.95–0.99) und Betrugsgewinne hält:

```
Angenommen:
  - Monatlicher Nutzen des Netzwerks (Transaktionsvolumen): 500€/Monat
  - Diskontfaktor: δ = 0.98 (pro Monat)
  - Maximaler Betrugsgewinn (5 × Stufe-3-Limit): 25.000€

E[EHRLICH, ab Monat T] = 500 / (1 - 0.98) = 25.000€

→ Ab dem Zeitpunkt, wo der Akteur 25.000€ zukünftigen Nutzen
  aus dem Netzwerk erwartet, ist Ehrlichkeit dominant.

→ Das ist ungefähr der Zeitpunkt, wo der did:key-Asset-Wert
  den maximalen Betrugsgewinn erreicht = ~50 Monate ≈ 4 Jahre.

ABER: Für die meisten Akteure setzt der Netzwerkeffekt viel
früher ein (wenige Monate), und der Betrugsgewinn ist durch
die Stufen-Limits gedeckelt.
```

### 6.3 Der Compound-Effekt

Das Vertrauenskapital unterliegt einem **Compound-Effekt**: Jede neue ehrliche Transaktion und jede erneuerte Attestierung stärkt den `did:key` marginal, was zu besseren Limits und mehr Transaktionsmöglichkeiten führt, was wiederum zu mehr Attestierungen führt:

```
Netzwerkeffekt:
  Mehr Vertrauen → Mehr Transaktionen → Mehr Beweise → Mehr Vertrauen
                    ↑                                    │
                    └────────────────────────────────────┘
                         POSITIVER FEEDBACK-LOOP

Der Kosten-Nutzen des Betrugs:
  Betrug = EINMALIGER Gewinn + PERMANENTER Verlust des Compound-Effekts

  Da der Compound-Effekt exponentiell wächst, übersteigt sein
  langfristiger Wert jeden einmaligen Betrugsgewinn — solange
  der Akteur rational und nicht extrem kurzsichtig handelt.
```

---

## 7. Zusammenfassung der Sicherheitseigenschaften

| Angriffsvektor | Schwierigkeit | Maximaler Schaden | Hauptmitigation |
|---|---|---|---|
| **Sybil (Masse)** | Hoch (physische Meetings, Rate Limit) | Marginal (Stufe-0-Firewall, γ=0.0) | Stufe-0-Rate-Limit, Multi-Source-Req., Zeitgates |
| **Sybil (Einzeln)** | Mittel (14+ Tage, 2 Attestierer) | 50€ (Stufe 1 Basis) × Dämpfung | Zeitgates, Multi-Source-Requirement |
| **Collusion Ring** | Hoch (8.5+ Monate pro Teilnehmer) | Durch Bottleneck gedeckelt | Cluster-Detection, REC-Metrik, Bottleneck |
| **Trust Farming** | Sehr hoch (12+ Monate) | Bis zu Stufe-3-Limit × Attestierer | Haftungsprinzip, Compound-Effekt-Verlust |
| **Eclipse** | Sehr hoch (muss Opfer überzeugen) | Variabel | Bidirektionale Intersection, eigene Kontakte |
| **Replay** | Unmöglich | 0 | Key Binding, Nonces |
| **Vampire** | Mittel (neuer Key = Cold Start) | Doppelte Identität | Key Successor Attestation |
| **Zombie Attestations** | Niedrig | Durch Freshness-Discount begrenzt | exp-Datum, Freshness-Discount, Epoch-Check |

---

## 8. Design-Empfehlungen

1. **Trust-Limits konservativ kalibrieren.** Lieber zu niedrig als zu hoch. Die Limits können über Netzwerk-Updates erhöht werden, aber zu hohe Limits machen Betrug profitabel.

2. **Zeitgates strikt durchsetzen.** Sie sind die primäre Verteidigung gegen schnelle Sybil-Angriffe. 14 Tage für Stufe 0→1 ist das Minimum.

3. **Haftung sichtbar machen.** Das Wallet sollte Nutzer warnen: "Wenn Sie X Stufe 3 geben, bürgen Sie effektiv für bis zu 5.000€ an Gutscheinen von X." Das schafft Awareness für die Konsequenzen.

4. **Cluster-Detection automatisieren.** Das Wallet sollte im Hintergrund verdächtige Muster erkennen und den Nutzer warnen, bevor er Gutscheine von verdächtigen Clustern akzeptiert.

5. **Cold-Start durch lokale Communities erleichtern.** Statt auf individuelles Bootstrapping zu setzen, können lokale Events (Marktplätze, Stammtische, Onboarding-Events) viele neue Nutzer gleichzeitig einführen. Das schafft sofort ein dichtes lokales Netzwerk.

6. **Den "Verlust des did:key-Assets" kommunizieren.** Nutzer müssen verstehen, dass ihr `did:key` ein wertvolles Asset ist, das sie durch Betrug unwiederbringlich verlieren. Diese Kommunikation ist ebenso wichtig wie die technischen Mechanismen.
