# 02 — Stranger Discovery Protocol

> **Projekt:** `human_money_core`
> **Autor:** Lead System Architect
> **Stand:** 2026-04-04
> **Status:** Forschungsdokument / Protokoll-Design
> **Abhängigkeiten:** Dokument 01 (Datenstrukturen)

---

## 1. Das Problem: Stranger Discovery

Alice betreibt einen Marktstand. Bob ist Tourist. Beide haben noch nie voneinander gehört. Bob möchte mit einem `human_money`-Gutschein bezahlen. Weder Alice noch Bob haben Internet. Sie kommunizieren über **Bluetooth Low Energy (BLE)** oder **NFC**.

**Die zentrale Frage:** Wie können Alice und Bob in wenigen Sekunden feststellen, ob ein Vertrauenspfad zwischen ihnen existiert — und diesen kryptographisch beweisen?

### 1.1 Annahmen und Randbedingungen

| Parameter | Wert |
|---|---|
| Kommunikationskanal | BLE (max ~1 Mbit/s effektiv) oder NFC (~424 Kbit/s) |
| Maximale akzeptable Latenz | < 10 Sekunden für den gesamten Handshake |
| Maximale Pfadlänge | 5 Hops (darüber hinaus: Trust-Score zu niedrig) |
| Daten im Wallet von Bob | Eigene Envelopes, ~50 Envelopes seiner Freunde, ~200 SD-JWT Trust Attestations |
| Daten im Wallet von Alice | Eigene Envelopes, ~50 Envelopes ihrer Freunde, ~200 SD-JWT Trust Attestations |
| Typische Envelope-Größe | ~800 Bytes (→ Dok. 01, Abschnitt 7) |

---

## 2. Protokoll-Überblick: Die 5 Phasen

```
┌─────────────────────────────────────────────────────────────────┐
│                  STRANGER DISCOVERY PROTOCOL                    │
│                                                                 │
│  Phase 1: BEACON         (DID-Austausch + Nonce)        ~100ms  │
│  Phase 2: INTERSECTION   (Cuckoo-Filter-Abgleich)       ~500ms  │
│  Phase 3: PROOF ATTACH   (SD-JWT-Kette zusammenstellen) ~200ms  │
│  Phase 4: VERIFICATION   (Pfad kryptographisch prüfen)  ~300ms  │
│  Phase 5: AUTHORIZATION  (Transaktion autorisieren)      ~100ms  │
│                                                                 │
│  Gesamtlatenz (optimistisch, 3-Hop-Pfad):              ~1.2s   │
│  Gesamtlatenz (pessimistisch, 5-Hop-Pfad):              ~3.5s   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1: BEACON (DID-Austausch)

### 3.1 Zweck
Beide Parteien tauschen ihre `did:key`s und eine frische, zufällige Nonce aus. Die Nonce dient als Challenge für das spätere Key Binding (Beweis des Schlüsselbesitzes).

### 3.2 Nachrichten

```
Alice → Bob:
┌──────────────────────────────────────────────┐
│  BeaconMessage                               │
│  ├── alice_did: "did:key:z6Mk...Alice"       │
│  ├── nonce_alice: [u8; 32]  (random)         │
│  ├── role: "RECEIVER" (Alice empfängt Zahlung)│
│  ├── requested_amount_cents: 1500  (15€)     │
│  └── protocol_version: 1                     │
└──────────────────────────────────────────────┘

Bob → Alice:
┌──────────────────────────────────────────────┐
│  BeaconMessage                               │
│  ├── bob_did: "did:key:z6Mk...Bob"           │
│  ├── nonce_bob: [u8; 32]  (random)           │
│  ├── role: "PAYER" (Bob bezahlt)             │
│  └── protocol_version: 1                     │
└──────────────────────────────────────────────┘
```

### 3.3 Sofort-Check: Lokaler Graph

Nach dem DID-Austausch prüft jede Partei sofort ihren lokalen Graphen:

```rust
// Pseudocode auf Bobs Seite
match bob.local_graph.direct_edges.get(&alice_did) {
    Some((level, attestation)) => {
        // Direkter Kontakt! Phase 2+3 überspringen → direkt zu Phase 4
        return Phase4::direct_proof(attestation);
    },
    None => {
        // Alice ist kein direkter Kontakt → Phase 2 starten
    }
}
```

**→ Fast Path:** Wenn Alice und Bob direkte Kontakte sind, reduziert sich der gesamte Handshake auf ~200ms (Beacon + Direct Proof + Authorization).

---

## 4. Phase 2: INTERSECTION (Bidirektionaler Cuckoo-Filter-Abgleich)

### 4.1 Das Kernproblem

Bob kennt Alice nicht direkt. Er muss herausfinden, ob es eine **Brückenperson** gibt — jemanden, der sowohl in Bobs als auch in Alices Vertrauensnetzwerk präsent ist.

**Ansatz: Bidirektionale Suche.** Statt von einem Ende zum anderen zu suchen, suchen beide Seiten gleichzeitig von ihrer Seite aus und treffen sich in der Mitte.

### 4.2 Pepper-Austausch via X25519 ECDH

Bevor die Cuckoo-Filter abgefragt werden können, müssen Bob und Alice die Pepper ihrer jeweiligen Filter kennen. Diese werden **nicht im Klartext** übertragen, sondern über einen ephemeren Diffie-Hellman-Schlüsselaustausch gesichert:

```
1. Alice generiert ephemeres X25519-Keypair: (alice_eph_pk, alice_eph_sk)
2. Bob generiert ephemeres X25519-Keypair: (bob_eph_pk, bob_eph_sk)
3. Austausch der öffentlichen Schlüssel über BLE
4. Beide berechnen: shared_secret = X25519(own_sk, other_pk)
5. Ableitung: encryption_key = HKDF-SHA256(shared_secret, "pepper-exchange")
6. Alice sendet: ChaCha20-Poly1305(encryption_key, alice_pepper)
7. Bob sendet: ChaCha20-Poly1305(encryption_key, bob_pepper)
```

> **Warum nicht die Ed25519-Keys direkt?** Ed25519 und X25519 verwenden zwar dieselbe Kurve (Curve25519), aber Ed25519-Keys sind für Signaturen optimiert, nicht für DH. Die Konvertierung `Ed25519 → X25519` ist möglich (und wird in libsodium's `crypto_sign_ed25519_pk_to_curve25519` implementiert), aber es ist kryptographisch sauberer, ephemere X25519-Keys zu verwenden — sie bieten **Forward Secrecy** (ein kompromittierter Langzeit-Key kompromittiert keine vergangenen Handshakes).

### 4.3 Der Intersection-Algorithmus

```
┌──────────────────────────────────────────────────────────────────┐
│                     BIDIRECTIONAL INTERSECTION                    │
│                                                                  │
│  BOB's Wallet                          ALICE's Wallet            │
│  ┌────────────┐                        ┌────────────┐            │
│  │ Bob's       │                        │ Alice's    │            │
│  │ Envelope    │                        │ Envelope   │            │
│  └─────┬──────┘                        └─────┬──────┘            │
│        │                                      │                   │
│  ┌─────▼──────┐                        ┌─────▼──────┐            │
│  │ Envelope   │                        │ Envelope   │            │
│  │ von Carol  │                        │ von Dave   │            │
│  └─────┬──────┘                        └─────┬──────┘            │
│        │                                      │                   │
│  ┌─────▼──────┐                        ┌─────▼──────┐            │
│  │ Envelope   │                        │ Envelope   │            │
│  │ von Eve    │                        │ von Frank  │            │
│  └────────────┘                        └────────────┘            │
│                                                                  │
│  Frage an Alice: "Sind Carol oder Eve in einem deiner Filter?"   │
│  Frage an Bob:   "Sind Dave oder Frank in einem deiner Filter?"  │
│                                                                  │
│  → Treffer: Carol ist in Daves Filter (Stufe 2)!                │
│  → Pfad: Bob → Carol → Dave → Alice                             │
└──────────────────────────────────────────────────────────────────┘
```

### 4.4 Protokoll-Nachrichten für Phase 2

**Runde 1: Austausch der Suchmengen**

Jede Seite sendet die `did:key`s ihrer direkten Kontakte (und ggf. 2-Hop-Kontakte, falls aus lokalen Envelopes bekannt) als kompakte Liste:

```
Bob → Alice:
┌──────────────────────────────────────────────────────────┐
│  IntersectionRequest                                     │
│  ├── ephemeral_x25519_pk: [u8; 32]                      │
│  ├── encrypted_pepper: [u8; 32+16]  (Pepper + AuthTag)  │
│  ├── search_set: [                                       │
│  │     "did:key:z6Mk...Carol",   // Bobs Stufe-3-Kontakt│
│  │     "did:key:z6Mk...Eve",     // Bobs Stufe-2-Kontakt│
│  │     "did:key:z6Mk...Gina",    // Bobs Stufe-1-Kontakt│
│  │     // ... (max 50 DIDs, priorisiert nach Stufe)      │
│  │   ]                                                   │
│  └── max_depth: 2  (Bob sucht bis Distanz 2 von sich)   │
└──────────────────────────────────────────────────────────┘
```

> **Datenschutz-Abwägung:** Bob offenbart hier die `did:key`s seiner Kontakte an Alice. Das ist ein bewusster Trade-off: Bob zeigt *seine* Kontakte, nicht deren Kontakte. Alice erfährt maximal, wen Bob kennt — nicht, wen Bobs Kontakte kennen (das ist in den Cuckoo-Filtern verborgen).
>
> **Mitigation:** Bob kann die Suchmenge auf seine engsten Kontakte (Stufe 2+3) beschränken, um die Exposition zu minimieren. Die Suchmenge wird nach Trust-Level absteigend priorisiert.

**Runde 1 (parallel): Alice sendet dasselbe an Bob**

```
Alice → Bob:
┌──────────────────────────────────────────────────────────┐
│  IntersectionRequest (analog zu Bobs Nachricht)          │
│  ├── ephemeral_x25519_pk: [u8; 32]                      │
│  ├── encrypted_pepper: [u8; 32+16]                       │
│  ├── search_set: [                                       │
│  │     "did:key:z6Mk...Dave",    // Alice' Stufe-3       │
│  │     "did:key:z6Mk...Frank",   // Alice' Stufe-2       │
│  │     // ...                                            │
│  │   ]                                                   │
│  └── max_depth: 2                                        │
└──────────────────────────────────────────────────────────┘
```

**Runde 2: Lokale Filter-Abfrage und Antwort**

Jede Seite empfängt die Suchmenge der anderen, entschlüsselt den Pepper, und prüft gegen ihre lokalen Cuckoo-Filter:

```rust
// Alice empfängt Bobs search_set und prüft:
fn intersection_check(
    bob_search_set: &[String],
    alice_pepper: &[u8; 32],
    alice_envelopes: &HashMap<String, IdentityEnvelope>,
) -> Vec<IntersectionHit> {
    let mut hits = Vec::new();

    for bob_contact_did in bob_search_set {
        // 1. Ist bob_contact_did direkt in Alice' eigenem Envelope?
        if let Some(level) = alice_own_envelope.filters.query(bob_contact_did, alice_pepper) {
            hits.push(IntersectionHit {
                bridge_did: bob_contact_did.clone(),
                found_in_envelope_of: alice_did.clone(),
                trust_level: level,
                distance_from_alice: 1,
            });
            continue;
        }

        // 2. Ist bob_contact_did in einem von Alice' gespeicherten Envelopes?
        for (envelope_issuer, envelope) in alice_envelopes.iter() {
            // Alice braucht den Pepper des jeweiligen Envelope-Issuers!
            // Diesen hat sie nur, wenn sie direkt mit dem Issuer verbunden ist.
            if let Some(issuer_pepper) = alice_pepper_cache.get(envelope_issuer) {
                if let Some(level) = envelope.filters.query(bob_contact_did, issuer_pepper) {
                    hits.push(IntersectionHit {
                        bridge_did: bob_contact_did.clone(),
                        found_in_envelope_of: envelope_issuer.clone(),
                        trust_level: level,
                        distance_from_alice: 2,
                    });
                }
            }
        }
    }

    // Sortierung: Höchste Vertrauensstufe × kürzeste Distanz zuerst
    hits.sort_by(|a, b| {
        let score_a = a.trust_level.damping_factor() / (a.distance_from_alice as f64);
        let score_b = b.trust_level.damping_factor() / (b.distance_from_alice as f64);
        score_b.partial_cmp(&score_a).unwrap()
    });

    hits
}
```

**Antwort-Nachricht:**

```
Alice → Bob:
┌──────────────────────────────────────────────────────────┐
│  IntersectionResponse                                    │
│  ├── hits: [                                             │
│  │     {                                                 │
│  │       bridge_did: "did:key:z6Mk...Carol",             │
│  │       found_in_envelope_of: "did:key:z6Mk...Dave",   │
│  │       trust_level: 2,  // Carol in Daves Stufe 2     │
│  │       distance_from_alice: 2                          │
│  │     },                                                │
│  │     // ... weitere Treffer                            │
│  │   ]                                                   │
│  └── total_hits: 1                                       │
└──────────────────────────────────────────────────────────┘
```

### 4.5 Kein Treffer? — Erweiterte Suche (Round 3)

Wenn Runde 2 keine Treffer ergibt, können Alice und Bob die Suche erweitern:

1. **Envelope-Austausch:** Bob sendet die Envelopes seiner engsten Kontakte (Stufe 3) an Alice, und umgekehrt. Alice kann nun die Filter von Bobs Stufe-3-Kontakten gegen *ihre* 2-Hop-Kontakte prüfen → effektive Suchtiefe: 4 Hops.

2. **Größe des Austauschs:** 5 Envelopes × 800 Bytes = 4 KB — über BLE in ~40ms übertragbar.

3. **Maximale Runden:** 3 Runden (→ maximale Suchtiefe: 6 Hops). Ab Hop 5 ist der Trust-Score ohnehin so niedrig, dass er für die meisten Transaktionen irrelevant ist.

```
Runde 1: Suchmenge (DIDs) austauschen         → 2 Hops
Runde 2: Antwort + ggf. Envelopes austauschen → 4 Hops
Runde 3: Erneute Suche mit erweiterten Daten  → 6 Hops
```

### 4.6 Scheitern der Intersection

Wenn nach 3 Runden kein Pfad gefunden wird:

```
Alice → Bob:
┌──────────────────────────────────────────────┐
│  IntersectionResult::NoPath                  │
│  ├── reason: "No trust path found within     │
│  │    6 hops"                                │
│  └── suggested_action: "BUILD_NEW_EDGE"      │
│       → Alice kann Bob Stufe 0 (Existence)   │
│         geben, wenn sie face-to-face steht   │
└──────────────────────────────────────────────┘
```

**→ Fallback: Bootstrap** (siehe Dok. 04, Bootstrapping-Problem).

---

## 5. Phase 3: PROOF ATTACHMENT (SD-JWT-Kettenaufbau)

### 5.1 Problem

Die Intersection hat einen Pfad gefunden:
```
Bob → Carol → Dave → Alice
```

Aber bisher sind das nur Filter-Treffer (probabilistisch!). Alice braucht **kryptographische Beweise** für jede Kante:

1. **Carol vertraut Bob (Stufe 3):** Bob hat ein SD-JWT von Carol in seinem Wallet.
2. **Dave vertraut Carol (Stufe 2):** Carol hat ein SD-JWT von Dave — aber Carol ist nicht hier!
3. **Alice vertraut Dave (Stufe 2):** Alice weiß das selbst (eigene direkte Kante).

### 5.2 Das Receiver Principle: Beweisketten vorbereiten

Das **Receiver Principle** besagt: Jeder Empfänger einer Trust Attestation (SD-JWT) trägt den Beweis in seinem eigenen Wallet. Wenn Carol ein SD-JWT von Dave hat, dann hat Carol diesen Beweis. Aber Bob braucht diesen Beweis jetzt — und Carol ist nicht da.

**Lösung: Forwarded Attestations (Transitive Beweiskette)**

Carol gibt Bob nicht nur das SD-JWT *von Carol an Bob* (das hat Bob sowieso), sondern auch eine **weitergeleitete Kopie** des SD-JWTs *von Dave an Carol*. Carol hat dieses SD-JWT in ihrem Wallet. Beim letzten Sync mit Bob hat sie es ihm weitergegeben — zusammen mit der selektiven Disclosure, die Bob für den Fall eines Handshakes braucht.

```
Bobs Wallet enthält (vorbereitet):
┌──────────────────────────────────────────────────────────┐
│  TrustChainBundle (für potenzielle Pfade über Carol)     │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Kante 1: Carol → Bob  (SD-JWT)                   │  │
│  │  ├── issuer: Carol's did:key                      │  │
│  │  ├── subject: Bob's did:key                       │  │
│  │  ├── trust_level_disclosure: "3"  (offengelegt)   │  │
│  │  └── exp: 2026-05-04                              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Kante 2: Dave → Carol  (Forwarded SD-JWT)        │  │
│  │  ├── issuer: Dave's did:key                       │  │
│  │  ├── subject: Carol's did:key                     │  │
│  │  ├── trust_level_disclosure: "2"  (offengelegt)   │  │
│  │  ├── forwarded_by: Carol's did:key                │  │
│  │  ├── forwarding_signature: Ed25519(Carol, ...)    │  │
│  │  └── exp: 2026-04-15                              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  Fehlende Kante: Alice → Dave                            │
│  (Bob hat keinen Beweis dafür; Alice muss das selbst     │
│   bestätigen — sie kennt Dave ja direkt.)                │
└──────────────────────────────────────────────────────────┘
```

### 5.3 Nachricht: Proof Bundle

```
Bob → Alice:
┌──────────────────────────────────────────────────────────┐
│  ProofBundle                                             │
│  ├── claimed_path: [                                     │
│  │     "did:key:z6Mk...Bob",                             │
│  │     "did:key:z6Mk...Carol",                           │
│  │     "did:key:z6Mk...Dave",                            │
│  │     "did:key:z6Mk...Alice"                            │
│  │   ]                                                   │
│  ├── attestations: [                                     │
│  │     SD-JWT(Carol → Bob, trust=3),                     │
│  │     SD-JWT(Dave → Carol, trust=2, forwarded by Carol) │
│  │   ]                                                   │
│  ├── key_binding_proof: Ed25519(Bob_SK,                  │
│  │     nonce_alice || nonce_bob || "PAYER")               │
│  └── transaction_context: {                              │
│        amount_cents: 1500,                               │
│        voucher_issuer_did: "did:key:z6Mk...Bob",         │
│        timestamp: 1743724800                             │
│      }                                                   │
└──────────────────────────────────────────────────────────┘
```

### 5.4 Die Forwarding-Autorisierung

Ein kritischer Sicherheitsaspekt: Darf Carol das SD-JWT von Dave einfach an Bob weiterleiten?

**Ja, mit Einschränkungen:**

1. **Carol signiert die Weiterleitung:** Die `forwarding_signature` beweist, dass Carol (und nicht ein Dritter) das SD-JWT autorisiert weitergegeben hat.

2. **Propagationsregel:** Ein SD-JWT vom Typ `TrustAttestation` enthält ein optionales Feld `max_forwarding_depth`. Dave kann festlegen, ob sein SD-JWT an Carol überhaupt weitergeleitet werden darf:
   - `max_forwarding_depth: 0` → Nicht weiterleiten (nur zwischen Dave und Carol verwendbar).
   - `max_forwarding_depth: 1` → Carol darf es an *eine* weitere Person weiterleiten.
   - `max_forwarding_depth: 2` → Zwei Stufen Weiterleitung erlaubt.

3. **Default:** `max_forwarding_depth: 2` (erlaubt 2-Hop-Beweisketten, die für die meisten Pfade ausreichen).

```rust
/// Erweiterung der TrustAttestation für Forwarding-Fähigkeit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardableTrustAttestation {
    /// Das originale SD-JWT.
    pub attestation: TrustAttestation,

    /// Maximale Weiterleitungstiefe (vom Issuer festgelegt).
    /// 0 = nicht weiterleitbar, 1 = eine Stufe, etc.
    pub max_forwarding_depth: u8,

    /// Aktuelle Weiterleitungstiefe (inkrementiert bei jeder Forwarding).
    pub current_forwarding_depth: u8,

    /// Kette der Forwarding-Signaturen.
    /// Jeder Forwarder signiert: (original_sd_jwt_hash || forwarder_did || recipient_did)
    pub forwarding_chain: Vec<ForwardingLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingLink {
    /// DID des Forwarders.
    pub forwarder_did: String,
    /// DID des Empfängers.
    pub recipient_did: String,
    /// Signatur des Forwarders.
    pub signature: [u8; 64],
    /// Zeitstempel der Weiterleitung.
    pub forwarded_at: u64,
}
```

---

## 6. Phase 4: VERIFICATION (Pfad-Verifikation)

### 6.1 Alice prüft den Proof Bundle

Alice führt folgende Schritte für jede Attestation in der Kette durch:

```rust
fn verify_proof_bundle(
    bundle: &ProofBundle,
    alice_graph: &LocalTrustGraph,
    nonce_alice: &[u8; 32],
    nonce_bob: &[u8; 32],
) -> Result<VerifiedPath, VerificationError> {

    let path = &bundle.claimed_path;
    let bob_did = &path[0];
    let alice_did = path.last().unwrap();

    // 1. Key Binding: Beweist Bob, dass er den privaten Schlüssel besitzt?
    let expected_message = [nonce_alice, nonce_bob, b"PAYER"].concat();
    let bob_pubkey = resolve_ed25519_pubkey(bob_did)?;
    ed25519_verify(&bob_pubkey, &expected_message, &bundle.key_binding_proof)?;

    // 2. Pfad-Validierung: Jede Kante einzeln prüfen
    let mut min_trust_level = TrustLevel::Confidant; // Worst case = best
    let mut accumulated_damping = 1.0_f64;

    for i in 0..path.len() - 1 {
        let from_did = &path[i];
        let to_did = &path[i + 1];

        let edge_trust = if to_did == alice_did {
            // Letzte Kante: Alice → vorheriger Hop.
            // Alice überprüft dies aus ihrem eigenen Graphen.
            alice_graph.direct_edges.get(from_did)
                .map(|(level, _)| *level)
                .ok_or(VerificationError::MissingEdge(from_did.clone(), to_did.clone()))?
        } else {
            // Mittlere Kanten: Aus dem ProofBundle.
            let attestation = bundle.find_attestation(to_did, from_did)?;
            verify_attestation(attestation)?
        };

        // 3. Dämpfung akkumulieren
        accumulated_damping *= edge_trust.damping_factor();
        if edge_trust < min_trust_level {
            min_trust_level = edge_trust;
        }
    }

    // 4. Effektives Limit berechnen
    let effective_limit = (min_trust_level.base_acceptance_limit_cents() as f64
                          * accumulated_damping) as u64;

    // 5. Prüfen ob Transaktionsbetrag innerhalb des Limits
    if bundle.transaction_context.amount_cents > effective_limit {
        return Err(VerificationError::InsufficientTrust {
            required: bundle.transaction_context.amount_cents,
            available: effective_limit,
        });
    }

    Ok(VerifiedPath {
        path: path.clone(),
        min_trust_level,
        accumulated_damping,
        effective_limit_cents: effective_limit,
        hop_count: path.len() - 1,
    })
}
```

### 6.2 Verifikationsschritte im Detail

| Schritt | Prüfung | Fehlschlag-Aktion |
|---|---|---|
| **Key Binding** | Ed25519-Signatur über `nonce_alice \|\| nonce_bob \|\| "PAYER"` | Abbruch: Identitätsdiebstahl vermutet |
| **SD-JWT Signatur** | Jedes SD-JWT gegen den `iss`-DID verifizieren | Abbruch: Gefälschtes Zertifikat |
| **SD-JWT Expiry** | `exp` > aktuelle Zeit | Abbruch: Abgelaufenes Zertifikat |
| **Forwarding-Tiefe** | `current_depth ≤ max_forwarding_depth` | Abbruch: Unerlaubte Weiterleitung |
| **Forwarding-Signatur** | Jede ForwardingLink-Signatur prüfen | Abbruch: Manipulierte Weiterleitung |
| **Letzte Kante** | Alice prüft eigenen Graphen: Kennt sie den vorletzten Hop? | Abbruch: Kein Vertrauenspfad |
| **Limit-Check** | Effektives Limit ≥ Transaktionsbetrag | Abbruch: Zu hohes Risiko |

---

## 7. Phase 5: AUTHORIZATION (Transaktions-Autorisierung)

### 7.1 Erfolgsfall

```
Alice → Bob:
┌──────────────────────────────────────────────────────────┐
│  AuthorizationResponse                                   │
│  ├── status: ACCEPTED                                    │
│  ├── verified_path_hash: SHA256(ProofBundle)              │
│  ├── effective_limit_cents: 4250                         │
│  ├── transaction_id: UUID                                │
│  ├── alice_signature: Ed25519(Alice_SK,                   │
│  │     nonce_bob || transaction_id || amount)             │
│  └── receipt: {                                          │
│        timestamp: 1743724800,                            │
│        amount_cents: 1500,                               │
│        payer: bob_did,                                   │
│        receiver: alice_did,                              │
│        trust_path_hash: ...,                             │
│        signatures: [alice_sig, bob_sig]                  │
│      }                                                   │
└──────────────────────────────────────────────────────────┘
```

### 7.2 Ablehnungsfall

```
Alice → Bob:
┌──────────────────────────────────────────────────────────┐
│  AuthorizationResponse                                   │
│  ├── status: REJECTED                                    │
│  ├── reason: INSUFFICIENT_TRUST                          │
│  ├── effective_limit_cents: 850  (8.50€)                 │
│  ├── suggestion: "Reduce amount to ≤ 850 cents           │
│  │    or present additional trust proofs"                 │
│  └── alternative_action: BUILD_DIRECT_EDGE               │
│       → "Alice can attest Bob as Level 0 (Existence)     │
│          for future transactions"                        │
└──────────────────────────────────────────────────────────┘
```

---

## 8. Sequenzdiagramm: Vollständiger Handshake

```
    Bob (Payer)                                   Alice (Receiver)
    ===========                                   ================

    ── Phase 1: BEACON ──────────────────────────────────────────
    │                                                            │
    │  BeaconMessage(bob_did, nonce_bob, PAYER)                  │
    │ ──────────────────────────────────────────────────────────► │
    │                                                            │
    │  BeaconMessage(alice_did, nonce_alice, RECEIVER, 1500ct)   │
    │ ◄────────────────────────────────────────────────────────── │
    │                                                            │
    │  [Lokaler Graph-Check: Alice nicht bekannt]                 │
    │                       [Lokaler Graph-Check: Bob nicht bek.] │
    │                                                            │
    ── Phase 2: INTERSECTION ────────────────────────────────────
    │                                                            │
    │  IntersectionReq(eph_pk, enc_pepper, search_set)           │
    │ ──────────────────────────────────────────────────────────► │
    │                                                            │
    │  IntersectionReq(eph_pk, enc_pepper, search_set)           │
    │ ◄────────────────────────────────────────────────────────── │
    │                                                            │
    │  [Cuckoo-Filter-Queries gegen Alice' search_set]           │
    │                [Cuckoo-Filter-Queries gegen Bobs search_s.] │
    │                                                            │
    │  IntersectionResp(hits: [{Carol, in Dave's filter, L2}])   │
    │ ◄────────────────────────────────────────────────────────── │
    │                                                            │
    │  IntersectionResp(hits: [{Dave, in Carol's filter, L2}])   │
    │ ──────────────────────────────────────────────────────────► │
    │                                                            │
    │  [Pfad identifiziert: Bob→Carol→Dave→Alice]                │
    │                                                            │
    ── Phase 3: PROOF ATTACHMENT ────────────────────────────────
    │                                                            │
    │  ProofBundle(path, SD-JWTs, key_binding, tx_context)       │
    │ ──────────────────────────────────────────────────────────► │
    │                                                            │
    ── Phase 4: VERIFICATION ────────────────────────────────────
    │                                                            │
    │                [Verify key binding]                         │
    │                [Verify each SD-JWT signature]               │
    │                [Verify forwarding chain]                    │
    │                [Check own graph: Alice→Dave? YES, L2]       │
    │                [Calculate effective limit: 4250 cents]      │
    │                [1500 ≤ 4250? YES → ACCEPT]                  │
    │                                                            │
    ── Phase 5: AUTHORIZATION ───────────────────────────────────
    │                                                            │
    │  AuthorizationResponse(ACCEPTED, limit=4250, receipt)      │
    │ ◄────────────────────────────────────────────────────────── │
    │                                                            │
    │  [Transaktion abgeschlossen]                               │
    │                                                            │
```

---

## 9. Bandbreiten-Analyse

Für einen typischen 3-Hop-Pfad (Bob → Carol → Dave → Alice):

| Phase | Nachricht | Größe (ca.) |
|---|---|---|
| 1. Beacon | 2 × BeaconMessage | 2 × 120 = 240 Bytes |
| 2. Intersection | 2 × IntersectionReq (je ~30 DIDs) | 2 × 1.600 = 3.200 Bytes |
| 2. Intersection | 2 × IntersectionResp | 2 × 200 = 400 Bytes |
| 3. Proof | 1 × ProofBundle (2 SD-JWTs + Forwarding) | ~2.800 Bytes |
| 4+5. Auth | 1 × AuthorizationResponse | ~400 Bytes |
| | **Gesamt** | **~7.040 Bytes** |

Bei BLE mit ~100 KB/s effektiver Nutzdatenrate: **~70ms reine Übertragungszeit**. Die Gesamtlatenz wird durch die Berechnungen (Filter-Queries, Signatur-Verifikationen) dominiert, nicht durch die Übertragung.

---

## 10. Edge Cases und Fehlerbehandlung

### 10.1 Mehrere Pfade gefunden

Wenn die Intersection mehrere mögliche Pfade enthüllt, wird der **stärkste** Pfad gewählt:

```rust
fn select_best_path(paths: Vec<CandidatePath>) -> CandidatePath {
    paths.into_iter()
        .max_by(|a, b| {
            // Primär: Höchstes effektives Limit
            // Sekundär: Kürzester Pfad (weniger Hops)
            let score_a = a.effective_limit as f64 / a.hop_count as f64;
            let score_b = b.effective_limit as f64 / b.hop_count as f64;
            score_a.partial_cmp(&score_b).unwrap()
        })
        .unwrap()
}
```

### 10.2 Abgelaufene Attestations in der Kette

Wenn ein SD-JWT im Bundle abgelaufen ist (`exp < now`), signalisiert Alice dies an Bob:

```
Alice → Bob:
{
  status: REJECTED,
  reason: EXPIRED_ATTESTATION,
  expired_edge: ("did:key:...Dave", "did:key:...Carol"),
  expired_at: 1743120000,
  suggestion: "Request fresh attestation from Dave to Carol"
}
```

Bob kann versuchen, einen alternativen Pfad zu präsentieren, oder die Transaktion wird abgebrochen.

### 10.3 False Positive im Cuckoo Filter

Ein Cuckoo-Filter-Treffer bedeutet "wahrscheinlich ja". Wenn Phase 2 einen Treffer meldet, aber Phase 3 fehlschlägt (weil Bob kein passendes SD-JWT hat oder die Attestation nicht zum Pfad passt), fällt das System elegant zurück:

1. Der gescheiterte Pfad wird markiert.
2. Der nächstbeste Pfad aus den Intersection-Ergebnissen wird versucht.
3. Nach Erschöpfung aller Pfade: `NoPath`-Ergebnis.

---

## 11. Zusammenfassung

Das Stranger Discovery Protocol löst das Problem der vertrauenslosen Offline-Interaktion durch:

1. **Bidirektionale Suche** — Beide Parteien suchen gleichzeitig, halbieren den Suchraum.
2. **Cuckoo-Filter als Schnelltest** — ~800 Bytes pro Envelope, Membership-Queries in Mikrosekunden.
3. **SD-JWT-Ketten als Beweis** — Kryptographisch bindend, selektiv offenlegbar, vom Empfänger mitgeführt.
4. **Pepper-gesicherte Filter** — Verhindern Dictionary-Attacken durch passive Angreifer.
5. **Forwarding mit Autorisierung** — Transitive Beweisketten mit kontrollierbarer Tiefe.
6. **Graceful Degradation** — Fallback auf alternative Pfade, Bootstrapping (Stufe 0), oder Transaktionsabbruch.

Die Gesamtlatenz von ~1–3 Sekunden für einen vollständigen Handshake mit Pfad-Discovery und kryptographischer Verifikation ist für Point-of-Sale-Szenarien akzeptabel.
