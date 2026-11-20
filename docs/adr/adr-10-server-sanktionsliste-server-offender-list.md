# ADR 10: Kryptographische Server-Sanktionsliste (`ServerOffenderList`) via `EquivocationProof`

**Status:** Akzeptiert / Spezifikation  
**Aktualisiert:** November 2026  
**Kontext:** Dezentrales Web of Trust (WoT), Sync-Locks (`LockCommittee`) & Betreiber-Vertrauen

---

## 1. Problemstellung & Motivation

Im Sync-Lock-Modell (`LockCommittee`) garantieren $N$ benannte `humoco-sync`-Server mit Quorum $Q > N/2$ den Online-Schutz vor Double-Spending. Ein byzantinischer Lock-Server verletzt die Write-Once-Invariante, wenn er auf denselben Set-Slot (`slot`) zwei unterschiedliche `FirstWrite`-Quittungen (`child_lock_a != child_lock_b`) mit seiner gültigen `lock_sk`-Signatur unterzeichnet (Equivocation).

Im Unterschied zu reinen Blockchain-Slashing-Systemen gibt es bei HuMoCo keine monetären Stakes und kein globales On-Chain-Gericht. Stattdessen liefert jeder Widerspruch selbst ein kompaktes, fälschungssicheres Schuldbeweis-Dokument (**`EquivocationProof`**), das ohne zentrale Instanz im Web of Trust verteilt und von jeder Wallet selbständig verifiziert wird (vgl. `sync_double_spend_schutz_plan.md` §6.7).

---

## 2. Kryptographisches Beweisformat

### 2.1 `EquivocationProof` (Signatur-Ebenen-Beweis)

Ein gültiger `ServerOffenderRecord` stützt sich ausschließlich auf objektive, unabhängig nachprüfbare Ed25519-Signaturen:

```rust
pub struct ServerOffenderRecord {
    pub proof: WotEquivocationProof,          // Zwei widersprüchliche FirstWrite-LockReceipts
    pub delegation: Option<WotLockDelegation>, // Admin-Delegation `HUMOCO-LOCK-DELEGATE-V1`
    pub recorded_at: u64,
}
```

Ein `WotEquivocationProof` wird nur akzeptiert, wenn **alle** folgenden Bedingungen gleichzeitig erfüllt sind:
1. Beide Quittungen (`receipt_a`, `receipt_b`) tragen `kind == FirstWrite`.
2. Beide stammen von demselben nicht-schwachen Server-Schlüssel (`receipt_a.lock_pub == receipt_b.lock_pub`).
3. Beide betreffen denselben Set-Slot (`receipt_a.slot == receipt_b.slot`).
4. Sie bezeugen unterschiedliche Ausgaben (`receipt_a.child_lock != receipt_b.child_lock`).
5. Beide tragen gültige Ed25519-Signaturen über das kanonische 257-Byte-Präimage mit Domain-Tag **`HUMOCO_LOCK_RECEIPT_V1`**.

### 2.2 Verknüpfung zum Betreiber (`admin_pub` via `HUMOCO-LOCK-DELEGATE-V1`)

Weil ein Server-Betreiber seinen ephemere Lock-Schlüssel (`lock_pub`) im Fehler- oder Betrugsfall einfach löschen und durch eine neue Installation ersetzen könnte, darf optional die signierte Lock-Delegation des Servers beigelegt werden:
* Kanonische Signaturnachricht:
  `"HUMOCO-LOCK-DELEGATE-V1\n<admin_pub_hex>\n<lock_pub_hex>\n<write_url>\n<read_url>\n<issued_at>"`
* Ist diese Signatur von `admin_pub` gültig und stimmt `delegation.lock_pub == receipt_a.lock_pub`, werden **sowohl `lock_pub` als auch `admin_pub` dauerhaft gesperrt**.

---

## 3. Verbreitung & Durchsetzung an der Kasse

1. **Lokale sofortige Entwertung:** Sobald eine Kasse oder ein Halter einen gültigen `EquivocationProof` erhält (`evaluate_checkout` oder `Sync` / Community-Feed), trägt sie `lock_pub` (und verifiziertem `delegation` folgend auch `admin_pub`) in ihre lokale `ServerOffenderList` ein.
2. **Einfluss auf die Kassen-Ampel (Grün-Regel):** Einträge in `ServerOffenderList` werden **sofort und bedingungslos** aus der Menge der Händler-vertrauten Server (`trusted_servers`) gestrichen. Ein überführter Server kann fortan **keine** für „Grün“ benötigte Vertrauensstimme ($N - Q + 1$) mehr liefern.
3. **Kompakte Hub-Verteilung (`ADR-08` BinaryFuse64):** Community-Hubs und Verbände können ihre verifizierten `ServerOffenderList`-Sperren optional als signierten 64-Bit Binary-Fuse-Sperrfilter (`HUMOCO_SERVER_OFFENDER_V1`) parallel zu den Positiv-Prüfsiegeln (`wot-provider-filter+v1`) verteilen. Jede empfangende App prüft bei Einzelmeldungen jedoch zwingend den vollständigen `EquivocationProof` kryptographisch nach, sodass niemand einen ehrlichen Community-Server durch bloße Behauptung denunzieren kann (Null-Denunziations-Garantie).

---

## 4. Konsequenzen & Sicherheitsinvarianten

* **Kein unbewiesener Bann:** Ein `ConflictSeen`-Beleg oder eine bloße Timeout-Meldung reicht ausdrücklich **nicht** für die `ServerOffenderList`; nur `FirstWrite`-Widerspruch (`EquivocationProof`) beweist Server-Fehlverhalten.
* **Dauerhafte Sanktion ohne Amnestie-Bypass:** Ein gesperrter `lock_pub` oder `admin_pub` wird im lokalen Register nicht über den Quartals-GC gelöscht, sondern überdauert die Gutscheinlaufzeit dauerhaft.
* **Zero-Compat:** `#![forbid(unsafe_code)]`, keine Legacy-Formate, explizite UTC-Zeitstempel und volle `wasm32-unknown-unknown`-Kompatibilität.
