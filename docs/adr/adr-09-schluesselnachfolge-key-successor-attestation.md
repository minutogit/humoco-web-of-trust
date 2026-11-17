# ADR 09: Schlüsselnachfolge (`KeySuccessorAttestation`) & Anti-Vampire-Schutz

**Status:** Akzeptiert / Spezifikation  
**Aktualisiert:** November 2026  
**Kontext:** Dezentrales Web of Trust (WoT), Key-Rotation, L2-Discovery & L1-Migrationsrechte

---

## 1. Problemstellung & Motivation

Im HuMoCo-Ökosystem ist jeder Teilnehmer durch ein selbst-souveränes Ed25519-Schlüsselpaar (`did:key`) identifiziert. In einem langlebigen Zahlungs- und Vertrauensnetzwerk treten drei Situationen auf, in denen sich der primäre `did:key` eines Nutzers ändert:

1. **Geplanter Schlüsselwechsel oder Gerätewechsel:** Beide Schlüsselpaare (`old_did` und `new_did`) sind gleichzeitig verfügbar und können sich gegenseitig autorisieren.
2. **Kompromittierungsverdacht (`Compromise`):** Der alte Schlüssel muss sauber auf einen frischen Schlüssel übergeleitet werden, solange `old_sk` noch unter Kontrolle steht oder eine Wiederherstellungsautorität einspringt.
3. **Totalverlust ohne Seed-Backup:** `old_did` (inklusive `creator_mig_sk` bei ausgegebenen Gutscheinen) ist verloren; die soziale Erreichbarkeit über `CardStore` und bestehende Kontakte soll kontrolliert auf `new_did` übergehen.

Gleichzeitig muss das Web of Trust zwei Angriffe ausschließen:
- **Vampire Attack (Identitäts-Vervielfachung):** Ein Angreifer erzeugt beliebig viele neue `did:key`s, sammelt mehrfach Vertrauen auf parallelen Identitäten oder versucht ohne Autorisierung, das Vertrauen eines anderen Schlüssels zu übernehmen (`docs/research/04-game-theory-and-attack-vectors.md` §5.4).
- **Kaperung der L2-Discovery (`anchor`-Slot):** Ein Dritter behauptet unbefugt, Nachfolger eines Gutschein-Erstellers zu sein, und lenkt Discovery-Lookups um.

---

## 2. Architektur: Zwei Autorisierungsmodi

### 2.1 Modus A — Geplante Dual-Signatur-Rotation (`KeySuccessorAttestation`)

Wenn der bisherige Schlüssel noch signieren kann, bestätigen **beide** Schlüssel kryptographisch exakt denselben Nachfolge-Eintrag:

```rust
pub enum KeyRotationReason {
    Routine,
    Compromise,
    DeviceMigration,
}

pub struct KeySuccessorAttestation {
    pub old_did: Did,
    pub new_did: Did,
    pub reason: KeyRotationReason,
    pub new_creator_mig_pub: Option<[u8; 32]>,
    pub rotated_at: u64,
    pub old_key_signature: [u8; 64],
    pub new_key_signature: [u8; 64],
}
```

* **Kanonisches Domain-Tag:** `HUMOCO_KEY_SUCCESSOR_V1` (SHA-256-Digest über Domain-Tag, kanonische UTF-8-DIDs `old_did` / `new_did` jeweils mit Längenpräfix, `reason`-Tag, `new_creator_mig_pub` [Flag + 32 Bytes] sowie `rotated_at` in `u64` Little-Endian).
* **Dual-Proof-Pflicht:** `old_key_signature` (signiert mit `old_did`) beweist die Übergabeautorität; `new_key_signature` (signiert mit `new_did`) beweist aktiven Schlüsselbesitz und verhindert das ungewollte Aufpfropfen fremder Nachfolgen auf ein Zielkonto.
* **Kein Zirkelbezug:** `old_did != new_did`, schwache Ed25519-Schlüssel werden strikt abgewiesen, und aufgelöste Nachfolgeketten sind hart auf **`MAX_SUCCESSOR_CHAIN_LEN = 8`** begrenzt sowie zyklusfrei zu prüfen.

### 2.2 Modus B — Notfall-Wiederherstellung bei totalem Schlüsselverlust

Geht `old_sk` verloren (z. B. Verlust des Smartphones ohne Seed-Backup, vgl. `sync_double_spend_schutz_plan.md` §5.5), kann `old_did` keine Dual-Signatur mehr leisten. In diesem Fall erfolgt die Autorisierung außerhalb der direkten Schlüsselkette über explizite Wiederherstellungsanker:

1. **Papier-Recovery-Schlüssel (`recovery_pub` im `AnchorManifest`):** Ein im Genesis-Anker fest verbundener Cold-Key unterzeichnet eine Notfall-Nachfolgebestätigung `old_did → new_did` inklusive `new_creator_mig_pub`.
2. **Bürgen-Quorum / Soziale Recovery-Wächter (`guarantor_mig_pubs`):** Nach Ablauf der 30-Tage-Ersteller-Inaktivität übernehmen bei verbürgten Gutscheinen die Bürgen technisch das L2-Migrationsrecht; ergänzend bestätigt die soziale Kontaktgruppe per neuer SD-JWT-Vertrauenslistenversion (`v_neu`) explizit `new_did`, während `old_did` im lokalen Kontaktbuch herabgestuft bzw. als abgelöst markiert wird.

---

## 3. Anti-Vampire-Invariante im Vertrauensgraphen

1. **Kaltstart ohne Attestierung:** Ohne gültige `KeySuccessorAttestation` beginnt ein neu generierter `did:key` zwingend bei **0 % Vertrauen** und erhält keinerlei Transitivität von älteren Schlüsseln des Nutzers.
2. **Identitäts-Faltung statt Addition:** Verifizierte `old_did → new_did`-Übergänge werden im lokalen Ego-Graphen als gerichtete Äquivalenz auf denselben logischen Akteur gefaltet (`old_did` und `new_did` können im selben Pfad nicht additiv gezählt werden; Shared-Edge Factoring behandelt den Übergang verlustbehaftungsfrei, aber kapazitätsneutral).
3. **Wiederherstellungs-Brücke für Discovery:** Für die `CardStore`-Auflösung (`humoco-market`) löst der Client eine Kette über `resolve_successor_chain(creator_did)` auf maximal 8 Hops auf und prüft erst dort den öffentlichen `anchor`-Slot.

---

## 4. Konsequenzen & Kompatibilität

* **Zero-Compat:** Unsignierte Nachfolge-Behauptungen im `ContactCard`-/`SdCard`-Profil werden ohne Rückwärtskompatibilität verworfen.
* **WASM-Portabilität:** Verifikation und Kettenauflösung sind zustandslos, `#![forbid(unsafe_code)]`, ohne eigene Systemuhr (`now_secs` als expliziter Parameter) und laufen identisch in Desktop, Mobile und WASM.
