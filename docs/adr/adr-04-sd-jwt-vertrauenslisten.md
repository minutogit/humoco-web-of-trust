# ADR 4: Vertrauenslisten als Selective Disclosure JWT (SD-JWT)

**Status:** Vorgeschlagen / Akzeptiert  
**Aktualisiert:** Protokoll-Harmonisierung & JWE/JWS Standards  
**Kontext:** Dezentrales Web of Trust (WoT) basierend auf `did:key`  
**Datum:** 6. April 2026 (Aktualisiert am 22. April 2026)

## 1. Problemstellung
Wir benötigen eine Methode für das "Stranger Discovery Protocol" (Offline-Nähe) und das asynchrone Gossip-Protokoll, um Vertrauensbeziehungen (Schnittmengen von Freunden) offenzulegen, ohne die komplette Netzwerk-Vertrauensliste unverschlüsselt in Klartext bereitzustellen.
Zusätzlich ergibt sich aus der Architektur für "Reziprokes Routing" (ADR 0005) die harte Anforderung: Wenn ein Peer eine fremde Vertrauensliste via Gossip weiterleitet, muss er – abhängig von den aufgebrauchten Hop-Limits – gezielt **einzelne** Einträge aus dieser Liste redigieren (löschen) können, ohne dass die kryptographische Ed25519-Signatur des ursprünglichen Erstellers bricht.

## 2. Getroffene Entscheidung
Wir strukturieren die Vertrauensliste (die *Trust List*), die via Gossip im Netzwerk verteilt wird, nativ als **SD-JWT (Selective Disclosure JWT)** nach dem IETF-Standard. Als verschlüsselter Transport-Umschlag wird hierfür die `SecureContainer`-Implementierung des `human-money-core` (JWE) genutzt.

### Technische Spezifikationen

#### A. Vertrauensliste als formelles SD-JWT
*   Der Nutzer (z.B. Alice) erstellt eine standardisierte JSON-Struktur, die als SD-JWT signiert wird.
*   Jeder Kontakt wird als separates, selektiv offenlegbares Claim-Objekt im Payload abgelegt.

#### B. Hop-by-Hop Redaktion bei Gossip
*   Wenn Alice ihre Liste verschickt, sendet sie das SD-JWT inklusive aller benötigten kryptographischen "Disclosures" (den Klartexten).
*   Wenn Bob dieses Paket empfängt und später via Gossip (ADR 0006) an Carol weitergeben möchte, prüft Bob für jeden Kontakt in Alices Liste das jeweilige verbleibende Hop-Limit.
*   Muss ein Kontakt redigiert (verborgen) werden, lässt Bob schlichtweg die spezifische Klartext-Disclosure weg. Carol sieht an der betroffenen Stelle im Hash-Baum (dem SD-JWT) nur noch unlesbare Salts/Hashes, **aber Alices digitale Signatur des Gesamt-Tokens bleibt zu 100 % valide und für Carol prüfbar.**

#### C. Privatsphäre durch Hop-Limits und Dateneffizienz (128 Bit)
*   **Nutzergesteuerte Privatsphäre:** Es wird kein globales "Verschleierungs-Salz" (Pepper) verwendet, da dies die dezentrale Pfadberechnung verhindern würde. Die Privatsphäre wird stattdessen exklusiv über die individuellen **Hop-Limits** (ADR 0005) gesteuert. Jeder Nutzer entscheidet für jeden Kontakt einzeln, wie weit dessen ID im Netzwerk sichtbar sein darf.
*   **Dateneffizienz (128 Bit):** Um die Datengröße der SD-JWTs so gering wie möglich zu halten (essenziell für NFC, QR-Codes und Gossip-Transaktionen), werden die Hashes (z. B. von SHA-256) innerhalb der SD-JWT-Struktur auf exakt **128 Bit (16 Bytes / ~22 Base64-Zeichen)** abgeschnitten (Truncation).
*   *Warum 128 Bit?* Dies ist der "goldene Mittelweg". Es verkleinert die Payload einer Liste mit 100 Usern um mehrere Kilobyte gegenüber vollen 256-Bit-Hashes, garantiert aber dennoch durch $2^{128}$ mögliche Permutationen eine absolute mathematische Kollisionsfreiheit – selbst bei einer planetaren Skalierung auf Milliarden von Knotenpunkten.

#### D. Struktur des SD-JWT Pakets (Schema-Beispiel)

Die vollständige Vertrauensliste, die ein Nutzer einmalig unterschreibt, ist semantisch wie folgt aufgebaut:

**1. Paket-Kopf / Metadaten (Klartext)**
*   **Issuer (Aussteller):** `did:key:z6Mk...` (Der Ersteller der Liste)
*   **Version / Epoche:** `5` (Wichtig für den asynchronen Delta-Sync, ADR 0006)
*   **Globales Max Hops:** `4` (Maximales Limit für das gesamte Paket, falls konfiguriert)

**2. Vertrauenseinträge / Claims (Selektiv offenlegbar)**
Jeder Kontakt wird als separates, selektiv offenlegbares Objekt im Payload hinterlegt. 

| Kontakt (128-Bit Payload-Hash) | Vertrauensstufe (0-3) | Individuelles Hop-Limit (Reaktive Spiegelung) | Status (Sichtbar / Geschwärzt?) |
| :--- | :--- | :--- | :--- |
| `b94d27b9934d3e08a52e52d7...` | 3 (Enger Vertrauter) | 3 Hops | **Sichtbar** (Klartext-Disclosure vorhanden) |
| `3f79bb7b435b05321651dafe...` | 1 (Bekannter) | 1 Hop | **Sichtbar** (Klartext-Disclosure vorhanden) |
| `~ unlesbarer SD-JWT Hash ~` | ? | ? | **Redigiert** (Hop-Limit abgelaufen, Disclosure entfernt) |

**3. Kryptographische Signatur**
*   Die Ed25519-Signatur des Issuers über die gesamte Struktur. Obwohl der Knoten, der dieses Paket weiterreicht, bestimmte Einträge (wie in Zeile 3) gezielt "geschwärzt" hat, bleibt die Signatur für die restlichen, sichtbaren Einträge (Zeile 1 und 2) mathematisch vollumfänglich valide.

#### G. Harte Regeln für lokale Interaktionen (QR/BLE)
Um die Dateneffizienz bei physischen Begegnungen (Stranger Discovery via QR-Code, BLE oder NFC) zu maximieren, gelten folgende verbindliche Anforderungen:
*   **Format:** Es wird ausschließlich **JWE Compact Serialization** verwendet. Die Full JSON Serialization von JWE ist aufgrund des Overheads verboten.
*   **Privacy Mode:** Es muss zwingend `PrivacyMode::TrialDecryption` genutzt werden. Dies verhindert, dass passive Lauscher (z.B. in der Nähe eines QR-Code-Scanners) Bewegungsprofile durch Auslesen der Empfänger-DIDs im Header erstellen können.
*   **Kein W3C VC Overhead:** Die Verwendung von W3C Verifiable Credentials (VCs) ist für lokale Handshakes **strikt untersagt**. Der zusätzliche JSON-LD/Context-Overhead (~100+ Bytes) würde die Kapazität von QR-Codes sprengen oder die BLE-Latenz unnötig erhöhen. Wir nutzen stattdessen die rohen SD-JWTs (JWS) direkt im JWE-Container.

## 3. Rationale (Begründung)
*   **Signaturerhaltende Reduktion:** SD-JWTs sind die optimale architektonische Lösung für die selektive Hop-Redaktion auf Einzelkontakt-Ebene, die in ADR 0005 gefordert wird.
*   **Sicherheitsstandards:** Das System nutzt durchgehend etablierte und intensiv geprüfte SD-JWT Strukturen.
*   **Protokoll-Harmonisierung:** Wir folgen strikt den RFC 7515 (JWS) und RFC 7516 (JWE) Standards, die SHA-256 und Base64URL voraussetzen.

## 4. Konsequenzen

- **Positiv:** Es ermöglicht die granulare Privatsphäre und das unwiderrufliche Verbergen abgelaufener Hops vollumfänglich und nativ auf Datenebene.
- **Risiko (Größen-Overhead):** SD-JWTs haben einen verhältnismäßig großen Overhead. Eine vollständige Liste mit 50–100 Kontakten kann eine Größe von mehreren Kilobytes erreichen.
- **Architektur:** Durch diese unumgängliche Datenmenge sind Delta-Sync und effizientes Caching (ADR 0006) absolut notwendig, insbesondere für den Transfer via QR-Code oder limitierten Funkstrecken.
