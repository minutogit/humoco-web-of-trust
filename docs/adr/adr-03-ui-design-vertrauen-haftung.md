# ADR 3: Architektur und UI-Design für dezentrales Vertrauen und Haftung

**Status:** Akzeptiert  
**Aktualisiert:** Protokoll-Harmonisierung & Drahtformat-Abschluss  
**Kontext:** Dezentrales Humangeld-Netzwerk (Web of Trust)  
**Datum:** 04. April 2026 (Aktualisiert am 30. Oktober 2026)

## 1. Kontext und Motivation

In einem dezentralen Humangeld-System (wie dem digitalen Minuto) gibt es keine zentrale Autorität und keinen globalen Token (wie Ethereum), der bei Fehlverhalten entzogen oder verbrannt („geslashed“) werden könnte. Das System basiert vollständig auf digitalen Leistungsversprechen und menschlichem Vertrauen.

Erfahrungen aus Projekten wie Proof of Humanity oder BrightID zeigen, dass eine reine, konsequenzlose Bestätigung („Ich kenne diese Person“) unweigerlich zu Sybil-Attacken führt. Es braucht zwingend ein „Skin in the Game“ (Haftung), um das Netzwerk abzusichern, ohne die Software jedoch zu einer bürokratischen „Justizbehörde“ aufzublähen.

---

## 2. Getroffene Entscheidungen

### 2.1 Semantische Trennung im UI („Für jemanden einstehen“)
Der Begriff „Vertrauen“ wird im UI durch **„Für jemanden einstehen“** (oder „Leumund bestätigen“) ersetzt. 
*   **Grund:** Dies macht dem Nutzer psychologisch klar, dass er seinen eigenen guten Ruf mit dem Verhalten der anderen Person verknüpft.

### 2.2 Zeit als universelle Währung der Haftung
Die Haftung für eine Reputationsbürgschaft wird in der ursprünglichsten Währung hinterlegt: **Lebenszeit bzw. Arbeitskraft** (Minuto-Prinzip: 1 Minuto = 1 Minute Arbeit).
*   **Grund:** Jeder gesunde Mensch verfügt über Zeit. Es erfordert kein Startkapital, erzeugt aber genug „Schmerz“ (Skin in the Game), um leichtfertige Identitätsbestätigungen zu verhindern.

### 2.3 Granulare Vertrauensstufen (Stufenmodell 0 bis 3)
Wir implementieren feste Abstufungen im UI, die intern auf mathematische Wahrscheinlichkeiten (Vertrauensfaktoren) gemappt werden:

| Stufe | UI-Kategorie | Soziale Haftung (Richtwert) | Interner Trust-Wert ($\gamma$) | Rolle im Graphen | Risiko-Level |
|---|---|---|---|---|---|
| **0** | **Mensch-Existenz** | Keine (0,0 Stunden) | 0 % (`0.0`) | Reiner Anti-Bot-Nachweis (1 Hop). **Keine Transit-Brücke**, keine Weiterleitung nachgelagerter Listen. | Kein Risiko |
| **1** | **Bekannter** | 0,5 Stunden | 30 % (`0.30`) | Aktive Vertrauenskante, Transit für Pfadberechnung erlaubt. | Gering (starke Dämpfung) |
| **2** | **Guter Kontakt** | 1,0 Stunden | 60 % (`0.60`) | Aktive Vertrauenskante, Transit für Pfadberechnung erlaubt. | Normal (moderate Dämpfung) |
| **3** | **Enger Vertrauter** | 4,0 Stunden | 85 % (`0.85`) | Aktive Vertrauenskante, Transit für Pfadberechnung erlaubt. | Hoch (sehr durchlässig) |

*   **Stufe 0 als Anti-Bot-Schutz:** Bestätigt ausschließlich für direkte Nachbarn, dass hinter einem Schlüsselpaar ein realer Mensch steht. Da $0.0 \times \text{alles} = 0.0$ gilt, ist Stufe 0 keine Transit-Brücke. Über reine Stufe-0-Kanten werden keine nachgelagerten Vertrauenslisten importiert oder weitergeleitet.
*   **Stufen 1 bis 3:** Tragen soziale Verantwortung in Arbeitszeit und bilden das Rückgrat der probabilistischen Pfadberechnung (siehe [ADR 1](./adr-01-pfadberechnung-und-vertrauenswahrscheinlichkeiten.md)).

### 2.4 Resilienz durch reinen Vertrauensentzug
Die App fungiert ausschließlich als „Notizbuch für positive Zusagen“. Es gibt kein algorithmisches „Makel“- oder „Downvote“-System.
*   **Verfahren:** Im Schadensfall (z. B. Betrug) fordert der Geschädigte die Haftungszeit vom Bürgen ein. Verweigert dieser die Haftung, entzieht der Geschädigte schlichtweg dem Bürgen das Vertrauen (Löschung der Verbindung im lokalen Graphen) und kommuniziert dies sozial.
*   **Grund:** Vermeidung von Angriffsvektoren für Rufmord-Kampagnen. Das Netzwerk bereinigt sich organisch durch das Kappen von Kanten.

---

## 3. Konsequenzen (Trade-offs)

*   **Positiv:** Die Software bleibt extrem schlank (KISS-Prinzip). Keine Schiedsgerichts-Logik oder Gerichtsverfahren im Code nötig.
*   **Positiv:** Die Eigenverantwortung der Nutzer wird radikal gefördert.
*   **Herausforderung:** Nutzer müssen lernen, Konflikte selbst auszutragen und auf ihr soziales Umfeld zu achten, anstatt sich auf eine „Vollkasko-Mentalität“ eines Plattformbetreibers zu verlassen.

---

## 4. Technische Spezifikation & Abschluss der offenen Punkte

Der offene Punkt bezüglich der technischen Repräsentation in der signierten Vertrauensliste ist wie folgt verbindlich abgeschlossen:

1.  **Ausschließlich diskrete Stufen `0..3` im Drahtformat:**  
    Im signierten SD-JWT-Drahtformat (in den selektiven Disclosures) wird pro Kontakt ausschließlich der diskrete Integer-Wert der Vertrauensstufe (`0 | 1 | 2 | 3`) zusammen mit dem Hop-Limit (`contact_max_hops`) übertragen (siehe [ADR 4](./adr-04-sd-jwt-vertrauenslisten.md)).
2.  **Keine Freitext-Haftungsstunden und keine Klartext-Namen:**  
    Es werden **keine** individuellen Freitext-Haftungsstunden und keine Klartextnamen fremder Kontakte im SD-JWT übertragen. Dies wahrt die Privatsphäre und garantiert minimale Paketgrößen für QR-Code- und BLE-Transfers.
3.  **Semantische Ableitung der Arbeitszeit-Haftung:**  
    Die soziale Arbeitszeit-Haftung (`0h / 0,5h / 1,0h / 4,0h`) ergibt sich rein semantisch aus der jeweiligen Stufe und wird von der Wallet zur visuellen Nutzerführung verwendet.
4.  **Schnittstellen und Datenspeicher:**  
    Die formale Datenstruktur des lokalen Registers sowie die Schnittstellen zur Integration in den Rust-Core (`human-money-core`) und dessen `TrustProvider`-Trait werden in [ADR 7 (Datenstruktur, Speicher und Schnittstellen)](./adr-07-datenstruktur-speicher-und-schnittstellen.md) definiert.
