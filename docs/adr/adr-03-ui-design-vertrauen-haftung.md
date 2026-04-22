# ADR 3: Architektur und UI-Design für dezentrales Vertrauen und Haftung

**Status:** Akzeptiert  
**Aktualisiert:** Protokoll-Harmonisierung & JWE/JWS Standards  
**Kontext:** Dezentrales Humangeld-Netzwerk (Web of Trust)  
**Datum:** 04. April 2026 (Aktualisiert am 22. April 2026)

## 1. Kontext und Motivation
In einem dezentralen Humangeld-System (wie dem digitalen Minuto) gibt es keine zentrale Autorität und keinen globalen Token (wie Ethereum), der bei Fehlverhalten entzogen oder verbrannt ("geslashed") werden könnte. Das System basiert vollständig auf digitalen Leistungsversprechen und menschlichem Vertrauen.

Erfahrungen aus Projekten wie Proof of Humanity oder BrightID zeigen, dass eine reine, konsequenzlose Bestätigung ("Ich kenne diese Person") unweigerlich zu Sybil-Attacken führt. Es braucht zwingend ein "Skin in the Game" (Haftung), um das Netzwerk abzusichern, ohne die Software jedoch zu einer bürokratischen "Justizbehörde" aufzublähen.

## 2. Getroffene Entscheidungen

### 2.1 Semantische Trennung im UI ("Für jemanden einstehen")
Der Begriff "Vertrauen" wird im UI durch **"Für einstehen"** (oder "Leumund bestätigen") ersetzt. 
- **Grund:** Dies macht dem Nutzer psychologisch klar, dass er seinen eigenen guten Ruf mit dem Verhalten der anderen Person verknüpft.

### 2.2 Zeit als universelle Währung der Haftung
Die Haftung für eine Reputationsbürgschaft wird in der ursprünglichsten Währung hinterlegt: **Lebenszeit/Arbeitskraft** (Minuto-Prinzip: 1 Minuto = 1 Minute Arbeit).
- **Grund:** Jeder gesunde Mensch verfügt über Zeit. Es erfordert kein Startkapital, erzeugt aber genug "Schmerz" (Skin in the Game), um leichtfertige Identitätsbestätigungen zu verhindern.

### 2.3 Granulare Vertrauensstufen (3-Stufen-Modell)
Wir implementieren drei feste Abstufungen im UI, die intern auf mathematische Wahrscheinlichkeiten (Vertrauensfaktoren) gemappt werden. Im Hintergrund gilt zudem die "Stufe 0" (Mensch-Existenz) als technisches Fundament ohne finanzielle Propagation.

| UI-Kategorie | Haftung (Beispiel) | Interner Trust-Wert (Gamma) | Risiko-Level |
|---|---|---|---|
| **Bekannter** | 0,5 Stunden | 30% (0.30) | Gering (starke Dämpfung) |
| **Guter Kontakt** | 1,0 Stunden | 60% (0.60) | Normal (moderate Dämpfung) |
| **Enger Vertrauter** | 4,0 Stunden | 85% (0.85) | Hoch (sehr durchlässig) |

### 2.4 Resilienz durch reinen Vertrauensentzug
Die App fungiert ausschließlich als "Notizbuch für positive Zusagen". Es gibt kein algorithmisches "Makel"- oder "Downvote"-System.
- **Verfahren:** Im Schadensfall (z. B. Betrug) fordert der Geschädigte die Haftungszeit vom Bürgen ein. Verweigert dieser die Haftung, entzieht der Geschädigte schlichtweg dem Bürgen das Vertrauen (Löschung der Verbindung im lokalen Graphen) und kommuniziert dies sozial.
- **Grund:** Vermeidung von Angriffsvektoren für Rufmord-Kampagnen. Das Netzwerk bereinigt sich organisch durch das Kappen von Kanten.

## 3. Konsequenzen (Trade-offs)

- **Positiv:** Die Software bleibt extrem schlank (KISS-Prinzip). Keine Schiedsgerichts-Logik im Code nötig.
- **Positiv:** Die Eigenverantwortung der Nutzer wird radikal gefördert.
- **Herausforderung:** Nutzer müssen lernen, Konflikte selbst auszutragen und auf ihr soziales Umfeld zu achten, anstatt sich auf eine "Vollkasko-Mentalität" eines Plattformbetreibers zu verlassen.

## 4. Offene Punkte / Abgleich mit Bestand

- Definition der technischen Repräsentation von "Zeit-Haftungsversprechen" in der `Vertrauensliste`.
