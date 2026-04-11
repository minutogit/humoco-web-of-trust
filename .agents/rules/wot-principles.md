---
name: wot-principles
description: Mandatory principles for all WoT related changes.
activation: always
---

# Web of Trust Grundregeln (Humoco)

Diese Regeln gelten global für alle Änderungen am Vertrauensnetzwerk:

- **Keine Vertrauensstufe > 0** ohne einen kryptographisch bindenden Beweis (SD-JWT).
- **Stufe-0-Kanten** (Existence) erfordern zwingend eine physische Face-to-Face Bestätigung.
- **Pfadtiefe:** Vertrauenspfade sind standardmäßig auf maximal 2-3 Hops limitiert, um CPU-Aufwand und Sybil-Risiko zu begrenzen.
- **Datenstrukturen:** Verwende Cuckoo-Filter für probabilistische Abgleiche und SD-JWTs für die Beweissicherung.
- **Multiplikative Dämpfung:** Vertrauen sinkt exponentiell pro Hop (γ-basiert).
- **Offline First:** Alle Kernlogiken müssen ohne Internetverbindung im Tauri-Client funktionieren.
