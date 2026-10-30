# HuMoCo Web of Trust — Agent Context & Rules

Dieses Verzeichnis enthält die Agenten-Konfiguration und Skills für das `humoco-wot` Crate.

## Enthaltene Komponenten

- **Hauptanweisungen:** [`instructions.md`](instructions.md) (per Symlink auch als `AGENTS.md` im Root verlinkt) mit Rollendefinition, Sprachrichtlinien und kryptographischen Invarianten.
- **Regeln:** [`rules/status-maintenance.md`](rules/status-maintenance.md) zur konsistenten Pflege von `STATUS.md`.
- **Skills:** [`skills/wot-architecture/SKILL.md`](skills/wot-architecture/SKILL.md) mit kompakter Referenz der ADRs 00–07, des Dual-Storage-Modells (`TrustRegister` + `EgoGraphCache`) und der Public-API-Methoden.

## Arbeitsweise
Agenten laden bei Bedarf den Skill `wot-architecture` und halten `STATUS.md` nach Meilensteinen aktuell.
