---
name: antigravity-setup
description: Anleitung für die Einrichtung von Antigravity Agenten-Anweisungen, Skills und Regeln in einem Repository.
---

# SKILL: Antigravity Repository Setup

Dieser Skill enthält das Wissen zur korrekten Strukturierung des `.agents/` Verzeichnisses, um Antigravity-Agenten (Hauptagenten und Subagenten) optimal in einem Projekt zu konfigurieren.

## 1. Das `.agents/` Verzeichnis
Das Hauptverzeichnis für alle Agenten-spezifischen Konfigurationen im Repository.

```text
.agents/
├── instructions.md         <-- Haupt-Anweisungen (Behavioral Guidelines)
├── rules/                  <-- "Always On" Verhaltensregeln
├── skills/                 <-- Modulare Wissenspakete
└── workflows/              <-- Strukturierte Arbeitsabläufe
```

## 2. Hauptagent-Anweisungen (`instructions.md`)
Die Datei `.agents/instructions.md` (alternativ `agents.md` oder `GEMINI.md`) definiert die Identität und die globalen Ziele des Agenten für diesen Workspace.

- **Zweck:** Legt fest, *wer* der Agent in diesem Projekt ist (z. B. "Du bist der WoT Architekt").
- **Inhalt:** Persönlichkeit, Prioritäten, Projektkontexte und strategische Leitplanken.
- **Aktivierung:** Wird beim Starten des Workspace automatisch geladen.

## 3. Verhaltensregeln (`rules/`)
Regeln in `.agents/rules/` dienen dazu, bestimmte Constraints (z. B. Sicherheitsvorgaben oder Coding-Standards) dauerhaft zu erzwingen.

- **Format:** Markdown-Datei mit YAML-Frontmatter.
- **Aktivierung:** Durch das Feld `activation: always` im Frontmatter ist die Regel dauerhaft aktiv.

```markdown
---
name: my-rule
description: Erklärt den Zweck der Regel.
activation: always
---
# Regel-Inhalt...
```

## 4. Skills (`skills/`)
Skills sind modulare Wissenseinheiten, die bei Bedarf geladen werden.

- **Pfad:** `.agents/skills/<skill-name>/SKILL.md`
- **Zwingende Voraussetzung:** YAML-Frontmatter mit `name` und `description`.

```markdown
---
name: wot-architecture
description: Fachwissen über Web of Trust Konzepte.
---
# Skill-Inhalt...
```

## 5. Workflows (`workflows/`)
Workflows definieren Schritt-für-Schritt-Anleitungen für spezifische Aufgaben (z. B. `/slash-commands`).

- **Pfad:** `.agents/workflows/<command-name>.md`
- **Turbo-Modus:** Mit `// turbo` markierte Schritte in run_command können automatisch ausgeführt werden (SafeToAutoRun: true).

## 6. Best Practices
- **Verzichte auf Over-Engineering:** Starte mit einer soliden `instructions.md`.
- **Nutze Frontmatter:** Ohne Frontmatter werden Regeln und Skills oft nicht korrekt indiziert.
- **Plural verwenden:** Nutze `.agents/` statt `.agent/` für bessere Zukunftskompatibilität.
