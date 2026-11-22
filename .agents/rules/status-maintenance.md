---
name: status-maintenance
description: Rule for maintaining STATUS.md in the project root.
activation: always
---

# STATUS.md Maintenance

Keep [`STATUS.md`](../../STATUS.md) up to date whenever features finish, priorities shift, or cross-repo dependencies change.

## Ecosystem Task Prefixes
- `CORE-NNN` → `human-money-core`
- `PROTO-NNN` → `humoco-proto`
- `SYNC-NNN` → `humoco-sync`
- `APP-NNN` → `human-money-app`
- `WOT-NNN` → `humoco-web-of-trust`
- `NODE-NNN` → `human-money-node` *(frozen via `NODE-004`)*

## Maintenance Rules
1. Maintain standard YAML frontmatter (`project`, `version`, `phase`, `health`, `last_updated`, `blocks`, `blocked_by`, `priority_tasks`).
2. Keep body sections concise: **Current Focus**, **Architecture / Core Decisions**, **MVP Priority Chain**, and progress milestones.
3. Update `last_updated` (`YYYY-MM-DD`) on every change; keep frontmatter and body consistent (English preferred, preserving existing German ADR/milestone context where needed).
4. Ecosystem coordination references sync with meta [`MASTER_OVERVIEW.md`](../../../MASTER_OVERVIEW.md) and [`TODO.md`](../../../TODO.md).
