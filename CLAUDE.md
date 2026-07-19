# CLAUDE.md — session-ws

Org-wide conventions (repo list, Hive-org boundary, package scopes, git workflow, commit
format, CI secrets) live in
[System-B90/.github CLAUDE.md](https://github.com/System-B90/.github/blob/main/CLAUDE.md).
This file covers what's specific to session-ws.

## What session-ws is

Shared WebSocket session server, published as `@system-b90/session-ws` to GitHub
Packages. Consumed by bluz and madash for real-time session/state sync.

## Git

Commit format: `Vibe-<PastTenseVerb> <description>` (e.g. `Vibe-Fixed`, `Vibe-Added`). No
`feat:`/`fix:`/`chore:` prefixes. Never commit directly to `main`/`master` — feature
branch + PR. Bump the package version deliberately before publishing — consumers pin
exact versions.
