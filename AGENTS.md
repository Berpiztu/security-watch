# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## Project

- security-watch checks, every day, the dependencies of Berpiztu's projects against the known vulnerabilities and the newest versions, and keeps the result: a status per project, which each project reads before it releases, and the history of every finding ([README.md](README.md))
- Public: anyone reads it, only Berpiztu changes it
- Layout: `projects/` what is watched; `watch/` the watcher; `status/`, `history.json`, `HISTORY.md` its output, written and committed by the workflow, never by hand; `.github/workflows/watch.yml` when it runs
- The root owns the README, the workflow and the rules below

## Rules

- English for code, comments, docs and commit messages
- Nothing here names a client, a server, a domain, an address or a person: a project's name and its dependencies only
- No secrets: the watcher reads public repositories with the workflow's token alone
- Commits by people are `Iosu Buenetxea (Berpiztu) <iosub@berpiztu.ai>`, pushed as `Iosub-ai`; the work address never appears. The workflow commits its results as `github-actions[bot]`
- A version is checked at its source before it is written (a package, an image, an action), never from memory
- The watcher is verified on GitHub (the Watch workflow, by hand or on push), never by building or running it on the owner's machine

## User Preferences

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

- Every change ends committed and pushed; git is done by the agent, never handed to the owner as commands

## Child DOX Index

- [projects/AGENTS.md](projects/AGENTS.md): what is watched, one file per project, and the shape of that file
- [watch/AGENTS.md](watch/AGENTS.md): the watcher, how it checks each kind of source, and what it writes (`status/`, `history.json`, `HISTORY.md`, issues)
