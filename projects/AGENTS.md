# projects

## Purpose

- What is watched: one YAML file per project, `<project>.yml`

## Ownership

- The project files and their shape; how they are read is owned by [watch/AGENTS.md](../watch/AGENTS.md)

## Local Contracts

- `name`: the project's name, also the name of its status file (`status/<name>.json`); a project's name only, never a client's
- `repository`: `owner/name` on GitHub, public
- `watch.branches`: the branches checked, by name
- `watch.releases`: how many of the latest published releases are checked, pre-releases included
- `sources`: where the project writes its dependencies, each a `file` (relative to the repository's root) and a `kind`: `nuget`, `dotnet-sdk`, `pip`, `dockerfile`, `compose`
- Versions are never copied here: they are read from the sources every day

## Work Guidance

- A new project is a new file, with every source that holds a dependency; a source missing at some ref is skipped there
- A new kind is added in the watcher first ([watch/AGENTS.md](../watch/AGENTS.md)), then listed here and in the README's table

## Verification

- The Watch workflow runs on every push that changes this folder; its status file says what was read, or why it failed

## Child DOX Index

- None
