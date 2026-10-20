# inventories

## Purpose

- What each project sent: `<project>/<ref>.json`, every library one of its branches or releases uses, at its exact version, saved by the watcher from the project's inventory issue

## Ownership

- The inventory's shape; the projects own their content and send it themselves, as an issue titled `inventory: <project>@<ref>` with the JSON in a ```json block, with a token that can open issues and nothing else

## Local Contracts

- `project`: the project's name, also the name of its status file (`status/<project>.json`); a project's name only, never a client's
- `ref`: the branch or the release tag; the file's name
- `type`: `branch` (sent again whenever its libraries change, the file replaced) or `release` (sent once; the latest three of a project are kept, older ones deleted by the watcher)
- `commit`, `sent`: the commit the list was made from, and when it was sent (UTC)
- `packages`: each `ecosystem` as OSV.dev names it (`NuGet`, `PyPI`, `npm`, `Maven` as `group:artifact`…), `name`, `version` (the one resolved, transitive ones included) and `direct` (the project asks for it itself)
- `dotnetSdk`: the SDK in its `global.json`, when it has one
- `images`: the container images it builds from or runs, listed, not scanned
- Never a secret, a client, a server, a domain or an address

## Work Guidance

- A project sends only when its list changed: it compares what it would send with the file here, without `sent` and `commit`
- Nobody edits an inventory by hand: the watcher writes every file here

## Verification

- An inventory issue starts the Watch workflow, which answers it (taken, with what stops a build, or why it was refused) and closes it within minutes

## Child DOX Index

- None
