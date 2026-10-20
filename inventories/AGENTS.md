# inventories

## Purpose

- What each project sends: `<project>/<ref>.json`, every library one of its branches or releases uses, at its exact version

## Ownership

- The inventory's shape; the projects own their content and send it themselves, with a token that writes to this repository alone

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
- Nobody edits an inventory by hand

## Verification

- A push here starts the Watch workflow; the project's status file shows what was read within minutes

## Child DOX Index

- None
