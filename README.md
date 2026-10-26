# security-watch

The libraries Berpiztu's projects use, checked against the known
vulnerabilities and the newest versions. Each project sends its own list;
every library is checked **once**, however many projects use it; and each
project asks for its result before every build.

Anyone can read it; only Berpiztu changes it. It reads no project, and has
access to none: a private project stays private, and only its list of
libraries travels.

## How it works

1. **A project sends its list** on every build, when the list changed: an
   issue titled `inventory: <project>@<ref>`, every library its branch or
   release uses at its exact version, the transitive ones included, its
   .NET SDK and its images, in a ```json block, opened by the account its
   build runs as, as anyone opens an issue: no project writes a file here,
   and needs no token for this repository. The watcher takes
   the list in, saves it to `inventories/<project>/<ref>.json`, answers the
   issue with the result and closes it; only from the accounts in
   [submitters.txt](submitters.txt), for the projects in
   [projects.txt](projects.txt).
2. **The watcher checks every library once**: every list read, each library
   (ecosystem, name, version) asked of [OSV.dev](https://osv.dev) once, each
   name's newest version read once from its registry, each .NET SDK checked
   against .NET's release metadata. It runs as soon as a list arrives, and
   every morning for the advisories published since.
3. **A project asks before every build**: its `status/<project>.json`, the
   ref it is building, and stops on anything moderate or worse. When the
   list security-watch holds is not the one the build uses, the build sends
   its own first and is judged on that one's answer.

```json
{
  "project": "wslc-ai-agent",
  "ref": "develop",
  "type": "branch",
  "commit": "55519a7",
  "sent": "2026-10-20T05:10:00Z",
  "packages": [
    { "ecosystem": "NuGet", "name": "Microsoft.AspNetCore.Components.WebAssembly.Server", "version": "10.0.13", "direct": true },
    { "ecosystem": "PyPI", "name": "flask", "version": "3.1.3", "direct": true }
  ],
  "dotnetSdk": "10.0.402",
  "images": ["nginx:stable", "python:3.12-slim"]
}
```

The shape: [inventories/AGENTS.md](inventories/AGENTS.md). Ecosystems are
OSV.dev's names: `NuGet`, `PyPI`, `npm`, `Maven` (`group:artifact`), and
the others it knows.

## A project joins

1. Its name goes in [projects.txt](projects.txt), and the account its builds
   run as in [submitters.txt](submitters.txt).
2. It keeps a copy of [client/SecurityWatch.ps1](client/SecurityWatch.ps1),
   sets its name and dot-sources it:

   ```powershell
   $SecurityWatchProject = "keyplus"
   . (Join-Path $PSScriptRoot "SecurityWatch.ps1")
   ```

3. Its build scripts call `Test-SecurityWatch` first and
   `Send-SecurityWatchInventory` once built, which waits for the answer and
   says it; its release script calls `Test-SecurityWatch -Release` first,
   which stops until the list it is about to release has been checked (a
   build comes first), and `Send-SecurityWatchInventory` with the release's
   tag when it tags it.

The list is made from what the build restored and asked for: NuGet
(transitive ones included), pinned requirements, the .NET SDK and the
container images. The issue is opened as whoever `gh` is signed in as on
that machine; GitHub Actions only asks.

## Before a repository is made public

GitHub scans a repository for secrets for free once it is public, and
stops a push that carries one: Berpiztu's public repositories, and every new
one, have both on. A private repository is not scanned at all on the free
plan, so a token in its history comes out the moment it is made public.
Before that, look at its whole history (every branch, pull request and
commit) with [client/scan-secrets.py](client/scan-secrets.py):

```powershell
python -I client/scan-secrets.py Berpiztu/<repository>
```

It shows every token by its shape (Anthropic, OpenAI, xAI, GitHub, Google,
AWS, Hugging Face, private keys, OAuth tokens), masked, and the values
assigned to names such as API_KEY or PASSWORD that look like keys. Each
secret is revoked at its service and taken out of the history first; only
then is the repository made public. A folder on this machine works too.

## What a project reads

```
https://raw.githubusercontent.com/Berpiztu/security-watch/main/status/<project>.json
```

Each ref the project sent, with `blocking` (anything moderate, high,
critical, or a .NET security release after the runtime its SDK bundles),
its `worst` severity, its `findings` with the day each was first seen and
the version that fixes it, the newer versions of the libraries it asks for
itself, and its images.

- [libraries.json](libraries.json): every library watched, its
  vulnerabilities, its newest version and who uses it.
- [HISTORY.md](HISTORY.md): every finding, newest first, from the day it
  was opened to the day it was closed.
- A blocking finding seen for the first time opens an **issue**, and GitHub
  mails it; the issue is closed, with a comment, as soon as the finding is
  gone, so the open issues are always the open problems.

## Rules

- **Nothing here names a client**, a server, a domain, an address or a
  person: a project's name and its libraries only.
- **No secrets**: no project holds a token for this repository; it opens an
  issue, as anyone can, and only the listed accounts are listened to.
- **Who may send**: [submitters.txt](submitters.txt) and
  [projects.txt](projects.txt), changed by Berpiztu alone.

## Run it

[.github/workflows/watch.yml](.github/workflows/watch.yml): on every
inventory issue, every morning, by hand from the Actions tab, and when the
watcher or the lists of who may send change. By hand on a machine, from this folder (no issue is opened without
`GH_TOKEN`):

```powershell
dotnet run watch/watch.cs
```

## For AI agents: DOX

This repository is documented for AI agents with **DOX**, from
[Iosub-ai/dox](https://github.com/Iosub-ai/dox), our fork of
[agent0ai/dox](https://github.com/agent0ai/dox): a hierarchy of `AGENTS.md`
files, one at the root with the project's rules and index, and one in each
folder with a contract of its own ([inventories/](inventories/AGENTS.md),
[watch/](watch/AGENTS.md)). An agent reads them from the root down before it
edits, and keeps them current after.

DOX is by [Agent Zero](https://www.agent-zero.ai/), under the
[MIT License](https://github.com/Iosub-ai/dox?tab=License-1-ov-file):
Copyright (c) 2026 Agent Zero.
