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
   .NET SDK and its images, in a ```json block. Its token can open issues
   and nothing else: no project can write a file here. The watcher takes
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
   ref it is building, and stops on anything moderate or worse.

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
  mails it.

## Rules

- **Nothing here names a client**, a server, a domain, an address or a
  person: a project's name and its libraries only.
- **No secrets**: a project's token lives in that project, never here, and
  can only open issues.
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
