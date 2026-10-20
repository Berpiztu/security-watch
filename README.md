# security-watch

Every day, the dependencies of Berpiztu's projects are checked against the
known vulnerabilities and the newest versions, and the result is kept here:
the state of each project now, and the history of every vulnerability that
ever touched one, from the day it was found to the day it was gone.

Anyone can read it; only Berpiztu changes it.

## What is watched

Each project is one file in [projects/](projects/), saying where the project
writes its dependencies, never the versions themselves: those are read from
the project's own files every day, so they are never out of date here.

```yaml
name: wslc-ai-agent
repository: Berpiztu/wslc-ai-agent
watch:
  branches: [main, develop]   # what is being worked on
  releases: 3                 # and the last releases, which people have installed
sources:
  - file: Directory.Packages.props
    kind: nuget
  - file: global.json
    kind: dotnet-sdk
  - file: app/requirements.txt
    kind: pip
  - file: app/Dockerfile
    kind: dockerfile
```

| Kind | Read from | Checked |
|---|---|---|
| `nuget` | `Directory.Packages.props`, and every project that restores without workloads | known vulnerabilities, direct and transitive; newer versions of the direct ones |
| `dotnet-sdk` | `global.json` | a .NET security release after the runtime that SDK bundles; a newer SDK in its band |
| `pip` | a requirements file's pinned lines (`name==version`) | known vulnerabilities; newer versions |
| `dockerfile`, `compose` | `FROM` and `image:` lines | listed, for now |

Vulnerabilities come from the GitHub Advisory Database (through `dotnet list
package --vulnerable`) and [OSV.dev](https://osv.dev); .NET's releases from
Microsoft's release metadata.

## What a project asks

`status/<project>.json`, at

```
https://raw.githubusercontent.com/Berpiztu/security-watch/main/status/<project>.json
```

```json
{
  "project": "wslc-ai-agent",
  "checked": "2026-10-20T05:23:00Z",
  "refs": [ { "ref": "main", "blocking": false }, { "ref": "v1.6.1", "blocking": true } ],
  "vulnerable": [
    {
      "where": [ "v1.6.1" ],
      "package": "Microsoft.AspNetCore.Components.WebAssembly.Server",
      "version": "10.0.12",
      "advisory": "GHSA-g27p-qf6j-c96c",
      "cve": "CVE-2026-102870",
      "severity": "high",
      "fixedIn": "10.0.13",
      "since": "2026-10-20"
    }
  ],
  "updates": [ ],
  "images": [ ]
}
```

A ref is **blocking** when something there is high, critical, or a .NET
security release: a release made from it would ship that. A project reads
this before it releases, and stops.

## When something is found

- A high, critical or security-release finding seen for the first time opens
  an **issue**, and GitHub mails it.
- [HISTORY.md](HISTORY.md) lists every finding, newest first: when it was
  opened, when it was closed, where, and the version that fixes it. An old
  release keeps its finding open until it is no longer among the releases
  watched.

## Rules

- **Nothing here names a client**, a server, a domain, an address or a
  person: a project's name and its dependencies only.
- **No secrets.** The watcher reads public repositories with the workflow's
  own token, and needs nothing else.

## Run it

Every morning on GitHub ([.github/workflows/watch.yml](.github/workflows/watch.yml)),
by hand from the Actions tab, and whenever `projects/` or the watcher change.
By hand on a machine, from this folder (no issue is opened without
`GH_TOKEN`):

```powershell
dotnet run watch/watch.cs
```
