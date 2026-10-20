# watch

## Purpose

- `watch.cs`: the watcher, a .NET 10 file-based app (`dotnet run watch/watch.cs` from the root), run by the Watch workflow

## Ownership

- How each project is checked, and everything it writes: `status/<project>.json`, `history.json`, `HISTORY.md`, the issues

## Local Contracts

- Refs: each branch named, and the latest releases (drafts left out); refs whose dependency files are the same are read once
- `nuget`: the central versions (`Directory.Packages.props`) asked of OSV.dev, the MAUI client's included; every project without `<UseMaui>true</UseMaui>` restored with `NuGetAudit=false` and `EnableWindowsTargeting=true`, then `dotnet list package --vulnerable --include-transitive`; newer stable versions from nuget.org
- `dotnet-sdk`: the SDK in `global.json`, the runtime its .NET release bundles, and every later .NET security release as a finding, with its CVEs; a newer SDK in the same band as an update
- `pip`: the pinned lines (`name==version`) asked of OSV.dev; newer versions from PyPI
- `dockerfile`, `compose`: base and service images listed, without build stages, `scratch` or references made of arguments; not scanned
- Severity: `low`, `moderate`, `high`, `critical`, `security-release`, `unknown`; a ref is `blocking` with any `high`, `critical` or `security-release` finding
- `status/<project>.json`: `project`, `repository`, `checked`, `refs` (`ref`, `blocking`), `vulnerable` (`where`, `kind`, `package`, `version`, `advisory`, `cve`, `severity`, `summary`, `fixedIn`, `url`, `since`), `updates`, `images`; or `error` alone when the project could not be read
- `history.json`: one entry per project, package, version and advisory, `opened` the first day seen, `closed` the first day gone; a project that failed closes nothing. `HISTORY.md` is the same, as a table, newest first
- Issues: one per blocking finding first seen, only with `GH_TOKEN` set
- Not AOT (`#:property PublishAot=false`): YAML and JSON are read and written by reflection

## Work Guidance

- A new kind: a static class with its reading, a case in `Sources.ReadAsync`, then [projects/AGENTS.md](../projects/AGENTS.md) and the README's table
- Every registry and advisory answer is read once per run (`Web`'s caches)

## Verification

- The Watch workflow, by hand (Actions → Watch → Run workflow) or on push: its log shows each project and its refs, and the committed status files show the result

## Child DOX Index

- None
