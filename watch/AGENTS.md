# watch

## Purpose

- `watch.cs`: the watcher, a .NET 10 file-based app (`dotnet run watch/watch.cs` from the root), run by the Watch workflow

## Ownership

- How the inventories are checked, and everything written from them: `libraries.json`, `status/<project>.json`, `history.json`, `HISTORY.md`, the issues

## Local Contracts

- First takes every open issue titled `inventory: <project>@<ref>`: accepted only from an author in `submitters.txt`, for a project in `projects.txt`, with a ```json block whose project and ref are the title's, a plain branch or tag name as the ref, and plain, bounded text in every field; saved to `inventories/<project>/<ref>.json`, answered after the check (taken, with what stops a build, or why it was refused) and closed
- Then reads every `inventories/**/*.json`; of each project's releases keeps the latest three by `sent` and deletes the older files
- Each library (ecosystem, name, version) is checked once, however many projects and refs use it: OSV.dev's batch query for its vulnerabilities, each advisory read once; each name's newest stable version read once from its registry (nuget.org, PyPI, npm, Maven Central)
- A `.NET SDK` is checked against .NET's release metadata: every .NET security release after the runtime it bundles is a `security-release` finding, with its CVEs; its newest version is the newest SDK of its band
- Severity: `unknown`, `low`, `moderate`, `high`, `critical`, `security-release`; a ref is `blocking` with `moderate` or worse; `low` and `unknown` only warn
- `libraries.json`: `checked`, and each library's `ecosystem`, `name`, `version`, `latest`, `vulnerabilities`, `usedBy` (`project@ref`)
- `status/<project>.json`: `project`, `checked`, and each ref's `ref`, `type`, `commit`, `sent`, `blocking`, `worst`, `findings` (`ecosystem`, `package`, `version`, `advisory`, `cve`, `severity`, `blocking`, `summary`, `fixedIn`, `url`, `since`), `updates` (direct libraries and the SDK with a newer version), `images`; a project that sends no inventory any more loses its status file
- `history.json`: one entry per project, library, version and advisory, `opened` the first day seen, `closed` the first day gone. `HISTORY.md` is the same, as a table, newest first
- Issues: one per blocking finding first seen, none while an open issue has the same title; inventory issues taken and findings opened only with `GH_TOKEN` set
- Not AOT (`#:property PublishAot=false`): JSON is read and written by reflection

## Work Guidance

- A new ecosystem's newest versions: a case in `Web.LatestAsync`; its vulnerabilities come from OSV.dev already, under the name OSV.dev gives it
- Every registry and advisory answer is read once per run (`Web`'s cache)

## Verification

- The Watch workflow, by hand (Actions → Watch → Run workflow), on a push of an inventory or of the watcher: its log says how many inventories, unique libraries and findings it read, and the committed files show the result

## Child DOX Index

- None
