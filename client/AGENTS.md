# client

## Purpose

- `SecurityWatch.ps1`: the one script every project's builds use to ask security-watch before a build and send it their list of libraries after
- `scan-secrets.py`: the secrets in a repository's whole history, run before a private repository is made public

## Ownership

- The client's behavior; each project keeps a copy of it and owns where its own scripts call it

## Local Contracts

- A project sets `$SecurityWatchProject` (its name in `projects.txt`) and dot-sources its copy; the project's repository is the one the copy lives in
- `Test-SecurityWatch [-Ref]`: first thing in a build; reads `status/<project>.json` for the ref (the branch, or the tag on a release's build on GitHub); a finding with `blocking` stops the build, any other warns; unreachable asks whether to go on, and stops on GitHub Actions
- `Send-SecurityWatchInventory [-Ref]`: once a build succeeded; only for `main`, `develop` and release tags, never on GitHub Actions; sends only when the list differs from `inventories/<project>/<ref>.json`, ignoring `sent` and `commit`; opens the inventory issue as whoever `gh` is signed in as, with no token of its own
- The list: NuGet from every restored project's `obj/project.assets.json` (transitive ones included) and the versions asked for (`Directory.Packages.props`, or each project file's `PackageReference`); PyPI from every tracked requirements file's pinned lines; the SDK from `global.json`, or the one installed; images from every tracked Dockerfile and Compose file
- A project's release script sends its release's list itself, when it tags it
- `scan-secrets.py <owner/repo | folder>`: every branch, pull request and commit; tokens by their shape, masked, and values assigned to key-like names that mix letters and digits with no dot (examples such as `your_..._here` left out); exits 1 when a token is found; a GitHub repository is mirror-cloned apart with this machine's git sign-in

## Work Guidance

- A change here is copied into every project that uses it, in the same piece of work; [README.md](../README.md) lists how a project joins
- A new ecosystem in the list needs its name as OSV.dev gives it, and a case in the watcher's newest-version lookup ([watch/AGENTS.md](../watch/AGENTS.md))

## Verification

- A project's build: it says whether it asked, what it found, and whether it sent; the inventory issue it opens is answered and closed within minutes

## Child DOX Index

- None
