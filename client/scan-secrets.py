"""Finds secrets in a git repository's whole history: every branch, every
pull request, every commit, not only the files of today. Run it before a
repository is made public: GitHub scans a private repository only once it is
public, when a secret in it is already out.

    python -I client/scan-secrets.py Berpiztu/virtus          # a GitHub repository, cloned apart
    python -I client/scan-secrets.py C:\\IA\\Berpiztu\\keyplus  # a checkout on this machine

Nothing is shown in full: each secret is masked. Two kinds of findings:

- secrets: a token by its very shape (Anthropic, OpenAI, xAI, GitHub,
  Google, AWS, Hugging Face, a private key, an OAuth token in JSON). Each is
  revoked at its service, and taken out of the history before the
  repository is made public.
- to look at: a value assigned to a name such as API_KEY, TOKEN, SECRET or
  PASSWORD. Most are code (`token = Convert…`); the ones that are not are
  secrets too.

Values meant as examples (your_api_key_here, xxx, <token>, changeme…) are
left out. Exits with 1 when a secret is found, 0 otherwise.
"""
import os
import re
import subprocess
import sys
import tempfile

SECRETS = {
    "Anthropic": r"sk-ant-[A-Za-z0-9_\-]{20,}",
    "OpenAI": r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}",
    "xAI": r"xai-[A-Za-z0-9]{20,}",
    "GitHub": r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})",
    "Google": r"AIza[0-9A-Za-z_\-]{30,}",
    "AWS": r"AKIA[0-9A-Z]{16}",
    "Hugging Face": r"hf_[A-Za-z0-9]{30,}",
    "Private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "OAuth token": r"\"(?:access|refresh)_token\"\s*:\s*\"[^\"]{20,}\"",
}
NAMED = re.compile(r"(?i)\b[A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+]{20,})")
EXAMPLE = re.compile(r"(?i)your|example|placeholder|changeme|dummy|sample|x{6,}|replace|here$|<|>|\.\.\.|test")


def looks_like_a_key(value):
    """A key mixes letters and digits and has no dot; code (oauth.load(), max_tokens_cap) does not."""
    return "." not in value and any(c.isdigit() for c in value) and any(c.isalpha() for c in value) and not EXAMPLE.search(value)
COMPILED = {kind: re.compile(p) for kind, p in SECRETS.items()}


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def mask(text):
    return text[:14] + "…" + f"({len(text)} chars)"


def scan(repo):
    found = {}
    commit, date, path = "", "", ""
    for line in git(repo, "log", "--all", "-p", "--no-color", "--format=COMMIT %h %ad", "--date=short").splitlines():
        if line.startswith("COMMIT "):
            _, commit, date = line.split(" ", 2)
            continue
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        hits = [(kind, m.group(0)) for kind, regex in COMPILED.items() for m in regex.finditer(line)]
        hits += [("to look at", m.group(0)) for m in NAMED.finditer(line)
                 if looks_like_a_key(m.group(1)) and not any(m.group(0) in h[1] or h[1] in m.group(0) for h in hits)]
        for kind, text in hits:
            entry = found.setdefault(text, {"kind": kind, "commits": [], "files": set()})
            entry["commits"].append(f"{commit} {date}")
            entry["files"].add(path)
    return found


def report(found, repo):
    head = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() or "HEAD"
    tip = git(repo, "grep", "-I", "-h", "-o", "-E", "|".join(SECRETS.values()), head, "--")
    secrets = {t: e for t, e in found.items() if e["kind"] != "to look at"}
    named = {t: e for t, e in found.items() if e["kind"] == "to look at"}
    for title, group in (("Secrets", secrets), ("To look at", named)):
        print(f"\n{title}: {len(group)}")
        for text, entry in sorted(group.items(), key=lambda e: e[1]["kind"]):
            commits = entry["commits"]
            where = "still in the files of today" if text in tip else "only in the history"
            print(f"  [{entry['kind']}] {mask(text)}, {where}")
            print(f"     first added {commits[-1]}, files: {', '.join(sorted(entry['files']))[:300]}")
    return len(secrets)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    target = sys.argv[1]
    if os.path.isdir(target):
        return 1 if report(scan(target), target) else 0
    # Git leaves its packs read-only, which Windows will not delete: the clone is left to the system.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
        mirror = os.path.join(folder, "repo.git")
        # Cloned as git clones on this machine, so a private repository is read with its sign-in too.
        subprocess.run(["git", "clone", "--quiet", "--mirror", f"https://github.com/{target}.git", mirror], check=True)
        return 1 if report(scan(mirror), mirror) else 0


if __name__ == "__main__":
    sys.exit(main())
