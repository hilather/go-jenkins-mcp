#!/usr/bin/env bash
# Documentation CI: required pages, no legacy SoT paths, policy greps, links, mermaid, coverage.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0
note() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; fail=1; }

note "== required pages =="
required=(
  README.md docs/README.md
  docs/getting-started/README.md docs/getting-started/local-native.md
  docs/getting-started/local-docker.md docs/getting-started/server.md
  docs/architecture/README.md docs/features/README.md docs/integrations/README.md
  docs/testing/qualification.md docs/deployment/README.md
  AGENTS.md CONTRIBUTING.md
)
for f in "${required[@]}"; do
  [[ -f "$f" ]] || err "missing $f"
done

note "== legacy paths must be gone =="
for f in \
  docs/jenkins-mcp-enterprise-agent-todo.md \
  docs/jenkins-mcp-enterprise-architecture.md \
  docs/jenkins-mcp-enterprise-task-index.json \
  docs/phase0-progress.md docs/phase1-progress.md docs/phase2-progress.md \
  docs/README-jenkins-mcp-enterprise-planning-pack.md
do
  [[ -e "$f" ]] && err "legacy path still present: $f"
done

note "== policy scan (active docs) =="
python3 - <<'PY'
import re, sys
from pathlib import Path

skip = {"archive", "release"}
files = [Path("README.md"), Path("AGENTS.md"), Path("CONTRIBUTING.md")]
files += [p for p in Path("docs").rglob("*.md") if not any(s in p.parts for s in skip)]

forbid = [
    (re.compile(r"Done\*"), "Done* marker"),
    (re.compile(r"phase[0-9]-progress"), "phase board path"),
    (re.compile(r"(?<!archive/)jenkins-mcp-enterprise-agent-todo\.md"), "agent-todo as active path"),
    (re.compile(r"(?<!archive/)jenkins-mcp-enterprise-task-index\.json"), "task-index as active path"),
    (re.compile(r"README-jenkins-mcp-enterprise-planning-pack"), "planning pack"),
]
allow = re.compile(
    r"archive/|must not|Do \*\*not\*\*|do not|never|forbid|not .*SoT|open work|GitHub Issues|remove|No phase|no phase|not treat|Historical",
    re.I,
)
errs = []
for f in files:
    text = f.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        if allow.search(line):
            continue
        for rx, label in forbid:
            if rx.search(line):
                errs.append(f"{f}:{i}: {label}: {line.strip()[:100]}")
if errs:
    print("FORBIDDEN:")
    for e in errs[:60]:
        print(" ", e)
    if len(errs) > 60:
        print(f"  ... +{len(errs)-60} more")
    sys.exit(1)
print("policy clean")
PY
[[ $? -eq 0 ]] || fail=1

note "== relative links =="
python3 - <<'PY'
import re, sys
from pathlib import Path
link_re = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
files = [Path("README.md"), Path("AGENTS.md"), Path("CONTRIBUTING.md")]
files += [p for p in Path("docs").rglob("*.md") if "archive" not in p.parts]
missing = []
checked = 0
for f in files:
    if not f.is_file():
        continue
    text = f.read_text(encoding="utf-8", errors="replace")
    for m in link_re.finditer(text):
        target = m.group(2).strip()
        if target.startswith(("http://", "https://", "mailto:", "#")) or "://" in target:
            continue
        path_part = target.split("#", 1)[0].split("?", 1)[0]
        if not path_part:
            continue
        dest = (f.parent / path_part).resolve()
        checked += 1
        root = Path(".").resolve()
        try:
            dest.relative_to(root)
        except ValueError:
            continue
        if not dest.exists():
            missing.append(f"{f} -> {target}")
print(f"checked {checked} links")
if missing:
    print("BROKEN:")
    for m in missing[:80]:
        print(" ", m)
    sys.exit(1)
print("links ok")
PY
[[ $? -eq 0 ]] || fail=1

note "== mermaid architecture =="
mc=$(grep -l '```mermaid' docs/architecture/*.md 2>/dev/null | wc -l)
[[ "$mc" -ge 5 ]] || err "need >=5 mermaid architecture pages, got $mc"
note "mermaid pages: $mc"

note "== support labels on indexes =="
for f in docs/features/README.md docs/integrations/README.md; do
  grep -qE 'Supported|Opt-in|Experimental|Stub|Not implemented' "$f" || err "$f missing labels"
done

note "== quick starts =="
for f in docs/getting-started/local-native.md docs/getting-started/local-docker.md docs/getting-started/server.md; do
  grep -qiE 'read-only|read only|--read-only' "$f" || err "$f missing RO default"
done
grep -qi 'remote Jenkins' docs/getting-started/local-docker.md || err "local-docker must say remote Jenkins"

note "== root README =="
if grep -nE 'phase0-progress|agent backlog|\*\*Release\*\*.*RELEASE_NOTES|Done\*' README.md; then
  err "README looks like status board"
fi
for path in docs/getting-started/local-native.md docs/getting-started/local-docker.md docs/getting-started/server.md; do
  grep -q "$path" README.md || err "README missing link $path"
done

# Integration coverage: registered tool namespaces mentioned
note "== integration coverage (namespaces) =="
for ns in jenkins_ admin_ fleet_; do
  grep -rq "$ns" docs/features docs/integrations docs/tool-contracts.md || err "missing docs mention of ${ns}* tools"
done

[[ $fail -eq 0 ]] || { note "docs-check FAILED"; exit 1; }
note "docs-check OK"
exit 0
