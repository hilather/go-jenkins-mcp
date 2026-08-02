#!/usr/bin/env python3
"""Validate docs/jenkins-mcp-enterprise-task-index.json (FND/FLC DAG hygiene).

Exit 0 when: unique IDs, known deps, no self/dup deps, acyclic graph.
Prints a short report suitable for CI/scratch capture.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "docs" / "jenkins-mcp-enterprise-task-index.json"
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])

    data = json.loads(path.read_text())
    tasks = data.get("tasks") or []
    errors: list[str] = []

    ids = [t["id"] for t in tasks]
    if len(ids) != len(set(ids)):
        seen: set[str] = set()
        dups = []
        for i in ids:
            if i in seen:
                dups.append(i)
            seen.add(i)
        errors.append(f"duplicate ids: {sorted(set(dups))}")

    by_id = {t["id"]: t for t in tasks}
    for t in tasks:
        tid = t["id"]
        deps = t.get("dependencies") or []
        if len(deps) != len(set(deps)):
            errors.append(f"{tid}: duplicate dependency entries")
        if tid in deps:
            errors.append(f"{tid}: self-dependency")
        for d in deps:
            if d not in by_id:
                errors.append(f"{tid}: missing dependency {d}")

    # cycle detect
    indeg = {t["id"]: 0 for t in tasks}
    children: dict[str, list[str]] = defaultdict(list)
    for t in tasks:
        for d in t.get("dependencies") or []:
            if d in by_id:
                indeg[t["id"]] += 1
                children[d].append(t["id"])
    q = deque(sorted([i for i, g in indeg.items() if g == 0]))
    ordered = 0
    while q:
        n = q.popleft()
        ordered += 1
        for c in sorted(children[n]):
            indeg[c] -= 1
            if indeg[c] == 0:
                q.append(c)
    if ordered != len(tasks):
        errors.append(f"cycle or unreachable: ordered {ordered} of {len(tasks)}")

    flc = [t for t in tasks if str(t["id"]).startswith("FLC-")]
    # Only flag notes that claim runtime peer-cache implementation is Done.
    # Phrases like "no runtime Done claim" or "runtime … still Planned" are OK.
    flc_false_done: list[str] = []
    for t in flc:
        sn = (t.get("status_note") or "").strip()
        low = sn.lower()
        if not sn:
            continue
        if low.startswith("planned"):
            continue
        if "still planned" in low or "no runtime done" in low:
            continue
        if "peer" in low and "planned" in low:
            # Done* foundation while peer-read/protocol still Planned is OK
            continue
        if "docs" in low and "runtime" in low and "planned" in low:
            # e.g. Done (docs) — runtime peer cache still Planned
            continue
        if "offline" in low and "not done" in low:
            continue
        if low.startswith("done") and "docs" not in low and "done*" not in low[:8]:
            flc_false_done.append(t["id"])
        # Done* with explicit residual language is allowed; bare "Done" without residual is not.
        if low.startswith("done ") and "planned" not in low and "residual" not in low:
            flc_false_done.append(t["id"])

    print(f"task_index: {path}")
    print(f"task_count: {len(tasks)}")
    print(f"flc_task_count: {len(flc)}")
    print(f"dependency_edges: {sum(len(t.get('dependencies') or []) for t in tasks)}")
    print(f"unique_task_ids: {len(ids) == len(set(ids))}")
    print(f"known_dependencies: {not any('missing dependency' in e for e in errors)}")
    print(f"acyclic_dependency_graph: {ordered == len(tasks)}")
    print(f"flc_runtime_false_done_claims: {len(flc_false_done)}")
    if flc_false_done:
        errors.append(f"FLC runtime false Done: {flc_false_done}")

    if errors:
        print("STATUS: FAIL")
        for e in errors:
            print(f"  error: {e}")
        return 1

    print("STATUS: OK")
    print("zero duplicate/missing-dep/cycle findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
