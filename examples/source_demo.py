"""Sources demo: fetch, preserve, re-fetch, detect change, detect a tampered blob.

Run: python examples/source_demo.py            (offline: GitHub served from tests/fixtures/github)
     python examples/source_demo.py --live     (two real GETs to https://api.github.com)

What it shows: the README of wking53214/WATCHER_MCU fetched through GitHubSource with its
commit and blob pinned; a local file read through LocalFileSource inside an explicit allowed
root; both recorded as sources in a temporary lab; an identical re-fetch recorded nowhere
(idempotent); a local file changed and re-recorded as a superseding source; verify_sources
passing, then failing after a blob is modified on disk.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from research_lab.clock import StepClock  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.records import Actor, ActorKind  # noqa: E402
from research_lab.sources import FixtureTransport, GitHubSource, LocalFileSource, urllib_transport  # noqa: E402
from research_lab.store import Principal  # noqa: E402

TENANT = "demo-tenant"
PRINCIPAL = Principal("demo-operator", frozenset({TENANT}))
GITHUB = Actor("github.com", ActorKind.EXTERNAL)
LOCAL = Actor("local-filesystem", ActorKind.SYSTEM)
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "github")
LOCAL_ROOT = "/home/user/WATCHER_MCU/watcher"
LOCAL_FILE = os.path.join(LOCAL_ROOT, "narrate.py")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="use the network instead of recorded fixtures")
    parser.add_argument("--local-root", default=LOCAL_ROOT, help="allowed root for the local file example")
    parser.add_argument("--local-file", default=LOCAL_FILE, help="local file to read (inside --local-root)")
    args = parser.parse_args(argv)
    clock = StepClock("2026-03-02T09:00:00Z")
    transport = urllib_transport if args.live else FixtureTransport(FIXTURES)
    print("== mode:", "LIVE (https://api.github.com)" if args.live else f"offline fixtures from {FIXTURES}")

    with tempfile.TemporaryDirectory() as workdir:
        db = os.path.join(workdir, "lab.sqlite")
        blob_root = os.path.join(workdir, "blobs")
        lab = Lab.create(db, TENANT, PRINCIPAL, ["governance-board"], clock, blob_root=blob_root)

        github = GitHubSource(transport, clock)
        readme = github.fetch_file("wking53214", "WATCHER_MCU", "README.md", ref="main")
        print(f"== GitHub: {readme.locator}")
        print(f"   commit {readme.pinned['commit_sha']} blob {readme.pinned['blob_sha']} {readme.size} bytes sha256 {readme.content_digest[:16]}...")
        first = lab.record_source(readme, GITHUB)
        print(f"   recorded {first.record.entity_id} created={first.created} changed={first.changed}")
        again = lab.record_source(github.fetch_file("wking53214", "WATCHER_MCU", "README.md", ref="main"), GITHUB)
        print(f"   re-fetch: same record {again.record.entity_id == first.record.entity_id} created={again.created} (idempotent, no new event)")

        if os.path.isdir(args.local_root) and os.path.isfile(args.local_file):
            local = LocalFileSource([args.local_root], clock)
            doc = local.fetch(args.local_file)
            rec = lab.record_source(doc, LOCAL)
            print(f"== local file: {doc.locator} ({doc.size} bytes) recorded {rec.record.entity_id} created={rec.created}")
            try:
                local.fetch("/etc/hostname")
            except Exception as exc:  # noqa: BLE001
                print(f"   outside the allowed root refused: {type(exc).__name__}: {exc}")
        else:
            print(f"== local file example skipped: {args.local_file} not available")

        scratch_root = os.path.join(workdir, "inputs")
        os.makedirs(scratch_root)
        changing = os.path.join(scratch_root, "dataset.csv")
        with open(changing, "w", encoding="utf-8") as handle:
            handle.write("a,b\n1,2\n")
        scratch = LocalFileSource([scratch_root], clock)
        v1 = lab.record_source(scratch.fetch(changing), LOCAL)
        with open(changing, "a", encoding="utf-8") as handle:
            handle.write("3,4\n")
        v2 = lab.record_source(scratch.fetch(changing), LOCAL)
        print(f"== changed source: {v1.record.entity_id} -> {v2.record.entity_id} changed={v2.changed} previous={v2.previous_id}")
        print(f"   old status: {lab.graph.node(v1.record.entity_id).status}; change block: {v2.record.body['change']['type']}")

        check = lab.verify_sources()
        print(f"== verify_sources: ok={check.ok} checked={check.checked}")
        blob_path = lab.blobs._path(v2.record.body["blob_digest"])
        os.chmod(blob_path, 0o644)
        with open(blob_path, "ab") as handle:
            handle.write(b"tampered\n")
        check = lab.verify_sources()
        print(f"== after tampering one blob on disk: ok={check.ok} problems={check.problems}")
        print(f"== chain verify: ok={lab.verify().ok} ({lab.store.count()} events)")
        lab.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
