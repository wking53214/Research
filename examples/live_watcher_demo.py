"""Live demo through WATCHER_MCU: one investigation with a real model. NOT run by any test.

This script makes a model call only when BOTH hold: the flag --live is given, and
WATCHER_MCU reports that a credential exists (watcher.narrate.credentials_present()). In
every other case it prints why, makes no call and exits with code 2. The credential stays
with WATCHER_MCU: this script never reads, prints or logs it, and the lab never sees it.

It needs a WATCHER_MCU checkout that has the generic port (watcher/port.py) on PYTHONPATH,
with WATCHER_MCU's own dependencies installed. The answer of a live model is a proposal:
the lab records it as AI-origin records and checks each quote against the preserved source.

As of this file's writing the live path has never been executed.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from research_lab.ai import STACK_PROFILE, AIError, WatcherAIPort, load_watcher_call  # noqa: E402
from research_lab.clock import SystemClock  # noqa: E402
from research_lab.investigation import run_investigation  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.records import Actor, ActorKind, Kind  # noqa: E402
from research_lab.sources import LocalFileSource  # noqa: E402
from research_lab.store import Principal  # noqa: E402

EXIT_NOT_RUN = 2
TENANT = "demo-tenant"
PRINCIPAL = Principal("demo-operator", frozenset({TENANT}))
OPERATOR = Actor("demo-operator", ActorKind.HUMAN)
RUNNER = Actor("investigation-runner", ActorKind.SYSTEM)
LOCAL = Actor("local-filesystem", ActorKind.SYSTEM)


def not_run(reason: str) -> int:
    print(f"live_watcher_demo: not run, no call was made: {reason}", file=sys.stderr)
    return EXIT_NOT_RUN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="required; without it nothing is called")
    parser.add_argument("--source", help="a local text file to investigate (required with --live)")
    parser.add_argument("--objective", default="What does this source establish?")
    parser.add_argument("--model", default=None, help="model id; default is WATCHER_MCU's DEFAULT_MODEL")
    parser.add_argument("--max-output-tokens", type=int, default=800)
    args = parser.parse_args(argv)
    if not args.live:
        return not_run("pass --live to make a real model call through WATCHER_MCU (it also needs a credential that WATCHER_MCU can see)")
    try:
        call = load_watcher_call()
        narrate = importlib.import_module("watcher.narrate")
    except (AIError, ImportError) as exc:
        return not_run(f"{exc}. Put a WATCHER_MCU checkout that has watcher/port.py on PYTHONPATH")
    if not narrate.credentials_present():
        return not_run("WATCHER_MCU reports no credential (watcher.narrate.credentials_present() is false)")
    if not args.source or not os.path.isfile(args.source):
        return not_run("--source must name an existing local text file")

    clock = SystemClock()
    source_path = os.path.realpath(args.source)
    port = WatcherAIPort(call, clock=clock, model=args.model or narrate.DEFAULT_MODEL)
    print(f"== LIVE: one call through WATCHER_MCU, model requested {port.model!r}, policy profile {STACK_PROFILE.name!r}")
    with tempfile.TemporaryDirectory() as workdir:
        lab = Lab.create(os.path.join(workdir, "lab.sqlite"), TENANT, PRINCIPAL, [], clock, blob_root=os.path.join(workdir, "blobs"))
        objective = lab.add(Kind.OBJECTIVE, {"title": args.objective}, OPERATOR)
        document = LocalFileSource([os.path.dirname(source_path)], clock).fetch(source_path)
        summary = run_investigation(lab, objective.entity_id, [(document, LOCAL)], [port], STACK_PROFILE, RUNNER, max_output_tokens=args.max_output_tokens)
        print(f"== complete={summary.complete} failed={summary.failed} unverified citations={summary.unverified_citations}")
        for hid in summary.hypotheses:
            node = lab.graph.node(hid)
            block = node.latest.provenance[0]
            print(f"   {hid} model_reported={block['model_reported']!r} is_live={block['is_live']} {node.latest.body['text'][:100]!r} citations {node.latest.body['citation_summary']}")
        print(f"== lab verify: {lab.verify().ok}; sources verify: {lab.verify_sources().ok} (the lab was in a temporary folder and is now removed)")
        lab.close()
    return 0 if summary.complete else 1


if __name__ == "__main__":
    sys.exit(main())
