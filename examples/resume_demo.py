"""Interrupted investigation, then resume.

Run: python examples/resume_demo.py [--db PATH]

Process 1 creates a lab, a plan with three steps, runs it, and is interrupted (simulated by a
BaseException that is not an Exception) in the middle of step 2 after a checkpoint. Process 2
opens the same store, finds step 2 STARTED with no terminal event, marks it INTERRUPTED with
PARTIAL outputs, refuses to complete the plan, resumes without re-running step 1, and then
completes. The clock is injected, so the record content is deterministic.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from research_lab.clock import StepClock  # noqa: E402
from research_lab.graph import Graph  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.lifecycle import IncompleteInvestigation  # noqa: E402
from research_lab.orchestration import Runner, StepContext, create_plan  # noqa: E402
from research_lab.records import Actor, ActorKind, Kind  # noqa: E402
from research_lab.store import Principal  # noqa: E402

TENANT = "demo-tenant"
PRINCIPAL = Principal("demo-operator", frozenset({TENANT}))
OPERATOR = Actor("demo-operator", ActorKind.HUMAN)


class SimulatedCrash(BaseException):
    """Not an Exception on purpose: the runner records nothing for it, like a killed process."""


def summary(runner: Runner) -> dict[str, str]:
    return {run.step: f"{run.state.value}/{run.output_state.value}/attempts={run.attempts}" for run in runner.states().values()}


def process_one(db: str, calls: dict[str, int]) -> str:
    print("== process 1: create the lab and the plan, then crash inside step 2")
    with Lab.create(db, TENANT, PRINCIPAL, ["governance-board"], StepClock("2026-03-01T09:00:00Z")) as lab:
        objective = lab.add(Kind.OBJECTIVE, {"title": "Does resume preserve completed work?"}, OPERATOR)
        plan, _tasks = create_plan(lab, OPERATOR, "resume demo", ["gather", "analyse", "report"], pursues=objective.entity_id)
        runner = Runner(lab, plan.entity_id, OPERATOR)

        def gather(ctx: StepContext) -> dict:
            calls["gather"] += 1
            return {"items": 3}

        def analyse(ctx: StepContext) -> dict:
            calls["analyse"] += 1
            ctx.checkpoint({"analysed": 1, "of": 3})
            raise SimulatedCrash()

        runner.register("gather", gather)
        runner.register("analyse", analyse)
        runner.register("report", lambda ctx: {"unreachable": True})
        try:
            runner.run()
        except SimulatedCrash:
            print("   crash while running step 'analyse' (after one checkpoint)")
        print("   states as left on disk:", json.dumps(summary(runner), sort_keys=True))
        return plan.entity_id


def process_two(db: str, plan_id: str, calls: dict[str, int]) -> None:
    print("== process 2: reopen the store and resume")
    with Lab.open(db, TENANT, PRINCIPAL, StepClock("2026-03-01T10:00:00Z")) as lab:
        runner = Runner(lab, plan_id, OPERATOR)
        print("   states before reconcile:", json.dumps(summary(runner), sort_keys=True))
        interrupted = runner.reconcile()
        print(f"   reconcile marked {len(interrupted)} task(s) INTERRUPTED with PARTIAL outputs")
        print("   states after reconcile: ", json.dumps(summary(runner), sort_keys=True))
        try:
            runner.complete("premature")
        except IncompleteInvestigation as exc:
            print("   complete() refused:", exc)

        def gather(ctx: StepContext) -> dict:
            calls["gather"] += 1
            return {"items": 3}

        def analyse(ctx: StepContext) -> dict:
            calls["analyse"] += 1
            return {"analysed": 3, "of": 3}

        runner.register("gather", gather)
        runner.register("analyse", analyse)
        runner.register("report", lambda ctx: {"written": True})
        runner.run()
        print("   states after resume:    ", json.dumps(summary(runner), sort_keys=True))
        plan = runner.complete("all steps completed")
        print("   plan status:", plan.disposition)
        print("   step call counts across both processes:", json.dumps(calls, sort_keys=True))
        print("   gather ran once in total: completed steps are not re-run on resume" if calls["gather"] == 1 else "   UNEXPECTED: gather re-ran")
        result = lab.verify()
        print("   store verify:", "ok" if result.ok else result.problems, f"({result.events_checked} events)")
        rebuilt = Graph.rebuild(lab.store.events())
        print("   graph rebuilt from log equals live graph:", rebuilt == lab.graph)
        history = [record.disposition for record in lab.graph.history(plan_id)]
        print("   plan history:", history)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=None, help="store path; default is a fresh temporary file")
    args = parser.parse_args(argv)
    workdir = None
    db = args.db
    if db is None:
        workdir = tempfile.TemporaryDirectory()
        db = os.path.join(workdir.name, "resume_demo.sqlite")
    calls = {"gather": 0, "analyse": 0}
    try:
        plan_id = process_one(db, calls)
        process_two(db, plan_id, calls)
    finally:
        if workdir is not None:
            workdir.cleanup()
    return 0 if calls["gather"] == 1 else 1


if __name__ == "__main__":
    sys.exit(main())
