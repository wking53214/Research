import math

import pytest
from conftest import ISSUERS, LEGACY_MODE, TENANT

from research_lab.clock import StepClock
from research_lab.graph import RUN_COMPLETED, RUN_FAILED, RUN_INTERRUPTED, RUN_PROGRESS, RUN_STARTED, EdgeType, Graph, TaskState
from research_lab.lab import Lab
from research_lab.lifecycle import IncompleteInvestigation
from research_lab.orchestration import OrchestrationError, Runner, StepFailed, UnregisteredStep, create_plan
from research_lab.records import Kind


class Crash(BaseException):
    """Simulates a killed process: not an Exception, so the runner writes nothing for it."""


def run_types(lab, plan_id):
    return [e.event_type for e in lab.store.events() if e.payload.get("plan") == plan_id and e.event_type.startswith("RUN_")]


def test_create_plan_builds_tasks_and_edges(lab, human):
    objective = lab.add(Kind.OBJECTIVE, {"title": "O"}, human)
    plan, tasks = create_plan(lab, human, "P", ["a", "b"], pursues=objective.entity_id)
    assert plan.kind is Kind.PLAN and plan.body["steps"] == ["a", "b"]
    assert [t.body["step"] for t in tasks] == ["a", "b"]
    assert lab.graph.edges_from(plan.entity_id, EdgeType.PURSUES)[0].to_id == objective.entity_id
    assert [n.entity_id for n in lab.graph.plan_tasks(plan.entity_id)] == [t.entity_id for t in tasks]
    assert all(run.state is TaskState.PENDING for run in lab.graph.run_states(plan.entity_id).values())
    with pytest.raises(OrchestrationError, match="at least one"):
        create_plan(lab, human, "empty", [])
    with pytest.raises(OrchestrationError, match="unique"):
        create_plan(lab, human, "dup", ["a", "a"])


def test_run_writes_started_then_completed_and_complete_closes(lab, human):
    plan, tasks = create_plan(lab, human, "P", ["a", "b"])
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: {"n": 1})
    runner.register("b", lambda ctx: [ctx.step, ctx.attempt])
    states = runner.run()
    assert all(run.state is TaskState.COMPLETED for run in states.values())
    assert states[tasks[1].entity_id].output == ["b", 1]
    assert run_types(lab, plan.entity_id) == [RUN_STARTED, RUN_COMPLETED, RUN_STARTED, RUN_COMPLETED]
    started = [e for e in lab.store.events() if e.event_type == RUN_STARTED][0]
    assert started.payload["idempotency_key"] == f"{plan.entity_id}:a"
    closed = runner.complete("done")
    assert closed.disposition == "CLOSED"
    assert all(lab.graph.node(t.entity_id).status == "CLOSED" for t in tasks)
    assert lab.verify().ok


def test_interrupted_run_then_resume(db_path, principal, human):
    calls = {"a": 0, "b": 0, "c": 0}
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), governance_mode=LEGACY_MODE)
    plan, tasks = create_plan(lab, human, "P", ["a", "b", "c"])
    runner = Runner(lab, plan.entity_id, human)

    def a(ctx):
        calls["a"] += 1
        return {"a": True}

    def b(ctx):
        calls["b"] += 1
        ctx.checkpoint({"half": 1})
        raise Crash()

    runner.register("a", a)
    runner.register("b", b)
    runner.register("c", lambda ctx: None)
    with pytest.raises(Crash):
        runner.run()
    assert run_types(lab, plan.entity_id) == [RUN_STARTED, RUN_COMPLETED, RUN_STARTED, RUN_PROGRESS]
    lab.close()

    resumed = Lab.open(db_path, TENANT, principal, StepClock("2026-02-01T00:00:00Z"))
    runner2 = Runner(resumed, plan.entity_id, human)
    before = runner2.states()
    assert before[tasks[1].entity_id].state is TaskState.STARTED
    assert before[tasks[1].entity_id].output_state.value == "PARTIAL"
    assert runner2.reconcile() == [tasks[1].entity_id]
    after = runner2.states()
    assert after[tasks[1].entity_id].state is TaskState.INTERRUPTED
    assert after[tasks[1].entity_id].output_state.value == "PARTIAL"
    assert after[tasks[1].entity_id].partial == [{"half": 1}]
    assert after[tasks[2].entity_id].state is TaskState.PENDING
    with pytest.raises(IncompleteInvestigation, match="b=INTERRUPTED/PARTIAL"):
        runner2.complete("too early")
    assert runner2.reconcile() == []  # idempotent

    def b_ok(ctx):
        calls["b"] += 1
        return {"b": True}

    def c(ctx):
        calls["c"] += 1
        return {"c": True}

    runner2.register("a", a)
    runner2.register("b", b_ok)
    runner2.register("c", c)
    final = runner2.run()
    assert calls == {"a": 1, "b": 2, "c": 1}
    assert final[tasks[1].entity_id].attempts == 2
    assert all(run.state is TaskState.COMPLETED for run in final.values())
    assert run_types(resumed, plan.entity_id) == [
        RUN_STARTED, RUN_COMPLETED, RUN_STARTED, RUN_PROGRESS, RUN_INTERRUPTED, RUN_STARTED, RUN_COMPLETED, RUN_STARTED, RUN_COMPLETED,
    ]
    runner2.complete("resumed and finished")
    assert resumed.graph.node(plan.entity_id).status == "CLOSED"
    assert Graph.rebuild(resumed.store.events()) == resumed.graph
    assert resumed.verify().ok
    resumed.close()


def test_partial_result_cannot_be_reported_complete_by_any_path(lab, human):
    plan, tasks = create_plan(lab, human, "P", ["a", "b"])
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: 1)

    def b(ctx):
        ctx.checkpoint("partial")
        raise Crash()

    runner.register("b", b)
    with pytest.raises(Crash):
        runner.run()
    with pytest.raises(IncompleteInvestigation):
        lab.transition(plan.entity_id, "CLOSED", human, "bypassing the runner")
    runner.reconcile()
    with pytest.raises(IncompleteInvestigation, match="INTERRUPTED/PARTIAL"):
        lab.transition(plan.entity_id, "CLOSED", human, "still bypassing")
    for task in tasks:
        lab.transition(task.entity_id, "CLOSED", human, "closing tasks by hand does not help")
    with pytest.raises(IncompleteInvestigation):
        lab.transition(plan.entity_id, "CLOSED", human, "tasks closed by hand")
    assert lab.graph.node(plan.entity_id).status == "OPEN"


def test_never_run_plan_cannot_be_closed(lab, human):
    plan, _ = create_plan(lab, human, "P", ["a"])
    with pytest.raises(IncompleteInvestigation, match="a=PENDING/NONE"):
        lab.transition(plan.entity_id, "CLOSED", human, "nothing ran")
    plan_without_tasks = lab.add(Kind.PLAN, {"title": "bare"}, human)
    lab.transition(plan_without_tasks.entity_id, "CLOSED", human, "no tasks, nothing partial")


def test_failed_step_is_recorded_and_can_be_retried(lab, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: 1 / 0)
    with pytest.raises(StepFailed, match="division"):
        runner.run()
    state = runner.states()[tasks[0].entity_id]
    assert state.state is TaskState.FAILED and "ZeroDivisionError" in state.error
    assert run_types(lab, plan.entity_id) == [RUN_STARTED, RUN_FAILED]
    with pytest.raises(IncompleteInvestigation, match="a=FAILED"):
        runner.complete("failed")
    runner.register("a", lambda ctx: "fixed")
    assert runner.run()[tasks[0].entity_id].attempts == 2
    runner.complete("ok")


def test_non_canonical_output_is_a_failure(lab, human):
    plan, tasks = create_plan(lab, human, "P", ["a"])
    runner = Runner(lab, plan.entity_id, human)
    runner.register("a", lambda ctx: {"x": math.nan})
    with pytest.raises(StepFailed, match="canonical"):
        runner.run()
    assert runner.states()[tasks[0].entity_id].state is TaskState.FAILED


def test_unregistered_step_writes_nothing(lab, human):
    plan, _ = create_plan(lab, human, "P", ["a"])
    runner = Runner(lab, plan.entity_id, human)
    count = lab.store.count()
    with pytest.raises(UnregisteredStep):
        runner.run()
    assert lab.store.count() == count


def test_runner_rejects_non_plan(lab, human):
    objective = lab.add(Kind.OBJECTIVE, {"title": "O"}, human)
    with pytest.raises(Exception, match="not a plan"):
        Runner(lab, objective.entity_id, human)
