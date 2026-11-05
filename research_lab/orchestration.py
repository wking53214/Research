"""Plans, tasks and a small resumable runner.

A plan is a record of kind plan; each step is a record of kind task linked PART_OF the plan.
Steps are callables registered under the task's step name, which is the idempotency key
within that plan. Every execution writes RUN_STARTED and then RUN_COMPLETED or RUN_FAILED.
A step may write RUN_PROGRESS checkpoints.

On resume, a task with RUN_STARTED and no terminal event is marked RUN_INTERRUPTED and its
outputs are marked PARTIAL. Completed steps are never re-run. complete() refuses to close
the plan while any task is PARTIAL, INTERRUPTED, FAILED or never run; Lab.transition
enforces the same rule for anyone closing a plan without the Runner.

Run state is derived from the event log through the graph, never kept only in memory, so a
new process can resume from the store alone.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

from .canonical import CanonicalError, normalize
from .graph import (
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_INTERRUPTED,
    RUN_PROGRESS,
    RUN_STARTED,
    EdgeType,
    Node,
    OutputState,
    TaskRun,
    TaskState,
)
from .lab import Lab
from .lifecycle import IncompleteInvestigation, ThreadStatus
from .records import Actor, Kind, Record
from .store import Event

__all__ = [
    "IncompleteInvestigation",
    "OrchestrationError",
    "OutputState",
    "Runner",
    "StepContext",
    "StepFailed",
    "TaskRun",
    "TaskState",
    "UnregisteredStep",
    "create_plan",
]


class OrchestrationError(Exception):
    """Base class for orchestration failures."""


class UnregisteredStep(OrchestrationError):
    """A plan task has no registered callable."""


class StepFailed(OrchestrationError):
    """A step raised; RUN_FAILED was recorded before this was raised."""


def create_plan(
    lab: Lab, actor: Actor, title: str, steps: Sequence[str], pursues: str | None = None
) -> tuple[Record, list[Record]]:
    """Add a plan record and one task record per step, linked PART_OF the plan."""
    if not steps:
        raise OrchestrationError("a plan needs at least one step")
    if len(set(steps)) != len(steps) or not all(isinstance(step, str) and step for step in steps):
        raise OrchestrationError("step names must be unique non-empty strings")
    edges = [(EdgeType.PURSUES, pursues)] if pursues else []
    plan = lab.add(Kind.PLAN, {"title": title, "steps": list(steps)}, actor, edges=edges)
    tasks = [
        lab.add(
            Kind.TASK,
            {"plan": plan.entity_id, "step": step, "index": index},
            actor,
            edges=[(EdgeType.PART_OF, plan.entity_id)],
        )
        for index, step in enumerate(steps)
    ]
    return plan, tasks


class StepContext:
    """What a step callable receives."""

    def __init__(self, runner: "Runner", run: TaskRun, attempt: int) -> None:
        self._runner = runner
        self.task_id = run.task_id
        self.step = run.step
        self.attempt = attempt
        self.lab = runner.lab

    def checkpoint(self, data: Any) -> None:
        """Record partial output. If the run is interrupted this is what PARTIAL refers to."""
        self._runner._emit(RUN_PROGRESS, self.task_id, self.step, self.attempt, data=data)


class Runner:
    def __init__(self, lab: Lab, plan_id: str, actor: Actor) -> None:
        self.lab = lab
        self.actor = actor
        self.plan_id = plan_id
        self.tasks: list[Node] = lab.graph.plan_tasks(plan_id)
        self._steps: dict[str, Callable[[StepContext], Any]] = {}

    def register(self, step: str, fn: Callable[[StepContext], Any]) -> None:
        self._steps[step] = fn

    def states(self) -> dict[str, TaskRun]:
        return self.lab.graph.run_states(self.plan_id)

    def _emit(self, event_type: str, task_id: str, step: str, attempt: int, **extra: Any) -> Event:
        payload = {
            "plan": self.plan_id,
            "task": task_id,
            "step": step,
            "idempotency_key": f"{self.plan_id}:{step}",
            "attempt": attempt,
            "actor": self.actor.to_dict(),
            "created_at": self.lab.clock.now(),
            **extra,
        }
        return self.lab._emit(event_type, payload)

    def reconcile(self) -> list[str]:
        """Mark every STARTED-but-unfinished task INTERRUPTED with PARTIAL outputs."""
        interrupted = []
        for run in self.states().values():
            if run.state is TaskState.STARTED:
                self._emit(RUN_INTERRUPTED, run.task_id, run.step, run.attempts, output_state=OutputState.PARTIAL.value)
                interrupted.append(run.task_id)
        return interrupted

    def run(self) -> dict[str, TaskRun]:
        """Reconcile, then run every task that has not COMPLETED, in plan order."""
        self.reconcile()
        for node in self.tasks:
            run = self.states()[node.entity_id]
            if run.state is TaskState.COMPLETED:
                continue
            fn = self._steps.get(run.step)
            if fn is None:
                raise UnregisteredStep(f"no callable registered for step {run.step!r}")
            attempt = run.attempts + 1
            self._emit(RUN_STARTED, run.task_id, run.step, attempt)
            context = StepContext(self, run, attempt)
            try:
                output = normalize(fn(context))
            except CanonicalError as exc:
                self._emit(RUN_FAILED, run.task_id, run.step, attempt, error=f"output not canonical JSON: {exc}")
                raise StepFailed(f"step {run.step!r}: output not canonical JSON") from exc
            except Exception as exc:
                self._emit(RUN_FAILED, run.task_id, run.step, attempt, error=f"{type(exc).__name__}: {exc}")
                raise StepFailed(f"step {run.step!r} failed: {exc}") from exc
            # A BaseException that is not an Exception (KeyboardInterrupt, SystemExit, a simulated
            # crash) propagates with nothing written: that is what an interruption looks like.
            self._emit(RUN_COMPLETED, run.task_id, run.step, attempt, output=output)
        return self.states()

    def incomplete(self) -> list[TaskRun]:
        return [run for run in self.states().values() if run.state is not TaskState.COMPLETED]

    def complete(self, reason: str) -> Record:
        """Close the tasks and the plan. Refused while any task is not COMPLETED."""
        offenders = self.incomplete()
        if offenders:
            detail = ", ".join(f"{run.step}={run.state.value}/{run.output_state.value}" for run in offenders)
            raise IncompleteInvestigation(f"plan {self.plan_id} cannot be completed: {detail}")
        for node in self.tasks:
            if node.status == ThreadStatus.OPEN.value:
                self.lab.transition(node.entity_id, ThreadStatus.CLOSED.value, self.actor, reason)
        return self.lab.transition(self.plan_id, ThreadStatus.CLOSED.value, self.actor, reason)
