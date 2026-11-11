"""run_investigation: a multi-source investigation on the resumable Runner.

Steps of the plan: record_sources, one call:<provider_id> per allowed port, analyse.
Every provider call is policy-checked before it is made, idempotent by request digest (a
resumed run reuses a preserved response instead of calling again), stored in the blob
store (request and raw response), parsed strictly, citation-verified, and recorded as
AI-origin proposals with an ai_call provenance block. One provider failing marks only its
own task FAILED; the others continue; the plan cannot close while any task is not COMPLETED.
Competing and contradictory proposals are all preserved; no winner is picked. Hypotheses
from different ports that cite a common source are marked NOT_INDEPENDENT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from .ai.citations import UNVERIFIED, VERIFIED, verify_citations
from .ai.outputs import parse_proposals
from .ai.policy import ProviderPolicy, check_port_allowed
from .ai.port import AIPort, AIRequest, AIResponse, SourceInput
from .graph import EdgeType, TaskState
from .lab import Lab
from .orchestration import Runner, StepContext, create_plan
from .records import Actor, ActorKind, Kind, Record
from .sources.base import SourceDocument

DEFAULT_PURPOSE = "propose_questions_and_hypotheses"
DEFAULT_INSTRUCTIONS = (
    "Read the source excerpts. Propose research questions and hypotheses that the excerpts bear on. "
    "Return only JSON of the form {\"questions\":[{\"text\":...}],\"hypotheses\":[{\"text\":...,\"cites\":[{\"source_id\":...,\"quote\":...}]}]}. "
    "Every quote must be copied verbatim from the excerpt of the source it cites."
)
NOT_INDEPENDENT = "NOT_INDEPENDENT"
INDEPENDENT_SOURCES = "INDEPENDENT_SOURCES"


class InvestigationError(Exception):
    """The investigation could not start."""


@dataclass
class InvestigationSummary:
    plan_id: str
    objective_id: str
    framing_question_id: str | None
    policy_profile: str
    sources: list[str] = field(default_factory=list)
    calls: dict[str, dict[str, Any]] = field(default_factory=dict)
    questions: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    unverified_citations: int = 0
    not_independent_pairs: list[dict[str, Any]] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    interrupted: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    complete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "objective_id": self.objective_id,
            "framing_question_id": self.framing_question_id,
            "policy_profile": self.policy_profile,
            "sources": list(self.sources),
            "calls": dict(self.calls),
            "questions": list(self.questions),
            "hypotheses": list(self.hypotheses),
            "unverified_citations": self.unverified_citations,
            "not_independent_pairs": list(self.not_independent_pairs),
            "failed": list(self.failed),
            "interrupted": list(self.interrupted),
            "pending": list(self.pending),
            "complete": self.complete,
        }


def build_request(
    lab: Lab,
    source_ids: Sequence[str],
    purpose: str = DEFAULT_PURPOSE,
    instructions: str = DEFAULT_INSTRUCTIONS,
    max_excerpt_chars: int = 4000,
    max_output_tokens: int = 800,
    settings: dict[str, Any] | None = None,
) -> AIRequest:
    """The exact request an investigation sends: one excerpt per preserved source, read from
    the blob store so a resumed run builds the same request."""
    if lab.blobs is None:
        raise InvestigationError("the lab has no blob store; sources cannot be read")
    inputs = []
    for source_id in source_ids:
        node = lab.graph.node(source_id)
        body = node.latest.body
        content = lab.blobs.read(body["blob_digest"])
        excerpt = content.decode("utf-8", errors="replace")[:max_excerpt_chars]
        inputs.append(SourceInput(source_id, body["content_digest"], excerpt))
    return AIRequest(purpose, instructions, tuple(inputs), max_output_tokens, dict(settings or {}))


def ai_actor(port: AIPort, response: AIResponse) -> Actor:
    kind = ActorKind.AI if port.is_model else ActorKind.SYSTEM
    return Actor(f"port:{port.provider_id}", kind, provider=port.provider_kind, model_family=response.model_reported)


def ai_call_block(port: AIPort, response: AIResponse, policy: ProviderPolicy) -> dict[str, Any]:
    return {
        "type": "ai_call",
        "provider_id": response.provider_id,
        "provider_kind": response.provider_kind,
        "adapter_version": response.adapter_version,
        "model_requested": response.model_requested,
        "model_reported": response.model_reported,
        "request_digest": response.request_digest,
        "response_digest": response.response_digest,
        "policy_profile": policy.name,
        "is_live": response.is_live,
        "is_model": port.is_model,
        "origin": response.origin,
        "finish_reason": response.finish_reason,
        "usage": response.usage,
        "latency_seconds": response.latency_seconds,
    }


def run_investigation(
    lab: Lab,
    objective_id: str,
    sources: Sequence[tuple[SourceDocument, Actor]],
    ports: Sequence[AIPort],
    policy: ProviderPolicy,
    actor: Actor,
    plan_id: str | None = None,
    purpose: str = DEFAULT_PURPOSE,
    instructions: str = DEFAULT_INSTRUCTIONS,
    max_excerpt_chars: int = 4000,
    max_output_tokens: int = 800,
    settings: dict[str, Any] | None = None,
    title: str = "investigation",
) -> InvestigationSummary:
    """Run (or resume, with plan_id) the investigation. Refuses, before anything runs, any
    port the policy does not allow. Returns a summary that says plainly what completed,
    failed, was interrupted or is still pending; complete is True only when the plan closed."""
    if actor.kind is not ActorKind.SYSTEM:
        raise InvestigationError("the investigation runner acts as a SYSTEM actor")
    if lab.blobs is None:
        raise InvestigationError("the lab has no blob store; open it with blob_root")
    objective = lab.graph.node(objective_id)
    if objective.kind is not Kind.OBJECTIVE:
        raise InvestigationError(f"{objective_id} is a {objective.kind.value}, not an objective")
    seen: set[str] = set()
    for port in ports:
        check_port_allowed(port, policy)  # refused here, before any call, under a profile that excludes it
        if port.provider_id in seen:
            raise InvestigationError(f"duplicate provider id {port.provider_id!r}")
        seen.add(port.provider_id)
    by_id = {port.provider_id: port for port in ports}
    steps = ["record_sources", *[f"call:{port.provider_id}" for port in ports], "analyse"]

    if plan_id is None:
        plan, _tasks = create_plan(lab, actor, title, steps, pursues=objective_id)
        plan_id = plan.entity_id
    runner = Runner(lab, plan_id, actor)
    task_by_step = {node.latest.body["step"]: node.entity_id for node in runner.tasks}
    if set(task_by_step) != set(steps):
        raise InvestigationError("the plan's steps do not match this investigation's ports")

    def output_of(step: str) -> dict[str, Any] | None:
        run = runner.states()[task_by_step[step]]
        return run.output if run.state is TaskState.COMPLETED else None

    def record_sources(ctx: StepContext) -> dict[str, Any]:
        ids = []
        for document, source_actor in sources:
            ids.append(lab.record_source(document, source_actor).record.entity_id)
        framing = lab.add(
            Kind.QUESTION,
            {"text": f"What do the preserved sources establish about: {objective.latest.body.get('title', objective_id)}", "role": "framing"},
            actor,
            edges=[(EdgeType.DECOMPOSES, objective_id)],
        )
        return {"sources": ids, "framing_question_id": framing.entity_id}

    def make_call(port: AIPort):
        def call(ctx: StepContext) -> dict[str, Any]:
            check_port_allowed(port, policy)
            recorded = output_of("record_sources")
            if recorded is None:
                raise InvestigationError("record_sources has not completed")
            request = build_request(lab, recorded["sources"], purpose, instructions, max_excerpt_chars, max_output_tokens, settings)
            lab.blobs.write(request.canonical_bytes())
            run = runner.states()[ctx.task_id]
            prior = [c for c in run.all_checkpoints if isinstance(c, dict) and c.get("request_digest") == request.request_digest and c.get("response_digest")]
            if prior:
                # Idempotent by request digest: a completed call is never made twice.
                text = lab.blobs.read(prior[-1]["response_digest"]).decode("utf-8")
                response = AIResponse.from_dict(prior[-1], text=text)
                reused = True
            else:
                response = port.complete(request)  # ProviderUnavailable/Refused/Timeout fail this task only
                lab.blobs.write(response.text.encode("utf-8"))
                ctx.checkpoint(response.to_dict(include_text=False))
                reused = False
            proposals = parse_proposals(response.text)  # ResponseFormatError fails this task; raw text is in the blob store
            block = ai_call_block(port, response, policy)
            author = ai_actor(port, response)
            question_ids = []
            for text in proposals.questions:
                record = lab.add(Kind.QUESTION, {"text": text, "proposed_by": port.provider_id}, author, edges=[(EdgeType.DECOMPOSES, objective_id)], provenance=[block])
                question_ids.append(record.entity_id)
            hypothesis_ids = []
            unverified = 0
            for proposal in proposals.hypotheses:
                checks = verify_citations(lab, proposal.cites)
                unverified += sum(1 for c in checks if c.status == UNVERIFIED)
                edges: list[tuple[EdgeType, str]] = [(EdgeType.ANSWERS, recorded["framing_question_id"])]
                for check in checks:
                    node = lab.graph.nodes.get(check.source_id)
                    if node is not None and node.kind is Kind.SOURCE and (EdgeType.CITES, check.source_id) not in edges:
                        edges.append((EdgeType.CITES, check.source_id))
                body = {
                    "text": proposal.text,
                    "proposed_by": port.provider_id,
                    "citations": [c.to_dict() for c in checks],
                    "citation_summary": {
                        "verified": sum(1 for c in checks if c.status == VERIFIED),
                        "unverified": sum(1 for c in checks if c.status == UNVERIFIED),
                    },
                    "status_note": "proposal from an AI port; citations checked for verbatim presence only (span in the normalised source text)",
                }
                record = lab.add(Kind.HYPOTHESIS, body, author, edges=edges, provenance=[block])
                hypothesis_ids.append(record.entity_id)
            return {
                "provider_id": port.provider_id,
                "provider_kind": port.provider_kind,
                "origin": response.origin,
                "is_model": port.is_model,
                "request_digest": request.request_digest,
                "response_digest": response.response_digest,
                "reused_recorded_response": reused,
                "questions": question_ids,
                "hypotheses": hypothesis_ids,
                "unverified_citations": unverified,
            }

        return call

    def analyse(ctx: StepContext) -> dict[str, Any]:
        outputs = {port.provider_id: output_of(f"call:{port.provider_id}") for port in ports}
        completed = {pid: out for pid, out in outputs.items() if out is not None}
        pairs = []
        reviews = []
        ids = list(completed)
        for i, left in enumerate(ids):
            for right in ids[i + 1 :]:
                for h1 in completed[left]["hypotheses"]:
                    for h2 in completed[right]["hypotheses"]:
                        shared = [node.entity_id for node in lab.graph.shared_sources(h1, h2)]
                        verdict = NOT_INDEPENDENT if shared else INDEPENDENT_SOURCES
                        review = lab.add(
                            Kind.REVIEW,
                            {"type": "independence_check", "pair": [h1, h2], "providers": [left, right], "verdict": verdict, "shared_sources": shared,
                             "note": "agreement between proposals that share a source is not validation"},
                            actor,
                            edges=[(EdgeType.REVIEWS, h1), (EdgeType.REVIEWS, h2)],
                        )
                        reviews.append(review.entity_id)
                        if shared:
                            pairs.append({"hypotheses": [h1, h2], "providers": [left, right], "shared_sources": shared})
        return {"providers_completed": ids, "providers_skipped": [pid for pid, out in outputs.items() if out is None], "not_independent_pairs": pairs, "reviews": reviews}

    runner.register("record_sources", record_sources)
    for port in ports:
        runner.register(f"call:{port.provider_id}", make_call(port))
    runner.register("analyse", analyse)
    states = runner.run(stop_on_failure=False)
    if all(run.state is TaskState.COMPLETED for run in states.values()):
        runner.complete("investigation complete")
    return summarise(lab, runner, objective_id, policy, by_id, task_by_step)


def summarise(lab: Lab, runner: Runner, objective_id: str, policy: ProviderPolicy, ports: dict[str, AIPort], task_by_step: dict[str, str]) -> InvestigationSummary:
    states = runner.states()
    recorded = states[task_by_step["record_sources"]]
    summary = InvestigationSummary(
        plan_id=runner.plan_id,
        objective_id=objective_id,
        framing_question_id=(recorded.output or {}).get("framing_question_id") if recorded.state is TaskState.COMPLETED else None,
        policy_profile=policy.name,
        sources=list((recorded.output or {}).get("sources", [])) if recorded.state is TaskState.COMPLETED else [],
    )
    for step, task_id in task_by_step.items():
        run = states[task_id]
        if run.state is TaskState.FAILED:
            summary.failed.append(f"{step}: {run.error}")
        elif run.state is TaskState.INTERRUPTED:
            summary.interrupted.append(step)
        elif run.state is not TaskState.COMPLETED:
            summary.pending.append(step)
        if step.startswith("call:"):
            entry: dict[str, Any] = {"state": run.state.value, "output_state": run.output_state.value, "attempts": run.attempts}
            if run.state is TaskState.COMPLETED and run.output:
                entry.update(run.output)
                summary.questions.extend(run.output["questions"])
                summary.hypotheses.extend(run.output["hypotheses"])
                summary.unverified_citations += run.output["unverified_citations"]
            elif run.error:
                entry["error"] = run.error
            summary.calls[step[len("call:") :]] = entry
    analysed = states[task_by_step["analyse"]]
    if analysed.state is TaskState.COMPLETED and analysed.output:
        summary.not_independent_pairs = list(analysed.output["not_independent_pairs"])
    summary.complete = lab.graph.node(runner.plan_id).status == "CLOSED"
    return summary


def record_pair_contradiction(lab: Lab, a_id: str, b_id: str, reason: str, actor: Actor, evidence: Sequence[dict[str, Any]]) -> Record:
    """Convenience over Lab.record_contradiction for two competing proposals."""
    return lab.record_contradiction(a_id, b_id, reason, actor, evidence)
