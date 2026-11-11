"""Investigation demo, offline: no network, no model.

Objective: "Which STACK component is the designated AI interaction boundary?"
Sources: the real WATCHER_MCU README at its pinned commit, served from the recorded GitHub
fixtures, and the local file watcher/narrate.py when a WATCHER_MCU checkout is present.
Ports: ExtractiveBaselinePort (deterministic keyword extraction, NOT a model) and a
ReplayAIPort fed a SYNTHETIC recording that this script writes itself. The synthetic
recording deliberately contains a fabricated quote, a hypothesis that contradicts the
baseline's, and a quote from the same source the baseline used. A simulated crash hits the
second provider after the first provider answered; the resume does not call the first
provider again. Then the log is exported and verified from the file alone.

Nothing printed here is a model's output. The WATCHER_MCU adapter (WatcherAIPort) is not
used here; examples/live_watcher_demo.py is the script for it and is never run by a test.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from research_lab.ai import (  # noqa: E402
    STACK_PROFILE,
    STANDALONE_DEV_PROFILE,
    Cite,
    ExtractiveBaselinePort,
    HypothesisProposal,
    Proposals,
    ProviderRefused,
    ReplayAIPort,
    parse_proposals,
    render_proposals,
    write_recording,
)
from research_lab.clock import StepClock  # noqa: E402
from research_lab.export import export_bundle, verify_bundle  # noqa: E402
from research_lab.investigation import build_request, run_investigation  # noqa: E402
from research_lab.lab import Lab  # noqa: E402
from research_lab.lifecycle import IncompleteInvestigation  # noqa: E402
from research_lab.orchestration import Runner  # noqa: E402
from research_lab.records import Actor, ActorKind, Kind  # noqa: E402
from research_lab.sources import FixtureTransport, GitHubSource, LocalFileSource  # noqa: E402
from research_lab.store import Principal  # noqa: E402

TENANT = "demo-tenant"
PRINCIPAL = Principal("demo-operator", frozenset({TENANT}))
OPERATOR = Actor("demo-operator", ActorKind.HUMAN)
RUNNER = Actor("investigation-runner", ActorKind.SYSTEM)
GITHUB = Actor("github.com", ActorKind.EXTERNAL)
LOCAL = Actor("local-filesystem", ActorKind.SYSTEM)
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "github")
LOCAL_ROOT = "/home/user/WATCHER_MCU/watcher"
LOCAL_FILE = os.path.join(LOCAL_ROOT, "narrate.py")
SETTINGS = {"topic_terms": ["watcher", "warden", "circuit", "narrates", "narrator", "interfere", "boundary", "cites"]}


class SimulatedCrash(BaseException):
    """Not an Exception on purpose: the runner records nothing for it, like a killed process."""


class CrashOnce:
    def __init__(self, inner):
        self.inner, self.crashed = inner, False

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def complete(self, request):
        if not self.crashed:
            self.crashed = True
            raise SimulatedCrash()
        return self.inner.complete(request)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--local-root", default=LOCAL_ROOT)
    parser.add_argument("--local-file", default=LOCAL_FILE)
    args = parser.parse_args(argv)
    clock = StepClock("2026-03-03T09:00:00Z")
    print("== offline demo: GitHub from recorded fixtures, replay port from a SYNTHETIC recording written below, no model, no network")

    with tempfile.TemporaryDirectory() as workdir:
        lab = Lab.create(os.path.join(workdir, "lab.sqlite"), TENANT, PRINCIPAL, ["governance-board"], clock, blob_root=os.path.join(workdir, "blobs"))
        objective = lab.add(Kind.OBJECTIVE, {"title": "Which STACK component is the designated AI interaction boundary?"}, OPERATOR)
        readme = GitHubSource(FixtureTransport(FIXTURES), clock).fetch_file("wking53214", "WATCHER_MCU", "README.md", ref="main")
        sources = [(readme, GITHUB)]
        print(f"== source 1: {readme.locator} at commit {readme.pinned['commit_sha'][:12]} ({readme.size} bytes, real fixture)")
        if os.path.isdir(args.local_root) and os.path.isfile(args.local_file):
            narrate = LocalFileSource([args.local_root], clock).fetch(args.local_file)
            sources.append((narrate, LOCAL))
            print(f"== source 2: {narrate.locator} ({narrate.size} bytes, local file)")
        else:
            print(f"== source 2 skipped: {args.local_file} is not available on this machine")

        # Pre-record the sources (idempotent: the investigation will find them again) so the
        # synthetic recording can be keyed by the exact request digest the investigation sends.
        source_ids = [lab.record_source(doc, actor).record.entity_id for doc, actor in sources]
        request = build_request(lab, source_ids, settings=SETTINGS)
        baseline = ExtractiveBaselinePort(clock)
        preview = parse_proposals(baseline.complete(request).text)
        baseline.calls.clear()
        if not preview.hypotheses:
            print("== the deterministic baseline found no sentence matching the topic terms; nothing to contradict")
            return 1
        shared_quote = preview.hypotheses[0].cites[0].quote
        shared_source = preview.hypotheses[0].cites[0].source_id
        synthetic = Proposals(
            ("Does any other component claim to be the AI boundary?",),
            (
                HypothesisProposal("SYNTHETIC: the Watcher is the designated AI interaction boundary", (Cite(shared_source, shared_quote),)),
                HypothesisProposal("SYNTHETIC: it is not the case that: " + preview.hypotheses[0].text, (Cite(shared_source, shared_quote),)),
                HypothesisProposal("SYNTHETIC: the Watcher approves merges", (Cite(shared_source, "The Watcher approves every merge it sees."), Cite("source_fabricated", "a source that does not exist"))),
            ),
        )
        recording = os.path.join(workdir, "synthetic_replay.jsonl")
        write_recording(recording, [{"request_digest": request.request_digest, "text": render_proposals(synthetic), "model_reported": "synthetic-model"}], "written by examples/investigation_demo.py")
        replay = ReplayAIPort(recording, clock, provider_id="replay-synthetic")
        print(f"== synthetic recording written: {len(replay)} entry, origin {replay.origin!r} (hand-written text, not a model's output)")

        try:
            run_investigation(lab, objective.entity_id, sources, [baseline, replay], STACK_PROFILE, RUNNER, settings=SETTINGS)
        except ProviderRefused as exc:
            print(f"== under STACK_PROFILE: refused before any call: {exc}")
        print(f"   calls so far: baseline={len(baseline.calls)} replay={len(replay.calls)} (neither port is of the watcher_mcu kind)")

        crashing = CrashOnce(replay)
        try:
            run_investigation(lab, objective.entity_id, sources, [baseline, crashing], STANDALONE_DEV_PROFILE, RUNNER, settings=SETTINGS)
        except SimulatedCrash:
            print("== simulated crash during the second provider's step, after the first provider answered")
        plan_id = [n for n in lab.graph.nodes.values() if n.kind is Kind.PLAN][0].entity_id
        states = {r.step: f"{r.state.value}" for r in lab.graph.run_states(plan_id).values()}
        print(f"   task states on disk: {states}")
        try:
            Runner(lab, plan_id, RUNNER).complete("premature")
        except IncompleteInvestigation as exc:
            print(f"   complete() refused: {exc}")

        summary = run_investigation(lab, objective.entity_id, sources, [baseline, crashing], STANDALONE_DEV_PROFILE, RUNNER, plan_id=plan_id, settings=SETTINGS)
        print(f"== resumed: complete={summary.complete} baseline calls={len(baseline.calls)} replay calls={len(replay.calls)} (provider 1 not called again)")
        for provider, call in summary.calls.items():
            kind = "DETERMINISTIC BASELINE (not a model)" if call.get("provider_kind") == "deterministic_baseline" else "SYNTHETIC replay (hand-written test data)"
            print(f"   {provider}: {call['state']} attempts={call['attempts']} questions={len(call.get('questions', []))} hypotheses={len(call.get('hypotheses', []))} unverified citations={call.get('unverified_citations')} [{kind}]")
        for hid in summary.hypotheses:
            body = lab.graph.node(hid).latest.body
            print(f"   {hid} [{body['proposed_by']}] {body['text'][:70]!r} citations {body['citation_summary']}")
            for cite in body["citations"]:
                if cite["status"] != "VERIFIED":
                    print(f"      UNVERIFIED cite on {cite['source_id']}: {cite['reason']}")
        print(f"== shared-source pairs marked NOT_INDEPENDENT: {len(summary.not_independent_pairs)} (agreement is not validation)")
        baseline_h = summary.calls["extractive-baseline"]["hypotheses"][0]
        contra_h = [h for h in summary.calls["replay-synthetic"]["hypotheses"] if "it is not the case" in lab.graph.node(h).latest.body["text"]][0]
        contradiction = lab.record_contradiction(baseline_h, contra_h, "the synthetic proposal negates the baseline's extracted sentence", OPERATOR, [{"type": "source", "ref": shared_source}])
        print(f"== contradiction preserved: {contradiction.entity_id} between {baseline_h} and {contra_h}; both stay {lab.graph.node(baseline_h).status}/{lab.graph.node(contra_h).status}")
        bundle = os.path.join(workdir, "bundle.jsonl")
        export_bundle(lab.store, bundle)
        check = verify_bundle(bundle)
        print(f"== exported {lab.store.count()} events; bundle verifies from file alone: ok={check.ok} policy_checked={check.policy_checked}")
        print(f"== lab verify: {lab.verify().ok}; sources verify: {lab.verify_sources().ok}")
        lab.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
