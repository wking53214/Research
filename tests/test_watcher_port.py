"""WatcherAIPort: the adapter for WATCHER_MCU's generic port. Offline and deterministic.

FakeWatcher implements the wire contract in this file; nothing here imports WATCHER_MCU
except the one test marked `integration`, which is deselected by default. Every text a fake
returns is synthetic test data, not a model's output."""

import ast
import os
import subprocess
import sys
import types

import pytest
from conftest import ISSUERS, ROOT, TENANT

from research_lab.ai import (
    STACK_PROFILE,
    STANDALONE_DEV_PROFILE,
    AIRequest,
    Cite,
    ExtractiveBaselinePort,
    HypothesisProposal,
    Proposals,
    ProviderRefused,
    ProviderUnavailable,
    ReplayAIPort,
    ResponseFormatError,
    SourceInput,
    WatcherAIPort,
    assert_conformant,
    check_port_allowed,
    load_watcher_call,
    render_proposals,
    run_conformance,
    write_recording,
)
from research_lab.ai import watcher as adapter
from research_lab.canonical import sha256_hex
from research_lab.clock import StepClock
from research_lab.graph import Graph, TaskState
from research_lab.investigation import build_request, run_investigation
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, Kind
from research_lab.sources import LocalFileSource

DIGEST = "0" * 64
RUNNER = Actor("investigation-runner", ActorKind.SYSTEM)
SYSTEM = Actor("local-filesystem", ActorKind.SYSTEM)
TEXT_A = "The Watcher narrates the run record for a person. Every sentence cites a measurement or is dropped. The Watcher never grades a change.\n"
TEXT_B = "The circuit has five members. Warden runs the circuit and issues grants. The Watcher is not a seat of the circuit.\n"
QUOTE_A = "The Watcher narrates the run record for a person."
WIRE_REQUEST_KEYS = {"instructions", "inputs", "model", "max_output_tokens", "request_digest"}
EXAMPLE = os.path.join(ROOT, "examples", "live_watcher_demo.py")


class WireError(Exception):
    """What the other side raises: an exception with a stable string `code`."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class FakeWatcher:
    """The wire contract of WATCHER_MCU's generic port, without WATCHER_MCU: strict keys,
    a size cap, the response mapping. `text` may be a function of the wire request; `error`
    is raised instead of answering; `spoil` edits the response to violate the contract."""

    def __init__(self, text='{"questions": [], "hypotheses": []}', error=None, spoil=None, model_reported="synthetic-model", usage=None):
        self.text, self.error, self.spoil, self.model_reported = text, error, spoil, model_reported
        self.usage = {"input_tokens": 11, "output_tokens": 5} if usage is None else usage
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        keys = set(request)
        if keys - (WIRE_REQUEST_KEYS | {"effort"}) or WIRE_REQUEST_KEYS - keys:
            raise WireError("format", "wrong keys")
        if not isinstance(request["inputs"], list) or not request["inputs"] or not all(isinstance(i, str) and i for i in request["inputs"]):
            raise WireError("format", "inputs must be a non-empty list of non-empty strings")
        if sum(len(part.encode("utf-8")) for part in (request["instructions"], *request["inputs"])) > 200_000:
            raise WireError("too_large", "instructions and inputs are over 200000 bytes")
        if self.error is not None:
            raise self.error
        text = self.text(request) if callable(self.text) else self.text
        response = {
            "text": text,
            "provider_id": "watcher_mcu",
            "provider_kind": "watcher_mcu",
            "adapter_version": "9.9.9",
            "model_requested": request["model"],
            "model_reported": self.model_reported,
            "finish_reason": "end_turn",
            "usage": self.usage,
            "request_digest": request["request_digest"],
            "response_digest": sha256_hex(text.encode("utf-8")),
            "is_live": True,
        }
        if self.spoil is not None:
            self.spoil(response)
        return response


def request(excerpt="The Watcher narrates the run record for a person.", inputs=None):
    items = (SourceInput("source_a", DIGEST, excerpt),) if inputs is None else inputs
    return AIRequest("propose", "Propose hypotheses about the watcher", items, 200, {})


def port_over(fake, **kwargs):
    return WatcherAIPort(fake, clock=StepClock(), model="model-x", **kwargs)


# the adapter against a fake that keeps the contract


def test_conformance_over_a_fake_that_keeps_the_wire_contract():
    fake = FakeWatcher()
    results = assert_conformant(port_over(fake), request(), unknown_request=request(excerpt="something else"))
    assert {r.name for r in results} == {"port_attributes", "request_digest_deterministic", "error_classes_distinguishable", "request_not_mutated", "response_provenance", "same_request_same_provenance", "unknown_request_handled"}
    assert len(fake.requests) == 3
    down = port_over(FakeWatcher(error=WireError("unavailable", "no credentials are configured for the model")))
    assert [r for r in run_conformance(down, request()) if not r.ok][0].name == "response_provenance"  # it cannot answer, and says so


def test_the_response_carries_the_lab_side_provenance():
    fake = FakeWatcher(text="hello")
    port = port_over(fake, provider_id="watcher-a")
    req = request()
    response = port.complete(req)
    assert (port.provider_kind, port.is_live, port.is_model, port.origin, port.adapter_version) == ("watcher_mcu", True, True, "watcher_mcu", "1")
    assert response.to_dict() == {
        "text": "hello", "provider_id": "watcher-a", "provider_kind": "watcher_mcu", "adapter_version": "1",
        "model_requested": "model-x", "model_reported": "synthetic-model", "request_digest": req.request_digest,
        "response_digest": sha256_hex(b"hello"), "finish_reason": "end_turn",
        "usage": {"input_tokens": 11, "output_tokens": 5, "watcher_adapter_version": "9.9.9"},
        "latency_seconds": 1, "is_live": True, "origin": "watcher_mcu",
    }
    assert port.calls == [req.request_digest]


def test_latency_is_measured_with_the_labs_clock():
    port = WatcherAIPort(FakeWatcher(), clock=StepClock(step_seconds=7), model="model-x")
    assert port.complete(request()).latency_seconds == 7


def test_what_the_other_side_does_not_report_is_recorded_as_unreported():
    fake = FakeWatcher(model_reported=None)
    fake.spoil = lambda response: response.update(usage=None)
    response = port_over(fake).complete(request())
    assert response.model_reported == "unreported" and response.usage == {"watcher_adapter_version": "9.9.9"}


def test_the_wire_request_is_built_from_the_request_and_the_request_is_not_changed():
    fake = FakeWatcher()
    req = request(inputs=(SourceInput("source_a", DIGEST, "first"), SourceInput("source_b", "1" * 64, "")))
    before = req.to_dict()
    port_over(fake).complete(req)
    port_over(fake, effort="low").complete(req)
    assert fake.requests[0] == {
        "instructions": "Propose hypotheses about the watcher",
        "inputs": [f"source_id: source_a\ncontent_sha256: {DIGEST}\nfirst", f"source_id: source_b\ncontent_sha256: {'1' * 64}\n"],
        "model": "model-x", "max_output_tokens": 200, "request_digest": req.request_digest,
    }
    assert fake.requests[1] == {**fake.requests[0], "effort": "low"}
    assert req.to_dict() == before


def test_the_constructor_refuses_what_it_cannot_use():
    for kwargs in ({"model": ""}, {"model": "m", "provider_id": " "}, {"model": "m", "effort": ""}, {"model": 5}):
        with pytest.raises(ValueError):
            WatcherAIPort(FakeWatcher(), clock=StepClock(), **kwargs)
    with pytest.raises(ValueError):
        WatcherAIPort("not callable", clock=StepClock(), model="m")


# the adapter against fakes that break the contract


def _drop(key):
    return lambda response: response.pop(key)


def _set(**changes):
    return lambda response: response.update(changes)


VIOLATIONS = [
    ("wrong digest", _set(response_digest="1" * 64), "response_digest does not match the text"),
    ("digest of other text", _set(text="swapped after hashing"), "response_digest does not match the text"),
    ("missing key", _drop("finish_reason"), "wrong keys"),
    ("missing text", _drop("text"), "wrong keys"),
    ("extra key", _set(tool_calls=[]), "wrong keys"),
    ("wrong echo", _set(request_digest="2" * 64), "request_digest is not the digest of the request"),
    ("wrong provider kind", _set(provider_kind="replay"), "provider_id and provider_kind"),
    ("wrong provider id", _set(provider_id="someone-else"), "provider_id and provider_kind"),
    ("not live", _set(is_live=False), "is_live must be true"),
    ("is_live not a bool", _set(is_live=1), "is_live must be true"),
    ("text not a string", _set(text=b"bytes"), "text must be a string"),
    ("text not UTF-8", _set(text="\ud800"), "text must be a string"),
    ("another model requested", _set(model_requested="model-y"), "model_requested is not the model"),
    ("empty model reported", _set(model_reported=""), "model_reported"),
    ("model reported not a string", _set(model_reported=5), "model_reported"),
    ("empty finish reason", _set(finish_reason=""), "finish_reason"),
    ("adapter version missing", _set(adapter_version=None), "adapter_version"),
    ("usage a list", _set(usage=[1, 2]), "usage must be null or exactly"),
    ("usage with another key", _set(usage={"input_tokens": 1, "output_tokens": 2, "cost": 3}), "usage must be null or exactly"),
    ("usage with a bool", _set(usage={"input_tokens": True, "output_tokens": 2}), "usage must be null or exactly"),
    ("usage negative", _set(usage={"input_tokens": -1, "output_tokens": 2}), "usage must be null or exactly"),
]


@pytest.mark.parametrize("name, spoil, match", VIOLATIONS, ids=[v[0] for v in VIOLATIONS])
def test_a_response_that_breaks_the_wire_contract_is_rejected(name, spoil, match):
    port = port_over(FakeWatcher(text="the raw text", spoil=spoil))
    with pytest.raises(ResponseFormatError, match=match):
        port.complete(request())
    results = {r.name: r for r in run_conformance(port, request())}
    assert not results["response_provenance"].ok and "ResponseFormatError" in results["response_provenance"].detail
    with pytest.raises(AssertionError, match="conformance failed"):
        assert_conformant(port, request())


def test_a_response_that_is_not_a_mapping_is_rejected():
    for answer in (None, "text", ["text"], 5):
        port = WatcherAIPort(lambda wire, answer=answer: answer, clock=StepClock(), model="model-x")
        with pytest.raises(ResponseFormatError, match="not a mapping") as caught:
            port.complete(request())
        assert caught.value.raw_text is None and caught.value.response_digest is None


def test_a_rejected_response_hands_over_its_raw_text_with_the_digest_of_that_text():
    port = port_over(FakeWatcher(text="the raw text", spoil=_set(request_digest="2" * 64)))
    with pytest.raises(ResponseFormatError) as caught:
        port.complete(request())
    assert caught.value.raw_text == "the raw text" and caught.value.response_digest == sha256_hex(b"the raw text")
    assert "the raw text" not in str(caught.value)  # the text is carried, never put in the message
    lying = port_over(FakeWatcher(text="the raw text", spoil=_set(response_digest="1" * 64)))
    with pytest.raises(ResponseFormatError) as caught:
        lying.complete(request())
    assert caught.value.response_digest == sha256_hex(b"the raw text")  # the recomputed digest, not the claimed one


# failures of the call


@pytest.mark.parametrize(
    "code, expected, match",
    [
        ("refused", ProviderRefused, "the model declined: said by the other side"),
        ("too_large", ProviderRefused, "rejected the request as too large: said by the other side"),
        ("format", ProviderRefused, "rejected the request as malformed: said by the other side"),
        ("unavailable", ProviderUnavailable, "watcher_mcu unavailable: said by the other side"),
    ],
)
def test_a_failure_is_mapped_by_its_code(code, expected, match):
    error = WireError(code, "said by the other side")
    with pytest.raises(expected, match=match) as caught:
        port_over(FakeWatcher(error=error)).complete(request())
    assert type(caught.value) is expected and caught.value.__cause__ is error


def test_a_refusal_is_not_unavailability_and_too_large_is_not_retried_as_an_outage():
    for code in ("refused", "too_large", "format"):
        with pytest.raises(ProviderRefused) as caught:
            port_over(FakeWatcher(error=WireError(code, "x"))).complete(request())
        assert not isinstance(caught.value, ProviderUnavailable)


def test_an_unknown_code_or_an_unknown_exception_is_unavailable_and_names_the_type():
    with pytest.raises(ProviderUnavailable, match="watcher_mcu call failed: WireError with unknown code 'rate_limited'") as caught:
        port_over(FakeWatcher(error=WireError("rate_limited", "secret-token-123"))).complete(request())
    assert "secret-token-123" not in str(caught.value) and isinstance(caught.value.__cause__, WireError)
    with pytest.raises(ProviderUnavailable, match="watcher_mcu call failed: ZeroDivisionError$") as caught:
        port_over(FakeWatcher(error=ZeroDivisionError("secret-token-123"))).complete(request())
    assert "secret-token-123" not in str(caught.value) and isinstance(caught.value.__cause__, ZeroDivisionError)
    not_a_string = WireError(404, "x")
    with pytest.raises(ProviderUnavailable, match="watcher_mcu call failed: WireError$"):
        port_over(FakeWatcher(error=not_a_string)).complete(request())


def test_an_interruption_is_not_turned_into_a_provider_error():
    class Killed(BaseException):
        pass

    with pytest.raises(Killed):
        port_over(FakeWatcher(error=Killed())).complete(request())


def test_a_request_with_no_inputs_and_one_over_the_cap_are_refused_by_the_other_side():
    with pytest.raises(ProviderRefused, match="malformed"):
        port_over(FakeWatcher()).complete(request(inputs=()))
    with pytest.raises(ProviderRefused, match="too large"):
        port_over(FakeWatcher()).complete(request(excerpt="x" * 200_001))


# policy


def test_stack_profile_allows_the_watcher_port_and_still_refuses_the_stand_ins(tmp_path):
    port = port_over(FakeWatcher())
    check_port_allowed(port, STACK_PROFILE)
    write_recording(str(tmp_path / "r.jsonl"), [], "empty")
    for stand_in in (ExtractiveBaselinePort(StepClock()), ReplayAIPort(str(tmp_path / "r.jsonl"), StepClock())):
        with pytest.raises(ProviderRefused, match="policy profile 'stack' does not allow"):
            check_port_allowed(stand_in, STACK_PROFILE)
    assert STACK_PROFILE.allowed_kinds == frozenset({"watcher_mcu"})


def test_standalone_dev_profile_is_unchanged_and_refuses_the_watcher_port():
    fake = FakeWatcher()
    with pytest.raises(ProviderRefused, match="policy profile 'standalone-dev' does not allow provider kind 'watcher_mcu'"):
        check_port_allowed(port_over(fake), STANDALONE_DEV_PROFILE)
    assert STANDALONE_DEV_PROFILE.allowed_kinds == frozenset({"replay", "deterministic_baseline"}) and fake.requests == []


# the lab does not import WATCHER_MCU


def test_no_module_of_the_package_imports_watcher():
    package = os.path.join(ROOT, "research_lab")
    seen = 0
    for base, _dirs, files in os.walk(package):
        for name in files:
            if not name.endswith(".py"):
                continue
            seen += 1
            with open(os.path.join(base, name), encoding="utf-8") as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):  # anywhere in the file, not only at module level
                if isinstance(node, ast.Import):
                    assert all(alias.name.split(".")[0] != "watcher" for alias in node.names), name
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    assert (node.module or "").split(".")[0] != "watcher", name
    assert seen > 10


def test_importing_the_lab_and_the_adapter_loads_no_watcher_module(tmp_path):
    """Even with a `watcher` package importable, importing the lab does not import it."""
    package = tmp_path / "watcher"
    package.mkdir()
    (package / "__init__.py").write_text("raise RuntimeError('the lab imported watcher at import time')\n", encoding="utf-8")
    code = "import sys, research_lab, research_lab.ai, research_lab.ai.watcher, research_lab.investigation; assert 'watcher' not in sys.modules; print('clean')"
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=os.pathsep.join([ROOT, str(tmp_path)]))
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0 and result.stdout.strip() == "clean", result.stderr


def test_load_watcher_call_says_plainly_when_watcher_is_not_installed(monkeypatch):
    def missing(name):
        raise ModuleNotFoundError(f"No module named {name.split('.')[0]!r}")

    monkeypatch.setattr(adapter.importlib, "import_module", missing)
    with pytest.raises(ProviderUnavailable, match="WATCHER_MCU with its generic port \\(watcher.port\\) is not installed"):
        load_watcher_call()


def test_load_watcher_call_returns_complete_and_refuses_a_module_without_it(monkeypatch):
    def complete(wire):
        return {}

    asked = []

    def fake_import(name):
        asked.append(name)
        return types.SimpleNamespace(complete=complete)

    monkeypatch.setattr(adapter.importlib, "import_module", fake_import)
    assert load_watcher_call() is complete and asked == ["watcher.port"]
    monkeypatch.setattr(adapter.importlib, "import_module", lambda name: types.SimpleNamespace())
    with pytest.raises(ProviderUnavailable, match="has no complete"):
        load_watcher_call()


# through the investigation runner, under STACK_PROFILE


@pytest.fixture
def world(db_path, principal, tmp_path, human):
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.txt").write_text(TEXT_A, encoding="utf-8")
    (root / "b.txt").write_text(TEXT_B, encoding="utf-8")
    local = LocalFileSource([str(root)], StepClock())
    docs = [(local.fetch(str(root / "a.txt")), SYSTEM), (local.fetch(str(root / "b.txt")), SYSTEM)]
    lab = Lab.create(db_path, TENANT, principal, ISSUERS, StepClock(), blob_root=str(tmp_path / "blobs"))
    objective = lab.add(Kind.OBJECTIVE, {"title": "Which component is the AI interaction boundary?"}, human)
    ids = [lab.record_source(doc, actor).record.entity_id for doc, actor in docs]
    yield {"lab": lab, "objective": objective.entity_id, "docs": docs, "sources": ids, "request": build_request(lab, ids), "tmp": tmp_path}
    lab.close()


def synthetic_json(world):
    """Synthetic test data in the strict output schema: one verbatim quote, one fabricated citation."""
    a, _b = world["sources"]
    return render_proposals(Proposals(
        ("Is the Watcher the boundary?",),
        (
            HypothesisProposal("SYNTHETIC: the Watcher is the designated AI interaction boundary", (Cite(a, QUOTE_A),)),
            HypothesisProposal("SYNTHETIC: the Watcher grades every change", (Cite("source_fabricated", "a source that does not exist"),)),
        ),
    ))


def investigate(world, ports, policy=STACK_PROFILE, plan_id=None):
    return run_investigation(world["lab"], world["objective"], world["docs"], ports, policy, RUNNER, plan_id=plan_id)


def test_investigation_under_stack_profile_records_proposals_with_provenance(world):
    lab = world["lab"]
    fake = FakeWatcher(text=synthetic_json(world))
    port = port_over(fake)
    summary = investigate(world, [port])
    assert summary.complete and summary.failed == [] and summary.pending == [] and summary.policy_profile == "stack"
    assert len(fake.requests) == 1 and fake.requests[0]["request_digest"] == world["request"].request_digest
    assert len(summary.hypotheses) == 2 and len(summary.questions) == 1
    call = summary.calls["watcher_mcu"]
    assert call["provider_kind"] == "watcher_mcu" and call["origin"] == "watcher_mcu" and call["is_model"] is True
    for hid in summary.hypotheses:
        node = lab.graph.node(hid)
        block = node.latest.provenance[0]
        assert block["type"] == "ai_call" and block["policy_profile"] == "stack" and block["provider_kind"] == "watcher_mcu"
        assert block["is_live"] is True and block["model_requested"] == "model-x" and block["model_reported"] == "synthetic-model"
        assert block["usage"] == {"input_tokens": 11, "output_tokens": 5, "watcher_adapter_version": "9.9.9"}
        assert lab.blobs.exists(block["request_digest"]) and lab.blobs.exists(block["response_digest"])
        assert node.author.kind is ActorKind.AI and node.author.id == "port:watcher_mcu" and node.author.provider == "watcher_mcu"
        assert node.status == "OPEN" and node.latest.evidence_label is None  # a proposal, not evidence
    assert lab.verify().ok and lab.verify_sources().ok and Graph.rebuild(lab.store.events()) == lab.graph


def test_investigation_flags_the_fabricated_citation_and_keeps_the_proposal(world):
    lab = world["lab"]
    summary = investigate(world, [port_over(FakeWatcher(text=synthetic_json(world)))])
    assert summary.complete and summary.unverified_citations == 1
    by_text = {lab.graph.node(h).latest.body["text"]: lab.graph.node(h).latest.body for h in summary.hypotheses}
    fabricated = by_text["SYNTHETIC: the Watcher grades every change"]
    assert fabricated["citation_summary"] == {"verified": 0, "unverified": 1} and fabricated["citations"][0]["status"] == "UNVERIFIED"
    assert by_text["SYNTHETIC: the Watcher is the designated AI interaction boundary"]["citation_summary"] == {"verified": 1, "unverified": 0}


def test_one_provider_failing_fails_only_its_task_and_a_resume_calls_only_that_one(world):
    lab = world["lab"]
    good = FakeWatcher(text=synthetic_json(world))
    bad = FakeWatcher(text=synthetic_json(world), error=WireError("unavailable", "the model could not be reached (APIConnectionError)"))
    ports = [port_over(good, provider_id="watcher-a"), port_over(bad, provider_id="watcher-b")]
    summary = investigate(world, ports)
    assert not summary.complete and lab.graph.node(summary.plan_id).status != "CLOSED"
    assert summary.calls["watcher-a"]["state"] == TaskState.COMPLETED.value and summary.calls["watcher-b"]["state"] == TaskState.FAILED.value
    assert len(summary.failed) == 1 and "call:watcher-b: ProviderUnavailable: watcher_mcu unavailable" in summary.failed[0]
    assert len(summary.hypotheses) == 2  # the provider that answered is recorded
    bad.error = None
    resumed = investigate(world, ports, plan_id=summary.plan_id)
    assert resumed.complete and resumed.failed == [] and len(resumed.hypotheses) == 4
    assert len(good.requests) == 1 and len(bad.requests) == 2  # the one that had answered was not called again
    # A gap that predates this adapter, recorded as an assertion: the analyse step completed in the first run with
    # watcher-b skipped, a completed step is never re-run, so the resumed plan closes without an independence check
    # of the two providers' hypotheses.
    assert resumed.not_independent_pairs == []
    assert lab.verify().ok


def test_two_watcher_ports_that_cite_the_same_source_are_marked_not_independent(world):
    ports = [port_over(FakeWatcher(text=synthetic_json(world)), provider_id=name) for name in ("watcher-a", "watcher-b")]
    summary = investigate(world, ports)
    assert summary.complete and len(summary.not_independent_pairs) == 1  # agreement over a shared source is not validation
    assert summary.not_independent_pairs[0]["providers"] == ["watcher-a", "watcher-b"]


def test_a_refusal_fails_the_task_and_records_nothing(world):
    refused = investigate(world, [port_over(FakeWatcher(error=WireError("refused", "the model declined (cyber)")))])
    assert not refused.complete and "ProviderRefused: watcher_mcu: the model declined" in refused.failed[0] and refused.hypotheses == []


def test_prose_instead_of_json_fails_the_task_and_the_raw_text_is_preserved(world):
    lab = world["lab"]
    prose = "SYNTHETIC: I think the Watcher is the boundary."
    summary = investigate(world, [port_over(FakeWatcher(text=prose))])
    assert not summary.complete and "ResponseFormatError" in summary.failed[0] and summary.hypotheses == []
    assert lab.blobs.read(sha256_hex(prose.encode("utf-8"))) == prose.encode("utf-8")


def test_a_wire_violation_fails_the_task_and_the_raw_text_is_preserved(world):
    lab = world["lab"]
    text = synthetic_json(world)
    summary = investigate(world, [port_over(FakeWatcher(text=text, spoil=_set(request_digest="2" * 64)))])
    assert not summary.complete and summary.hypotheses == [] and summary.questions == []
    assert "ResponseFormatError: watcher_mcu wire response: request_digest is not the digest of the request" in summary.failed[0]
    assert sha256_hex(text.encode("utf-8")) in summary.failed[0]
    assert lab.blobs.read(sha256_hex(text.encode("utf-8"))) == text.encode("utf-8")  # nothing was recorded from it, and it is kept


def test_stack_profile_refuses_a_stand_in_beside_the_watcher_port_before_any_call(world, tmp_path):
    lab = world["lab"]
    fake = FakeWatcher(text=synthetic_json(world))
    baseline = ExtractiveBaselinePort(StepClock())
    write_recording(str(tmp_path / "r.jsonl"), [], "empty")
    replay = ReplayAIPort(str(tmp_path / "r.jsonl"), StepClock())
    count = lab.store.count()
    for ports, kind in (([port_over(fake), baseline], "deterministic_baseline"), ([port_over(fake), replay], "replay")):
        with pytest.raises(ProviderRefused, match=f"policy profile 'stack' does not allow provider kind '{kind}'"):
            investigate(world, ports)
    with pytest.raises(ProviderRefused, match="policy profile 'standalone-dev' does not allow provider kind 'watcher_mcu'"):
        investigate(world, [port_over(fake)], policy=STANDALONE_DEV_PROFILE)
    assert fake.requests == [] and baseline.calls == [] and replay.calls == [] and lab.store.count() == count


# the live example refuses to run


def run_example(args, pythonpath):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=pythonpath)
    return subprocess.run([sys.executable, EXAMPLE, *args], capture_output=True, text=True, env=env)


def fake_watcher_checkout(tmp_path, credentials):
    """A stand-in `watcher` package: it says whether a credential exists and leaves a file
    behind if the port is ever called."""
    package = tmp_path / "fake_checkout" / "watcher"
    package.mkdir(parents=True)
    marker = tmp_path / "called"
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "narrate.py").write_text(f"DEFAULT_MODEL = 'model-x'\n\n\ndef credentials_present():\n    return {credentials!r}\n", encoding="utf-8")
    (package / "port.py").write_text(f"def complete(request):\n    open({str(marker)!r}, 'w').close()\n    raise RuntimeError('called')\n", encoding="utf-8")
    return str(package.parent), marker


def test_the_live_example_without_the_flag_makes_no_call_and_exits_2(tmp_path):
    checkout, marker = fake_watcher_checkout(tmp_path, credentials=True)
    result = run_example([], checkout)
    assert result.returncode == 2 and "not run, no call was made" in result.stderr and "--live" in result.stderr
    assert result.stdout == "" and not marker.exists()


def test_the_live_example_without_a_credential_makes_no_call_and_exits_2(tmp_path):
    checkout, marker = fake_watcher_checkout(tmp_path, credentials=False)
    source = tmp_path / "s.txt"
    source.write_text(TEXT_A, encoding="utf-8")
    result = run_example(["--live", "--source", str(source)], checkout)
    assert result.returncode == 2 and "reports no credential" in result.stderr
    assert result.stdout == "" and not marker.exists()


def test_the_live_example_without_watcher_installed_exits_2(tmp_path):
    result = run_example(["--live"], str(tmp_path))
    assert result.returncode == 2 and "is not installed" in result.stderr and result.stdout == ""


def test_the_live_example_never_reads_a_credential_itself():
    with open(EXAMPLE, encoding="utf-8") as handle:
        source = handle.read()
    assert "environ" not in source and "API_KEY" not in source and "AUTH_TOKEN" not in source and "getpass" not in source


# cross-repository check, deselected by default (-m integration, with WATCHER_MCU and CNS on PYTHONPATH)


@pytest.mark.integration
def test_the_real_watcher_port_and_the_adapter_agree_on_the_wire_format(world):
    """Imports the real watcher.port. No network and no model: the narrator is a fake."""
    import importlib

    real = importlib.import_module("watcher.port")
    narrate = importlib.import_module("watcher.narrate")
    text = synthetic_json(world)

    class FakeNarrator:
        def __init__(self, error=None):
            self.calls, self.error = [], error

        def complete(self, system, prompt, model, effort, max_tokens):
            self.calls.append((system, prompt, model, effort, max_tokens))
            if self.error is not None:
                raise self.error
            return {"text": text, "model": "synthetic-model", "stop_reason": "end_turn", "usage": {"input_tokens": 11, "output_tokens": 5}}

    def over(narrator, **kwargs):
        return WatcherAIPort(lambda wire: real.complete(wire, narrator), clock=StepClock(), model="model-x", **kwargs)

    assert load_watcher_call() is real.complete
    narrator = FakeNarrator()
    assert_conformant(over(narrator), world["request"], unknown_request=request())
    response = over(narrator, effort="low").complete(world["request"])
    assert response.text == text and response.model_reported == "synthetic-model" and response.finish_reason == "end_turn"
    assert response.usage == {"input_tokens": 11, "output_tokens": 5, "watcher_adapter_version": importlib.import_module("watcher").__version__}
    system, prompt, model, effort, max_tokens = narrator.calls[-1]
    assert system == world["request"].instructions and (model, effort, max_tokens) == ("model-x", "low", world["request"].max_output_tokens)
    assert all(item.excerpt in prompt and item.source_id in prompt for item in world["request"].inputs)

    for error, expected, match in (
        (narrate.Refused("the model declined (cyber)"), ProviderRefused, "the model declined"),
        (narrate.ModelResponseError("the response is not a message (str)"), ProviderUnavailable, "not a message"),
    ):
        with pytest.raises(expected, match=match):
            over(FakeNarrator(error)).complete(world["request"])
    unused = FakeNarrator()
    with pytest.raises(ProviderRefused, match="too large"):
        over(unused).complete(request(excerpt="x" * (real.MAX_INPUT_BYTES + 1)))
    with pytest.raises(ProviderRefused, match="malformed"):
        over(unused).complete(request(inputs=()))
    with pytest.raises(ProviderRefused, match="malformed"):
        over(unused, effort="not-an-effort").complete(world["request"])
    assert unused.calls == []

    summary = investigate(world, [over(FakeNarrator())])
    assert summary.complete and summary.unverified_citations == 1 and len(summary.hypotheses) == 2
