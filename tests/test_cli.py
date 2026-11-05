import json
import os
import subprocess
import sys

import pytest
from conftest import ROOT, tamper

from research_lab import __version__
from research_lab.cli import main
from research_lab.export import verify_bundle

AT = "2026-04-01T12:00:00Z"


def run(capsys, *argv) -> tuple[int, dict | None, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    data = json.loads(captured.out) if captured.out.strip() else None
    return code, data, captured.err


def common(db: str, principal: str = "alice", tenant: str = "acme") -> list[str]:
    return ["--db", db, "--tenant", tenant, "--principal", principal, "--at", AT]


def actor(name: str = "alice", kind: str = "HUMAN") -> list[str]:
    return ["--actor", name, "--actor-kind", kind]


def test_full_flow_through_the_cli(capsys, tmp_path):
    db = str(tmp_path / "cli.sqlite")
    code, data, _ = run(capsys, "init", *common(db), "--issuer", "gov-1")
    assert code == 0 and data["genesis"]["governance_issuers"] == ["gov-1"] and data["genesis"]["tenant"] == "acme"

    code, data, _ = run(capsys, "add", "objective", *common(db), *actor(), "--title", "Objective")
    assert code == 0
    objective = data["record"]["entity_id"]
    assert data["record"]["disposition"] == "OPEN" and data["record"]["created_at"] == AT

    code, data, _ = run(capsys, "add", "question", *common(db), *actor(), "--text", "Q?", "--decomposes", objective)
    assert code == 0
    question = data["record"]["entity_id"]
    assert data["edges"] == [{"edge": "DECOMPOSES", "to": objective}]

    code, data, _ = run(capsys, "add", "hypothesis", *common(db), *actor("model-1", "AI"), "--provider", "v", "--model-family", "f", "--text", "H", "--answers", question)
    assert code == 0
    hypothesis = data["record"]["entity_id"]
    assert data["record"]["origin"] == {"id": "model-1", "kind": "AI", "provider": "v", "model_family": "f"}

    code, data, _ = run(capsys, "add", "evidence", *common(db), *actor(), "--text", "ran it", "--label", "EXECUTED", "--supports", hypothesis)
    assert code == 0 and data["record"]["evidence_label"] == "EXECUTED"
    code, data, _ = run(capsys, "add", "evidence", *common(db), *actor(), "--text", "but", "--label", "INSPECTED", "--contradicts", hypothesis)
    assert code == 0

    code, data, _ = run(capsys, "transition", *common(db), *actor(), "--entity", hypothesis, "--to", "DEFERRED", "--reason", "mixed evidence")
    assert code == 0 and data["record"]["version"] == 2 and data["record"]["disposition"] == "DEFERRED"

    code, data, _ = run(capsys, "show", *common(db), "--entity", hypothesis)
    assert code == 0
    assert data["status"] == "DEFERRED" and [h["disposition"] for h in data["history"]] == ["OPEN", "DEFERRED"]
    assert {e["edge"] for e in data["edges_in"]} == {"SUPPORTS", "CONTRADICTS"}
    assert data["edges_out"][0]["to"] == question

    code, data, _ = run(capsys, "verify", *common(db))
    assert code == 0 and data["ok"] and data["events_checked"] == 7

    out = str(tmp_path / "bundle.jsonl")
    code, data, _ = run(capsys, "export", *common(db), "--out", out)
    assert code == 0 and data["event_count"] == 7
    assert verify_bundle(out).ok


def test_cli_refusals_exit_one_with_json_error(capsys, tmp_path):
    db = str(tmp_path / "cli.sqlite")
    assert run(capsys, "init", *common(db))[0] == 0
    code, data, _ = run(capsys, "add", "objective", *common(db), *actor(), "--title", "O")
    objective = data["record"]["entity_id"]

    code, data, err = run(capsys, "add", "question", *common(db), *actor(), "--text", "Q")
    assert code == 1 and data is None and json.loads(err)["error"] == "RecordError"

    code, _, err = run(capsys, "transition", *common(db), *actor(), "--entity", objective, "--to", "ACCEPTED", "--reason", "x")
    assert code == 1 and json.loads(err)["error"] == "TransitionError"

    code, _, err = run(capsys, "transition", *common(db), *actor(), "--entity", objective, "--to", "REOPENED", "--reason", "x")
    assert code == 1 and "OPEN -> REOPENED" in json.loads(err)["message"]

    code, _, err = run(capsys, "show", *common(db, tenant="other"), "--entity", objective)
    assert code == 1 and json.loads(err)["error"] == "AccessRefused"

    code, _, err = run(capsys, "show", *common(db, principal="mallory"), "--entity", objective)
    assert code == 1 and "not entitled" in json.loads(err)["message"]

    code, _, err = run(capsys, "init", *common(db))
    assert code == 1 and "already has events" in json.loads(err)["message"]


def test_cli_verify_reports_tampering_and_other_commands_refuse(capsys, tmp_path):
    db = str(tmp_path / "cli.sqlite")
    assert run(capsys, "init", *common(db))[0] == 0
    code, data, _ = run(capsys, "add", "objective", *common(db), *actor(), "--title", "O")
    objective = data["record"]["entity_id"]
    raw = tamper(db)
    raw.execute("UPDATE events SET payload = '{}' WHERE seq = 1")
    raw.close()
    code, data, _ = run(capsys, "verify", *common(db))
    assert code == 1 and not data["ok"] and any("seq 1: hash mismatch" in p for p in data["problems"])
    code, _, err = run(capsys, "show", *common(db), "--entity", objective)
    assert code == 1 and json.loads(err)["error"] == "IntegrityError"


def test_init_is_deterministic_with_fixed_clock(capsys, tmp_path):
    one = run(capsys, "init", *common(str(tmp_path / "one.sqlite")), "--issuer", "g")[1]
    two = run(capsys, "init", *common(str(tmp_path / "two.sqlite")), "--issuer", "g")[1]
    assert one["head_hash"] == two["head_hash"]


def test_usage_error_exits_two(capsys):
    with pytest.raises(SystemExit) as info:
        main(["add", "mystery", "--db", "x", "--tenant", "t", "--principal", "p"])
    assert info.value.code == 2


def test_python_dash_m_entry_point(tmp_path):
    env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""), PYTHONDONTWRITEBYTECODE="1")
    version = subprocess.run([sys.executable, "-m", "research_lab", "--version"], capture_output=True, text=True, env=env, cwd=ROOT)
    assert version.returncode == 0 and __version__ in version.stdout
    db = str(tmp_path / "sub.sqlite")
    init = subprocess.run(
        [sys.executable, "-m", "research_lab", "init", *common(db), "--issuer", "gov-1"],
        capture_output=True, text=True, env=env, cwd=ROOT,
    )
    assert init.returncode == 0, init.stderr
    assert json.loads(init.stdout)["genesis"]["tenant"] == "acme"
    verify = subprocess.run([sys.executable, "-m", "research_lab", "verify", *common(db)], capture_output=True, text=True, env=env, cwd=ROOT)
    assert verify.returncode == 0 and json.loads(verify.stdout)["ok"]
