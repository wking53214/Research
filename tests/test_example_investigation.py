import os
import subprocess
import sys

from conftest import ROOT

EXAMPLE = os.path.join(ROOT, "examples", "investigation_demo.py")


def test_investigation_demo_runs_offline(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "narrate.py").write_text("# The narrator cites the watcher run record and never interferes with the circuit.\n")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, EXAMPLE, "--local-root", str(root), "--local-file", str(root / "narrate.py")],
        capture_output=True, text=True, env=env, cwd=str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "offline demo" in out and "SYNTHETIC" in out and "not a model" in out
    assert "under STACK_PROFILE: refused before any call" in out and "calls so far: baseline=0 replay=0" in out
    assert "simulated crash" in out and "complete() refused" in out
    assert "resumed: complete=True baseline calls=1 replay calls=1" in out
    assert "UNVERIFIED cite on source_fabricated: unknown source" in out
    assert "NOT_INDEPENDENT" in out and "contradiction preserved" in out
    assert "bundle verifies from file alone: ok=True policy_checked=True" in out
    assert "lab verify: True; sources verify: True" in out
