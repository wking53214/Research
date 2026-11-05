import os
import subprocess
import sys

from conftest import ROOT

EXAMPLE = os.path.join(ROOT, "examples", "resume_demo.py")


def test_resume_demo_runs_and_shows_the_resume(tmp_path):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, EXAMPLE, "--db", str(tmp_path / "demo.sqlite")], capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "crash while running step 'analyse'" in out
    assert "analyse\": \"STARTED/PARTIAL/attempts=1" in out
    assert "reconcile marked 1 task(s) INTERRUPTED with PARTIAL outputs" in out
    assert "analyse\": \"INTERRUPTED/PARTIAL/attempts=1" in out
    assert "complete() refused: plan " in out
    assert "gather ran once in total" in out
    assert "\"analyse\": \"COMPLETED/COMPLETE/attempts=2\"" in out
    assert "plan status: CLOSED" in out
    assert "store verify: ok" in out
    assert "graph rebuilt from log equals live graph: True" in out
    assert "plan history: ['OPEN', 'CLOSED']" in out


def test_resume_demo_default_temp_store():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, EXAMPLE], capture_output=True, text=True, env=env, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    assert "gather ran once in total" in result.stdout
