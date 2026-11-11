import os
import subprocess
import sys

from conftest import ROOT

EXAMPLE = os.path.join(ROOT, "examples", "source_demo.py")


def test_source_demo_runs_offline_from_fixtures(tmp_path):
    """Default mode never touches the network: a local root inside tmp_path stands in for the
    WATCHER_MCU checkout so the test does not depend on sibling repositories."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "narrate.py").write_text("print('stand-in')\n")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, EXAMPLE, "--local-root", str(root), "--local-file", str(root / "narrate.py")],
        capture_output=True, text=True, env=env, cwd=str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "mode: offline fixtures" in out
    assert "commit 4ab218d0c4c31e78bc0b9359f6c09fa32c87babd blob 1862cdec13f22793e20c82f95ef43ddb86d40385 42937 bytes" in out
    assert "re-fetch: same record True created=False" in out
    assert "outside the allowed root refused: SourceRefused" in out
    assert "changed=True previous=source_" in out and "old status: SUPERSEDED" in out
    assert "verify_sources: ok=True checked=4" in out
    assert "after tampering one blob on disk: ok=False" in out and "is corrupt" in out
    assert "chain verify: ok=True" in out
