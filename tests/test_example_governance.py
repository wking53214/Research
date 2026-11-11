import os
import subprocess
import sys

from conftest import ROOT

EXAMPLE = os.path.join(ROOT, "examples", "governance_demo.py")


def test_governance_demo_refuses_the_forgery_applies_the_signed_grant_and_refuses_the_replay(tmp_path):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, EXAMPLE], capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    out = result.stdout
    lines = out.splitlines()
    assert lines[0].startswith("TEST-ONLY KEYS") and lines[-1].startswith("TEST-ONLY KEYS")  # said loudly, first and last
    assert "governance mode AUTHENTICATED" in out
    assert "REFUSED  claim kind SYSTEM and quote the public issuer id (attack A5): GrantRefused" in out
    assert "REFUSED  a grant naming the board, signed with the AI's own key: GrantRefused: grant signature does not verify" in out
    assert "REFUSED  the same grant with no signature at all" in out
    assert "status RECOMMENDED; events written by the attempts: 0" in out
    assert "APPLIED  relay the board's signed grant (submitted by the AI)" in out
    assert "status ACCEPTED; submitted by kind AI; authority: signature of governance-board" in out
    assert "REFUSED  the same grant a second time: GrantRefused: the grant's nonce was already used" in out
    assert "REFUSED  the same grant with the target edited to ADMITTED" in out
    assert "REFUSED  a new, validly signed grant that reuses the nonce" in out
    assert out.count("APPLIED") == 1 and out.count("REFUSED") == 6
    assert "verify: ok=True mode=AUTHENTICATED authenticated=1 unauthenticated=0" in out
    assert "offline, from the bundle file alone: ok=True grants re-verified=1" in out


def test_the_signer_is_used_only_by_tests_and_this_demo():
    """The reference signer never leaves tests/ and the demo: nothing in the package or in
    the other examples imports it."""
    offenders = []
    for folder in ("research_lab", "examples"):
        for base, _dirs, files in os.walk(os.path.join(ROOT, folder)):
            for name in files:
                if name.endswith(".py") and name != "governance_demo.py":
                    with open(os.path.join(base, name), encoding="utf-8") as handle:
                        text = handle.read()
                        if "import ed25519_signer" in text or "from ed25519_signer" in text:
                            offenders.append(os.path.join(base, name))
    assert offenders == []
    with open(os.path.join(ROOT, "tests", "ed25519_signer.py"), encoding="utf-8") as handle:
        assert "TEST-ONLY" in handle.read().splitlines()[0]
