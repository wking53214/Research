"""Repository-level rules: no em dashes, stdlib-only core, version in one place."""

import ast
import os
import re
import sys

from conftest import ROOT

from research_lab import __version__

EM_DASH = chr(0x2014)  # spelled as a code point so this file does not contain the character itself
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", "build", "dist"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".txt", ".cfg", ".ini", ".yml", ".yaml", ".json", ""}


def repo_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(base, name)
            if os.path.splitext(name)[1] in TEXT_SUFFIXES and name not in {"LICENSE"}:
                yield path
            elif name == "LICENSE":
                yield path


def test_no_em_dashes_anywhere():
    offenders = []
    for path in repo_files():
        with open(path, encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                if EM_DASH in line:
                    offenders.append(f"{os.path.relpath(path, ROOT)}:{number}")
    assert offenders == []


def test_core_package_imports_only_the_standard_library():
    package = os.path.join(ROOT, "research_lab")
    allowed = set(sys.stdlib_module_names) | {"research_lab"}
    violations = []
    for name in sorted(os.listdir(package)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(package, name), encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [] if node.level else [(node.module or "").split(".")[0]]
            else:
                continue
            violations.extend(f"{name}: {root}" for root in roots if root not in allowed)
    assert violations == []


def test_version_is_declared_once_and_documented():
    assert __version__ == "0.1.0"
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        pyproject = handle.read()
    assert 'version = { attr = "research_lab.__version__" }' in pyproject
    assert not re.search(r'^version = "', pyproject, flags=re.MULTILINE)
    assert 'name = "stack-research-lab"' in pyproject
    assert 'dependencies = []' in pyproject
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
        assert f"## [{__version__}]" in handle.read()


def test_readme_states_status_honestly():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()
    for heading in ("## What is implemented", "## Not implemented in increment 1", "## Acceptance criteria", "## Quickstart"):
        assert heading in readme, heading
    assert "production ready" not in readme.lower()
    with open(os.path.join(ROOT, "NOTICE"), encoding="utf-8") as handle:
        assert "Copyright 2026 William N. King" in handle.read()
