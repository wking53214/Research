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


def package_modules():
    package = os.path.join(ROOT, "research_lab")
    for base, dirs, files in os.walk(package):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.relpath(os.path.join(base, name), package), os.path.join(base, name)


def test_core_package_imports_only_the_standard_library():
    allowed = set(sys.stdlib_module_names) | {"research_lab"}
    violations = []
    for name, path in package_modules():
        with open(path, encoding="utf-8") as handle:
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


AI_PROVIDER_MARKERS = (
    "anthropic", "openai", "google.generativeai", "genai", "api.anthropic.com", "api.openai.com",
    "generativelanguage.googleapis.com", "mistral", "cohere", "ollama", "bedrock", "vertexai",
)


def test_package_contains_no_ai_provider_sdk_or_url():
    """AI access will exist only through the AI port (round 2b); until then nothing in the
    package may name or reach an AI provider."""
    hits = []
    for name, path in package_modules():
        with open(path, encoding="utf-8") as handle:
            text = handle.read().lower()
        hits.extend(f"{name}: {marker}" for marker in AI_PROVIDER_MARKERS if marker in text)
    assert hits == []


def test_only_one_network_host_is_named_in_the_package():
    hosts = set()
    for name, path in package_modules():
        with open(path, encoding="utf-8") as handle:
            hosts.update(re.findall(r"https?://([a-z0-9.-]+\.[a-z]{2,})", handle.read()))
    assert hosts == {"api.github.com"}


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
    # "Not implemented yet" replaced "Not implemented in increment 1" when increment 2 began.
    for heading in ("## What is implemented", "## Not implemented yet", "## Acceptance criteria", "## Quickstart"):
        assert heading in readme, heading
    assert "production ready" not in readme.lower()
    with open(os.path.join(ROOT, "NOTICE"), encoding="utf-8") as handle:
        assert "Copyright 2026 William N. King" in handle.read()
