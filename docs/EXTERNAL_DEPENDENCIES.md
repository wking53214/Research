# External dependencies

## Core (runtime)

None. `research_lab` imports only the Python standard library:
`argparse`, `collections`, `dataclasses`, `datetime`, `enum`, `hashlib`, `hmac`, `json`,
`math`, `os`, `sqlite3`, `sys`, `typing`, `unicodedata`. `tests/test_repo_hygiene.py` parses
every module in the package and fails if any import is outside `sys.stdlib_module_names`
(EXECUTED).

`pyproject.toml` declares `dependencies = []` and `requires-python = ">=3.11"`.

## Development

| Package | Where declared | Used for | Status in the build environment |
|---|---|---|---|
| pytest >= 8 | `[project.optional-dependencies] dev` | the test suite | EXECUTED with pytest 9.1.1 loaded from a pre-existing local cache; nothing installed |
| ruff | `[tool.ruff]` configuration only, not declared as a dependency | linting, if the owner wants it | NOT EXECUTED (not available here) |

No STACK repository is imported, vendored or copied. CNS, TIE, HERALD, WATCHER_MCU and the
others were read for their contracts only, as the build brief allowed.

## Network

None at runtime, none in tests.
