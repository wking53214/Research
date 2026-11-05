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

Core records, store, graph, lifecycle, orchestration and export: none. Tests: none (GitHub
responses come from `tests/fixtures/github`, served by `FixtureTransport`).

`research_lab.sources.github.GitHubSource` with `urllib_transport` makes read-only HTTPS GET
requests to `https://api.github.com` only, when a caller asks for a live fetch (CLI
`add source --kind github` without `--github-fixtures`, `examples/source_demo.py --live`).

GitHub REST API (version header `2022-11-28`), endpoints used:

| Endpoint | Purpose |
|---|---|
| `GET /repos/{owner}/{repo}` | repository metadata: `full_name`, `default_branch`, `pushed_at` |
| `GET /repos/{owner}/{repo}/git/ref/heads/{branch}` and `.../git/ref/tags/{tag}` | resolve a branch or lightweight tag to a commit sha |
| `GET /repos/{owner}/{repo}/contents/{path}?ref={commit}` | one file's base64 content, size and blob sha at a pinned commit |

Rate limits: unauthenticated requests are limited per source address (60 per hour at the
time of capture, INSPECTED from the `x-ratelimit-limit: 60` header in the fixtures). A 403
or 429 with `x-ratelimit-remaining: 0` raises `SourceUnavailable` with the reset epoch in the
message; the lab does not retry. A token raises the limit; it is used only when a caller
passes `token_env` naming the variable, and never recorded.

When GitHub is unavailable (network, proxy refusal, 5xx, 404, rate limit): the fetch raises
`SourceUnavailable` with the HTTP status when there was one; nothing is recorded; previously
recorded sources and their blobs remain usable. A changed response format raises
`SourceFormatError` with the digest of the raw response.

Fixtures: four responses captured live on 2026-11-05 (see `tests/fixtures/github/MANIFEST.json`),
unauthenticated, headers reduced to content-type, etag, last-modified, cache-control,
x-github-media-type, x-github-api-version-selected, x-ratelimit-limit and
x-ratelimit-remaining. Bodies are verbatim. The academic hosts named in the proposal (arXiv,
Crossref, OpenAlex) are blocked from the build environment and have no adapter.
