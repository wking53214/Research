# research_lab (stack-research-lab) 0.1.0

A governed research laboratory kept as a durable, tamper-evident, resumable research graph:
objectives, questions, hypotheses, sources, evidence, experiments, findings, contradictions,
decisions and capability proposals, with lifecycle and authority rules enforced in code.

It works standalone (outside STACK), one store per tenant, with replaceable governance. It
never authorizes production changes. External AI and sources are instruments, never the
foundation, and never treated as verified knowledge.

This is **increment 1 (foundation)**. Everything below says what exists now. Evidence labels
used in this repository: EXECUTED (run here), INSPECTED (read), INFERRED, UNKNOWN.

Core is Python 3.11+ standard library only (sqlite3 included). Apache-2.0, Copyright 2026
William N. King.

## What is implemented

| Module | What it does now | Status |
|---|---|---|
| `research_lab.canonical` | Canonical JSON (sorted keys, compact, ASCII, NFC strings, non-finite floats refused, strict types) and full SHA-256 digests | implemented |
| `research_lab.clock` | Injected clocks: `FixedClock`, `StepClock`, `SystemClock`. Timestamps are second-precision UTC strings | implemented |
| `research_lab.records` | `Actor` (HUMAN, AI, SYSTEM, EXTERNAL, optional provider and model family), `Kind` (13 kinds), `EvidenceLabel`, immutable versioned `Record` envelope with stable entity id, version, tenant, body, origin, created_at, parents, provenance, disposition, full content digest and full entity digest | implemented |
| `research_lab.store` | Append-only SQLite event log, hash chained with full SHA-256, genesis with tenant, schema version, governance issuers and entitled principals; `verify()` detects edited payload, deleted event, reordered event, sequence gap, wrong tenant, second genesis; `Signer` and `Anchor` protocols; `HmacSigner` (explicit key of at least 32 bytes, key id label, no default); `MemoryAnchor`; tenant scoping and default-deny principal check at open; no update or delete API; SQLite triggers refuse UPDATE and DELETE | implemented |
| `research_lab.graph` | Materialized nodes, typed edges and run states rebuilt from the log; edge table of allowed (from kind, edge, to kind); queries: children, ancestors, history, contradictions of a hypothesis, open threads, traceability from objective to capability proposal (partial chains reported as partial) | implemented |
| `research_lab.lifecycle` | Thread statuses (OPEN, DEFERRED, CLOSED, SUPERSEDED, REJECTED, REOPENED), finding stages (PROPOSED, REVIEWED, REPRODUCED, RECOMMENDED, ACCEPTED, ADMITTED, WITHDRAWN), transition tables, lab versus governance authority checks, self-review refusal | implemented |
| `research_lab.lab` | The write path: add, link, transition, govern, supersede, verify. Verifies the chain before trusting a store it opens | implemented |
| `research_lab.orchestration` | Plan and task records, `Runner` with registered steps keyed by idempotency key, RUN_STARTED, RUN_PROGRESS, RUN_COMPLETED, RUN_FAILED, RUN_INTERRUPTED events, resume that marks interrupted tasks PARTIAL and never re-runs completed steps, `complete()` refused while any task is not COMPLETED | implemented |
| `research_lab.export` | Deterministic JSON-lines bundle, verified before write, `verify_bundle()` from the file alone | implemented; import and merge are not implemented |
| `research_lab.sources` | `SourcePort` contract and `SourceDocument`; `LocalFileSource` (explicit allowed roots, realpath confinement, O_NOFOLLOW open, regular files only, size cap); `GitHubSource` (read-only GET to https://api.github.com only, no redirects, timeout, size cap, strict JSON and base64, blob sha recomputed, commit and blob pinned, injected transport with `FixtureTransport` for tests); `BlobStore` (content-addressed, write-once, verify-on-read, per tenant) | implemented (increment 2a) |
| `Lab.record_source`, `Lab.verify_sources`, `Graph.shared_sources` | source records with digests and pins, idempotent re-fetch, changed content superseding the old source, blob verification, shared-source query | implemented (increment 2a) |
| `research_lab.ai` | `AIPort` contract (`AIRequest` with request digest, `AIResponse` with provenance), errors, `ProviderPolicy` with `STACK_PROFILE` and `STANDALONE_DEV_PROFILE`, strict output parser, citation verification against preserved blobs, conformance suite; two implementations: `ReplayAIPort` (recorded SYNTHETIC test data) and `ExtractiveBaselinePort` (deterministic keyword extraction, not a model) | implemented (increment 2b); no vendor SDK; no WATCHER_MCU implementation exists |
| `research_lab.investigation` | `run_investigation` on the resumable Runner: policy check before any call, provider calls idempotent by request digest, request and raw response preserved, strict parse, citations verified, AI-origin proposals with `ai_call` provenance, shared-source pairs marked NOT_INDEPENDENT, one provider's failure isolated, summary that states what is complete, failed and unverified; `Lab.record_contradiction` | implemented (increment 2b) |
| `python -m research_lab` | init, add (objective, question, hypothesis, evidence, challenge, source), transition, show (open challenges, ai_call provenance, citation status, contradictions), verify (chain, policy and source blobs), export. No `investigate` command: it would need ports, recordings and a policy on the command line and was left out to keep the CLI thin | implemented |
| `examples/resume_demo.py` | Interrupted investigation resumed in a second process over the same store | implemented, exercised by tests |

Identities are claims in increment 1. A `Principal` or `Actor` id is checked against the
genesis entitlement set and the authority rules, but it is not authenticated. See
`docs/SECURITY.md`.

## Designed only

* Governance port beyond the disposition record. Today governance is one record type
  (`govern()`), whose issuer must be in the genesis issuer set and whose actor must be HUMAN or
  SYSTEM. No governance process, seats or quorum exist here; they belong to the owner's
  governance components.
* Review independence. Today only two rules hold: the author (same actor id) can never review
  or accept its own record, and no AI can record a governance disposition. A second AI id may
  move a finding through review stages. Independence descriptors are increment 3.

## Not implemented yet

The WATCHER_MCU implementation of the AI port (needs a change in WATCHER_MCU the owner has
not reviewed; see `docs/WATCHER_MCU_PORT.md`), any live external AI provider, experiment
runner and isolation, review independence descriptors beyond the shared-source check,
governance port beyond the disposition record, CNS and TIE adapters, bundle import and
merge, authentication of principals or actors, changing entitlements after genesis, source
adapters other than GitHub REST and local files (academic hosts are not reachable from the
build environment), a provider policy fixed in genesis (today the deployer supplies it).

AI output is always a proposal. The two AI port implementations that exist are a replay of
SYNTHETIC test data and a deterministic extractor that is not a model; nothing the package
prints or records is a model's output.

A source is an input the lab preserved: never evidence by itself, never verified knowledge.
The blob store is a reproducibility cache; the native evidence owners (TIE, HERALD, CCC)
keep their role and the lab references their ids.

## Quickstart

Requires Python 3.11 or newer. Nothing to install for the core; run from the repository root.

```sh
python -m research_lab init --db lab.sqlite --tenant acme --principal alice --issuer board-1 --at 2026-04-01T12:00:00Z
python -m research_lab add objective --db lab.sqlite --tenant acme --principal alice --actor alice --actor-kind HUMAN --title "Does resume preserve completed work?" --at 2026-04-01T12:00:01Z
```

The `add` output contains the objective's `entity_id`. Use it for the question, and so on:

```sh
python -m research_lab add question   --db lab.sqlite --tenant acme --principal alice --actor alice --actor-kind HUMAN --text "What state survives a crash?" --decomposes <OBJECTIVE_ID> --at 2026-04-01T12:00:02Z
python -m research_lab add hypothesis --db lab.sqlite --tenant acme --principal alice --actor model-1 --actor-kind AI --provider vendor --model-family family --text "Completed steps survive" --answers <QUESTION_ID> --at 2026-04-01T12:00:03Z
python -m research_lab add evidence   --db lab.sqlite --tenant acme --principal alice --actor alice --actor-kind HUMAN --text "examples/resume_demo.py shows it" --label EXECUTED --supports <HYPOTHESIS_ID> --at 2026-04-01T12:00:04Z
python -m research_lab transition     --db lab.sqlite --tenant acme --principal alice --actor alice --actor-kind HUMAN --entity <HYPOTHESIS_ID> --to DEFERRED --reason "needs a second run" --at 2026-04-01T12:00:05Z
python -m research_lab show   --db lab.sqlite --tenant acme --principal alice --entity <HYPOTHESIS_ID>
python -m research_lab verify --db lab.sqlite --tenant acme --principal alice
python -m research_lab export --db lab.sqlite --tenant acme --principal alice --out lab.jsonl
python examples/resume_demo.py
```

Sources (increment 2a). Local files need explicit allowed roots; GitHub fetches are live
unless `--github-fixtures DIR` points at recorded responses (the repository ships
`tests/fixtures/github`, captured on 2026-11-05):

```sh
python -m research_lab add source --db lab.sqlite --tenant acme --principal alice --actor local-fs --actor-kind SYSTEM --kind file --path /abs/path/data.csv --allow-root /abs/path
python -m research_lab add source --db lab.sqlite --tenant acme --principal alice --actor github.com --actor-kind EXTERNAL --kind github --repo wking53214/WATCHER_MCU --path README.md --ref main --github-fixtures tests/fixtures/github
python -m research_lab verify --db lab.sqlite --tenant acme --principal alice      # now also checks source blobs
python examples/source_demo.py            # offline, from fixtures
python examples/source_demo.py --live     # two GETs to https://api.github.com
```

Blobs live in `<db>.blobs/<tenant>/` unless `--blob-root` says otherwise.

Investigation (increment 2b), offline, from Python:

```sh
python examples/investigation_demo.py     # fixtures + a synthetic replay recording + the deterministic baseline; no network, no model
```

`--at` is optional; without it the wall clock is used. Every command prints JSON. A refusal
prints a JSON error on stderr and exits 1; `verify` exits 1 when the chain does not verify.

The same flow from Python:

```python
from research_lab.clock import StepClock
from research_lab.graph import EdgeType
from research_lab.lab import Lab
from research_lab.records import Actor, ActorKind, EvidenceLabel, Kind
from research_lab.store import Principal

alice = Principal("alice", frozenset({"acme"}))
human = Actor("alice", ActorKind.HUMAN)
lab = Lab.create("lab.sqlite", "acme", alice, governance_issuers=["board-1"], clock=StepClock())
objective = lab.add(Kind.OBJECTIVE, {"title": "O"}, human)
question = lab.add(Kind.QUESTION, {"text": "Q"}, human, edges=[(EdgeType.DECOMPOSES, objective.entity_id)])
print(lab.graph.traceability(objective.entity_id))
print(lab.verify().ok)
lab.close()
```

## Rules enforced in code

Each rule has positive and negative tests under `tests/`.

* Lab code paths can never set ACCEPTED or ADMITTED (`tests/test_lifecycle.py`). Those stages
  are written only by `Lab.govern()`, which requires an issuer id in the genesis governance
  issuer set and an actor of kind HUMAN or SYSTEM. An AI actor is refused even with a valid
  issuer id. No API changes the issuer set after genesis; a second GENESIS event is refused and
  a tampered genesis fails verification, so a Lab refuses to open it.
* Every finding starts PROPOSED. An author (by actor id) cannot review or accept its own
  record. An AI-authored hypothesis is a thread (a proposal) and never becomes a finding by
  transition.
* Withdrawing a finding that is ACCEPTED or ADMITTED is itself a governance disposition
  (`Lab.govern` to WITHDRAWN, same rules as acceptance); the lab path and `supersede` leave
  such a finding as it is. WITHDRAWN is terminal: a retry is a new finding that supersedes
  or derives from the withdrawn one (`tests/test_withdrawal.py`).
* Challenges are advice, never authority. Anyone entitled, including an AI actor or the
  author, may file a challenge (non-empty reason, at least one evidence reference) against a
  finding or hypothesis; filing never changes the target. Only a governance disposition
  resolves it UPHELD or DISMISSED, only the filer may withdraw it, and upholding does not
  withdraw the finding (`tests/test_challenges.py`).
* A rejected hypothesis that gains new supporting evidence keeps its full rejection history.
  Nothing is deleted; superseded, rejected, withdrawn and failed items stay queryable.
* The store is the only writer. There is no update or delete API. `verify()` recomputes every
  hash and detects edits, deletions, reordering, gaps and a wrong tenant
  (`tests/test_store.py`).
* The store is the single enforcement point. Every append is validated against the real
  head inside the store's write transaction (catch-up, check, insert), so a stale second
  writer gets `ConcurrentWriteConflict` and writes nothing, and a raw append of an
  out-of-policy event through any store, bare or a Lab's, is refused at write time; the
  validator is attached by `EventStore.open` and `create` themselves, and the only opt-out
  is the test-only `unsafe_unvalidated=True`
  (`tests/test_concurrency.py`, `tests/test_replay_policy.py`, `tests/test_mandatory_validator.py`).
* The log is not trusted on replay either. Every event is re-checked against the same rules
  when a store is opened, verified or exported, and when a bundle is verified. An event
  written outside the validated path that breaks a rule (for example an AI actor recording
  ADMITTED) makes `Lab.open` fail with `PolicyViolation` and `verify` report it
  (`tests/test_replay_policy.py`, including the exact attack that found the gap).
* A Lab is bound to the thread that opened it; other threads get `ThreadAffinityError`.
* Sources are instruments. `LocalFileSource` reads only regular files inside explicitly
  configured roots (path traversal and symlink escapes refused); `GitHubSource` talks only to
  https://api.github.com, follows no redirect, caps sizes, reads JSON and base64 strictly and
  recomputes the blob sha; a source record is written by an EXTERNAL or SYSTEM actor and
  pins commit and blob; re-fetching identical content adds nothing, changed content
  supersedes the old source; `verify_sources` detects a blob modified after preservation
  (`tests/test_sources_local.py`, `tests/test_sources_github.py`, `tests/test_blobs.py`,
  `tests/test_record_source.py`). Nothing in the package names or reaches an AI provider
  (`tests/test_repo_hygiene.py`).
* All AI interaction goes through `AIPort`. The investigation refuses, before any call, a
  port the policy does not allow (under `STACK_PROFILE` every existing port, because the
  WATCHER_MCU implementation does not exist). Every call is preserved (request and raw
  response), parsed strictly, and its citations checked verbatim against the preserved
  sources; UNVERIFIED cites are flagged and kept. Proposals are AI-origin records that can
  never carry the EXECUTED label, cannot be reviewed or accepted by their author, and are
  never picked as winners: contradictory proposals are preserved and pairs that share a
  source are marked NOT_INDEPENDENT. One provider's failure fails only its task
  (`tests/test_ai_port.py`, `tests/test_investigation.py`).
* A store belongs to one tenant. Opening it for another tenant, by a principal that does not
  claim the tenant, or by a principal not in the genesis entitlement set, is refused.
* `HmacSigner` refuses to run without an explicit key of at least 32 bytes. The key id is a
  label. No default key exists anywhere.
* Resume: a task left STARTED is marked INTERRUPTED with PARTIAL outputs; completed steps are
  not re-run; a plan cannot be closed (by the Runner or by `Lab.transition`) while any task is
  PARTIAL, INTERRUPTED, FAILED or never run (`tests/test_orchestration.py`).
* `Graph.rebuild(events)` equals the live graph, including run states, across a reopen
  (`tests/test_graph.py`).
* Bundles are verified before write and verifiable from the file alone
  (`tests/test_export.py`).
* Canonical JSON refuses NaN and Infinity (`tests/test_canonical.py`).

## Acceptance criteria

The owner's 15 first-milestone criteria, with a conservative status for increment 1. Statuses:
implemented, partially implemented, designed but unimplemented, not yet addressed. Evidence
names the file or test that proves the claim; nothing beyond what the tests prove is claimed.

| # | Criterion | Status | Evidence and what is missing |
|---|---|---|---|
| 1 | A research objective can be created. | implemented | `Kind.OBJECTIVE`; CLI `add objective`; `tests/test_cli.py::test_full_flow_through_the_cli`, `tests/test_graph.py` |
| 2 | An investigation can be decomposed into related research questions. | implemented | `QUESTION DECOMPOSES OBJECTIVE` and `QUESTION DECOMPOSES QUESTION` edges, `Graph.children`, branching in `tests/test_graph.py::test_traceability_reports_complete_and_partial_chains`; CLI `add question --decomposes` |
| 3 | At least one external AI research provider can be used through WATCHER_MCU. | not yet addressed | The port contract and conformance suite exist (`docs/WATCHER_MCU_PORT.md`), but no WATCHER_MCU implementation exists and no external provider was called. Under `STACK_PROFILE` every investigation is refused before any call (`tests/test_investigation.py::test_stack_profile_refuses_before_any_call`). |
| 4 | At least one non-AI information source can be queried. | partially implemented | `GitHubSource` and `LocalFileSource` fetch, `Lab.record_source` preserves, and `run_investigation` feeds the preserved sources to the ports and records proposals against them (`tests/test_investigation.py`, `examples/investigation_demo.py`). Missing: only two adapters; academic hosts unreachable here; no live run of a full investigation against a live source in this round (offline fixtures). |
| 5 | Research outputs retain their source provenance. | partially implemented | Every record version carries its origin actor, timestamp, parent version and provenance refs; source records carry locator, adapter id and version, retrieval metadata, response and content SHA-256, blob digest and for GitHub the commit and blob sha; AI-origin proposals carry an `ai_call` block (provider id and kind, model requested and reported, request and response digests, policy profile, origin tag) and per-cite verification status; `CITES` edges and `Graph.shared_sources` link outputs to sources (`tests/test_investigation.py::test_happy_path_records_proposals_with_provenance`). Missing: provenance of a live model's output (none exists). |
| 6 | Hypotheses can be created and tracked. | partially implemented | `Kind.HYPOTHESIS`, `ANSWERS` edge, thread statuses, full history, reopen, supersede, `contradictions_of` (`tests/test_lifecycle.py`, `tests/test_graph.py`). Missing: falsification criteria, confidence and uncertainty fields, competing-hypothesis structure (increment 3). |
| 7 | Contradictory findings can be preserved. | partially implemented | `CONTRADICTS` edges, `Kind.CONTRADICTION` records, `Graph.contradictions_of`; challenge records flag an accepted finding without changing it and stay queryable with their resolutions; nothing is deleted (`tests/test_graph.py::test_contradictions_of_hypothesis`, `tests/test_lifecycle.py::test_rejected_hypothesis_later_supported_keeps_rejection_history`, `tests/test_challenges.py`). Missing: contradiction detection, and a resolution workflow beyond a `DECISION RESOLVES CONTRADICTION` edge and governance resolution of a challenge. Status unchanged: the ruling adds a record, not detection. |
| 8 | Research can be resumed after interruption. | implemented | `Runner.reconcile` and `run`; interrupted task marked INTERRUPTED with PARTIAL outputs; completed steps not re-run; completion refused while partial (`tests/test_orchestration.py::test_interrupted_run_then_resume`, `tests/test_example.py`, `examples/resume_demo.py`). Scope: steps registered in process; no external execution. |
| 9 | Experiments can be recorded and reproduced to a defined standard. | designed but unimplemented | `Kind.EXPERIMENT` and the `TESTS` edge exist as record shapes only. No pre-registration, run record, environment capture or reproduction standard (increment 3). |
| 10 | Research findings can undergo independent review. | partially implemented | Review stages REVIEWED, REPRODUCED, RECOMMENDED; the author (same actor id) can never review or accept its own record; no AI can record acceptance; replay enforces the same (`tests/test_lifecycle.py`, `tests/test_replay_policy.py`). Missing: independence descriptors (provider, model family, source set); a second AI id may currently review (`test_increment1_limitation_a_different_ai_may_review`). |
| 11 | Failed and rejected findings remain available. | implemented | REJECTED, WITHDRAWN, SUPERSEDED and FAILED items stay as nodes with full version history and remain queryable; no delete API (`tests/test_lifecycle.py::test_rejected_hypothesis_later_supported_keeps_rejection_history`, `tests/test_graph.py::test_supersede_keeps_old_entity_queryable`, `tests/test_orchestration.py::test_failed_step_is_recorded_and_can_be_retried`). |
| 12 | A capability proposal can be generated without automatically authorizing implementation. | partially implemented | `Kind.CAPABILITY_PROPOSAL` derives from a finding; no code path authorizes anything; ACCEPTED and ADMITTED are governance-only dispositions that lab code and AI actors cannot set, on write or on replay (`tests/test_lifecycle.py`, `tests/test_replay_policy.py`). Missing: generation from findings, submission, admission tracking (increment 4). |
| 13 | Research records can be exported or exchanged through defined interfaces. | partially implemented | Deterministic JSON-lines bundle with schema version, verified before write, verifiable from the file alone including policy replay (`tests/test_export.py`, `tests/test_replay_policy.py`). Missing: import and merge, CNS and TIE exchange adapters. |
| 14 | The system can operate without one particular external AI vendor. | partially implemented at best | No vendor SDK or URL exists in the package (`tests/test_repo_hygiene.py`); one `AIPort` with two interchangeable implementations runs the same investigation (`tests/test_investigation.py`). But both implementations are non-vendor (synthetic replay, deterministic baseline) and no live external vendor has been exercised, so vendor independence is shown only for the contract, not for a real vendor. |
| 15 | The architecture supports future internally operated execution. | partially implemented | The port contract plus one internally operated deterministic implementation (`ExtractiveBaselinePort`, not a model) run end to end under `STANDALONE_DEV_PROFILE`. No internal model, no execution port, no sandbox. |

Summary: implemented 4 (items 1, 2, 8, 11); partially implemented 9 (4, 5, 6, 7, 10, 12, 13,
14, 15); designed but unimplemented 1 (9); not yet addressed 1 (3).

## Tests

`pytest` from the repository root (the `dev` extra lists it). In the build environment pytest
was loaded from a local cache by a wrapper script; nothing was installed. Tests are
deterministic, use injected clocks and temporary files, and make no network calls. The run
record for this version is in `CHANGELOG.md`.

## Layout

```
research_lab/      package (stdlib only); research_lab/sources/ holds the source adapters, research_lab/ai/ the AI port
tests/             pytest suite; tests/fixtures/github/ holds recorded GitHub responses and a manifest
examples/          resume_demo.py, source_demo.py, investigation_demo.py
docs/              ARCHITECTURE.md, SECURITY.md, KNOWN_LIMITATIONS.md, EXTERNAL_DEPENDENCIES.md
```

## License

Apache-2.0. See LICENSE and NOTICE.
