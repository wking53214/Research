# Architecture (increment 1)

Labels: EXECUTED, INSPECTED, INFERRED, UNKNOWN. Everything in this file describes code that
exists in `research_lab/` and is exercised by `tests/` (EXECUTED) unless marked otherwise.

## Shape

```
            CLI (research_lab.cli)        examples/resume_demo.py
                    |                              |
                    v                              v
              research_lab.lab.Lab  <----  research_lab.orchestration.Runner
                    |      \
     validates with |       \ applies each appended event to
   lifecycle, graph |        v
   edge table       |   research_lab.graph.Graph   (derived state, rebuilt from the log)
                    v
          research_lab.store.EventStore  (the only writer; SQLite; hash chain)
                    |
                    v
          research_lab.export            (JSON lines; verify before write; verify from file)
```

Dependencies between modules point downward only: `canonical` and `clock` have none;
`records` uses both; `store` uses `canonical`; `lifecycle` uses `records`; `graph` uses
`records`, `store`, `lifecycle`; `lab` uses all of those; `orchestration` uses `lab` and
`graph`; `export` uses `store`; `cli` uses `lab`, `export`, `store`. Core imports only the
standard library (`tests/test_repo_hygiene.py` reads the source to check).

## The log is the truth

Every change is an event appended to one SQLite table with a full SHA-256 hash over the
canonical JSON of `{seq, tenant, event_type, payload, prev_hash}`. Event types:

| Type | Payload | Written by |
|---|---|---|
| `GENESIS` | `schema_version`, `tenant`, `governance_issuers`, `principals` | `EventStore.create` only, seq 0 only |
| `RECORD` | `record` (version 1 of an entity), `edges` (from this record) | `Lab.add` |
| `TRANSITION` | `record` (next version), `from`, `to`, `actor`, `reason`, `governance` (null or `{issuer_id}`) | `Lab.transition`, `Lab.govern` |
| `EDGE` | `from`, `edge`, `to`, `actor`, `created_at` | `Lab.link` |
| `RUN_STARTED`, `RUN_PROGRESS`, `RUN_COMPLETED`, `RUN_FAILED`, `RUN_INTERRUPTED` | `plan`, `task`, `step`, `idempotency_key`, `attempt`, `actor`, `created_at`, plus `data`, `output`, `error` or `output_state` | `Runner` |

The store has no update or delete method. SQLite triggers refuse UPDATE and DELETE as a
second line, not as a boundary (see SECURITY.md). `verify()` recomputes every hash and checks
sequence continuity, prev_hash links, tenant on every row, genesis shape, optional signatures
and optional anchors.

## Records

A `Record` is one version of an entity. Fields covered by its full content digest:
`entity_id`, `entity_digest`, `version`, `kind`, `tenant`, `body`, `origin` (the actor that
produced this version), `created_at` (from the injected clock), `disposition`, `parents`
(previous version), `provenance` (list of dicts, for example the transition reason or the
governance issuer), `evidence_label` (required for evidence and finding).

`entity_digest` is the full SHA-256 of the version-1 seed (kind, tenant, body, origin,
created_at, parents, provenance). A derived `entity_id` is `kind_` plus its first 16 hex
characters. The id is a label; integrity is the full digest, which `verify_digest()` checks
along with the prefix. A caller may supply an id of its own as long as it does not imitate the
derived form.

The author of an entity is the origin of version 1. Transition versions carry the
transitioning actor as origin, so the history says who moved what.

## Graph

`Graph` is derived state. `Graph.rebuild(events)` replays the log; `Lab` applies every event
it appends to its live `Graph` through the same `apply()` method. `Graph.__eq__` compares
`to_dict()`, so `tests/test_graph.py` proves rebuild equals live, including across a reopen
and including run states. The graph lives in memory and is rebuilt on open; it is not
persisted separately. For increment 1 sizes that is deliberate: one source of truth, no
second store to drift.

The log is not trusted on replay. `Graph.apply()` calls `Graph.check(event)` first, which
validates the event against the lab's rules in the graph's current state and raises
`PolicyViolation` (a `GraphError`) with the seq and the rule. See SECURITY.md for the
per-event-type list.

The store is the single enforcement point for writes. `Graph` implements the store's
`Validator` protocol (`applied_seq`, `apply`, `check`); `EventStore.open` and `create`
attach a fresh `Graph` by default (imported lazily, since `graph.py` imports `store.py`), and
`Lab` replaces it with its own rebuilt graph. `unsafe_unvalidated=True` is the test-only
opt-out.
`EventStore.append` then runs, inside one `BEGIN IMMEDIATE` transaction: read the real head,
apply to the validator every event it has not seen (catch-up), `check()` the candidate,
insert, commit; and only after commit `apply()` the event to the validator. A failed check
writes nothing; a stale caller whose event is invalid on the real state gets
`ConcurrentWriteConflict`; a stale caller whose event is still valid is accepted after
catch-up. `Lab._emit` is therefore just `store.append`, with `Lab.refresh()` on failure so the
graph and the log never disagree. `verify_store()` in `lab.py` does chain verification from
one read snapshot and then the policy replay; `Lab.verify()` refreshes first and requires the
replay of the prefix the graph has seen to equal the graph.

Edges run from the dependent entity to the one it refers to. The allowed combinations are in
`EDGE_TABLE` in `graph.py`; `SUPERSEDES` is allowed between any two entities of the same kind.
Queries: `children`, `ancestors`, `history`, `contradictions_of`, `open_threads`,
`traceability`, `plan_tasks`, `run_states`.

## Lifecycle and authority

`lifecycle.py` holds two vocabularies and two transition tables. `check_lab_transition`
refuses governance-only stages outright, then checks the table, then refuses a review stage
when the actor id equals the author id. `check_governance_transition` requires kind finding, a
transition that `governance_required()` names (to ACCEPTED, to ADMITTED, or to WITHDRAWN
from ACCEPTED or ADMITTED), an issuer in the genesis set, a HUMAN or SYSTEM actor, an actor
different from the author, and a table-legal move. `Graph.check_plan_closable` refuses to
close a plan whose tasks are not all COMPLETED; `Lab.transition` and replay both call it.

Initial statuses are not chosen by the caller: findings start PROPOSED, everything else OPEN.
WITHDRAWN is terminal for a finding; a retry is a new finding that SUPERSEDES or
DERIVES_FROM the withdrawn one, so the withdrawal history stays on the old entity.
`Lab.supersede` returns a `Supersession` that says whether the old entity was retired: a
finding at ACCEPTED or ADMITTED, an entity already terminal, or a challenge, is left as it is.

Challenges use a third, four-word vocabulary (`ChallengeStatus`: OPEN, UPHELD, DISMISSED,
WITHDRAWN) because neither the thread nor the finding vocabulary has "resolved by
governance, for or against". `governance_required` names UPHELD and DISMISSED; the lab path
may set only WITHDRAWN, and only when the actor is the filer. `check_challenge_filing`
requires a non-empty `reason`, at least one provenance item and exactly one CHALLENGES edge,
and runs inside `Graph._check_record`, so filing is validated by the store and on replay.
A CHALLENGES edge is never accepted in an EDGE event. Queries live on the graph:
`challenges_of`, `open_challenges`, `entities_with_open_challenges`,
`findings_with_open_challenges`, `challenge_summary`; `Lab.file_challenge` is the
convenience writer and the CLI has `add challenge`.

## Orchestration

Run state is derived from RUN_* events in the graph. `Runner.run()` first reconciles (any task
STARTED with no terminal event becomes INTERRUPTED with PARTIAL outputs), then runs each task
not yet COMPLETED. A step that raises an `Exception` is recorded FAILED; a `BaseException`
that is not an `Exception` propagates with nothing written, which is what a killed process
leaves behind. `Runner.complete()` and `Lab.transition(plan, CLOSED)` both refuse while any
task is not COMPLETED.

## Export

A bundle is a header line plus one canonical-JSON line per event. `export_bundle` runs
`verify()` first and refuses to write otherwise. `verify_bundle` rebuilds the chain from the
file, checks the tenant from the header against the genesis and every row, and checks the
header's count, head hash and issuers. Import and merge do not exist.

## Ports and adapters (increment 2a: sources)

`research_lab/sources/base.py` is the port: `SourcePort` (`adapter_id`, `adapter_version`,
`fetch(locator) -> SourceDocument`) and `SourceDocument` (content bytes, locator, media type,
`retrieved_at` from the injected clock, adapter id and version, retrieval metadata, response
and content SHA-256, optional `pinned` coordinates). Errors: `SourceUnavailable` (keeps the
HTTP status), `SourceRefused` (policy), `SourceFormatError` (keeps the raw response digest),
`SourceTooLarge`. The core records know nothing about adapters: `Lab.record_source` turns a
`SourceDocument` into a `source` record through `SourceDocument.record_body()`.

Adapters: `LocalFileSource` (explicit roots, realpath confinement, O_NOFOLLOW and O_NONBLOCK
open, fstat regular-file check, size cap) and `GitHubSource` (one host, https only, no
redirects, timeout, size cap, strict JSON and base64, declared size and git blob sha checked
against the decoded bytes, ref resolved to a commit through `git/ref/heads` or `git/ref/tags`,
transport injected: `urllib_transport` for the network, `FixtureTransport` for recorded
responses). `BlobStore` is the content-addressed, write-once, verify-on-read cache, one
directory per tenant; `Lab.open(..., blob_root=...)` attaches one.

Idempotency and change: `Graph.source_by_locator` finds the current source for a locator;
identical content records nothing; different content creates a replacement that
`SUPERSEDES` the old source and carries a `change` block. `Graph.shared_sources(a, b)` and
`sources_cited_by` support later correlated-source detection. `Lab.verify_sources` checks
every blob; the CLI `verify` adds a `sources` key beside the chain result.

Future adapters implement `SourcePort`; the AI port (round 2b) will be a separate package
and nothing in `sources` names or reaches an AI provider.

## The AI port and the investigation (increment 2b)

`research_lab/ai/port.py` is the only way AI output enters the lab: `AIRequest` (purpose,
instructions, source inputs with entity id, content digest and the exact excerpt, output
cap, settings, and a request digest over all of it), `AIResponse` (text plus provenance:
provider id and kind, adapter version, model requested and reported, request digest echoed,
response digest, finish reason, usage, latency from the injected clock, `is_live`,
`origin`), the `AIPort` protocol and four errors. `research_lab/ai/conformance.py` is the
suite any implementation must pass; `docs/WATCHER_MCU_PORT.md` is the contract and the wire
format of the WATCHER_MCU implementation.

Implementations: `ReplayAIPort` serves responses keyed by request digest from a JSON-lines
recording whose header must say `origin: synthetic_test_data` (anything else is refused);
`ExtractiveBaselinePort` ranks sentences of the excerpts by keyword overlap and returns them
as exact quotes. Neither is a model.

`WatcherAIPort` (`research_lab/ai/watcher.py`) is the adapter for WATCHER_MCU's generic
port. It is given a callable (`watcher.port.complete` in a deployment, a fake in every
default test) and exchanges plain mappings with it, so the lab imports nothing of
WATCHER_MCU; `load_watcher_call()` imports it lazily through `importlib`. The adapter builds
the wire request from the `AIRequest`, maps a failure by the exception's `code`, checks the
wire response strictly (keys, types, echo of the lab's request digest, response digest
recomputed) and measures latency with the lab's clock. A rejected wire response is a
`ResponseFormatError` carrying the raw text, which `run_investigation` writes to the blob
store before the task fails. Credentials and the vendor SDK stay in WATCHER_MCU. No live
call has been made through it.

`ProviderPolicy` (`research_lab/ai/policy.py`) names the provider kinds a deployment allows.
It is supplied by the deploying code, not fixed in genesis (moving it there is a later
hardening). `STACK_PROFILE` allows only `watcher_mcu`; `STANDALONE_DEV_PROFILE` allows
`replay` and `deterministic_baseline`.

Flow of `run_investigation` (`research_lab/investigation.py`), one plan on the Runner:

1. Policy: every port is checked against the policy before the plan is created. A refused
   port means no call and no plan.
2. `record_sources`: each `SourceDocument` is preserved (idempotent) and a framing question
   by the SYSTEM runner decomposes the objective.
3. `call:<provider>` per port: the request is built from the preserved blobs (so a resume
   builds the same request and digest); the request bytes go to the blob store; if an
   earlier attempt of this task already checkpointed a response for this request digest,
   that response is reused from the blob store and the provider is not called again;
   otherwise the port is called, the raw response text is stored and checkpointed; the text
   is parsed strictly (a format error fails this task with the raw digest in the error);
   citations are verified; questions and hypotheses are recorded as AI-origin (or SYSTEM
   for a non-model port) records with an `ai_call` provenance block; CITES edges go to the
   cited sources that exist. A provider error fails this task only.
4. `analyse`: for every pair of hypotheses from different ports, `shared_sources` decides
   `NOT_INDEPENDENT` or `INDEPENDENT_SOURCES`, recorded as a review record that REVIEWS both.
   Contradictions are not inferred; `Lab.record_contradiction` preserves one when a person or
   later round identifies it, and no proposal is ever chosen over another.
5. The plan closes only when every task COMPLETED; the `InvestigationSummary` lists what is
   complete, failed, interrupted, pending and how many citations are unverified.

Run state lives in the graph (`TaskRun.all_checkpoints` keeps every checkpoint of every
attempt), so resume works from the store alone and the idempotency check survives a crash.

## Decisions taken while building

* Lab verifies the chain on open by default. A tampered genesis is therefore never loaded as
  policy. `verify=False` exists for tools that report on a broken store; the CLI `verify`
  command uses the bare `EventStore` for that reason.
* Entitled principals are part of genesis and cannot change afterwards in this increment. This
  keeps "who may open" in the same tamper-evident place as "who may accept". It is a
  limitation for real deployments (see KNOWN_LIMITATIONS.md).
* Run state moved into the graph rather than living only in the Runner so that a plan cannot
  be closed around the Runner (INFERRED risk, now tested).
* After independent verification found that authority rules ran only on the write path,
  validation moved into `Graph.check()`, shared by write and replay. A forged event in the
  log now makes `Lab.open` fail with `PolicyViolation` instead of loading the forgery.
* After a second verification found that a stale second writer could poison the log
  (validation against a stale in-memory graph, outside the append transaction), the check
  moved inside the store's write transaction with catch-up to the real head. One Lab per
  thread is enforced rather than locked, as the simpler safe shape.
* Timestamps come only from injected clocks. The CLI uses the wall clock unless `--at` is
  given. Ordering and integrity come from the chain sequence, never from timestamps.
