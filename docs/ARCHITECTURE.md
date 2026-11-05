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
