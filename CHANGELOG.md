# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow
Semantic Versioning. The version lives in one place, `research_lab.__version__`;
`pyproject.toml` reads it. Nothing is tagged until the owner tags it.

## [Unreleased]

## [0.1.0] - 2026-11-05, not tagged, not committed by the builder

Increment 1, foundation. Built in a working tree; the owner decides what to commit.

### Added

- `research_lab.canonical`: canonical JSON and full SHA-256 digests. NaN and Infinity refused,
  strings NFC-normalized, strict types, duplicate keys after normalization refused.
- `research_lab.clock`: injected clocks (`FixedClock`, `StepClock`, `SystemClock`).
- `research_lab.records`: `Actor`, `ActorKind`, `Kind`, `EvidenceLabel`, `Ref`, immutable
  versioned `Record` with full content digest and full entity digest; derived entity ids are
  a 16-hex prefix of the entity digest and are checked against it.
- `research_lab.store`: append-only hash-chained SQLite event log with genesis (tenant, schema
  version, governance issuers, entitled principals), `verify()`, `Signer` and `Anchor`
  protocols, `HmacSigner` (no default key, at least 32 bytes, key id label), `MemoryAnchor`,
  tenant and principal default deny, SQLite triggers against UPDATE and DELETE.
- `research_lab.graph`: materialized nodes, typed edges, run states; edge table; queries for
  children, ancestors, history, contradictions, open threads and traceability.
- `research_lab.lifecycle`: thread statuses, finding stages, transition tables, lab versus
  governance authority checks, self-review refusal, `IncompleteInvestigation`.
- `research_lab.lab`: the write path (`add`, `link`, `transition`, `govern`, `supersede`,
  `verify`), chain verification before a store is trusted.
- `research_lab.orchestration`: plans, tasks, `Runner` with idempotency keys, resume with
  INTERRUPTED and PARTIAL marking, completed steps never re-run, completion refused while any
  task is not COMPLETED.
- `research_lab.export`: deterministic JSON-lines bundle, verified before write,
  `verify_bundle()` from the file alone. Import and merge are not implemented.
- CLI `python -m research_lab`: init, add, transition, show, verify, export.
- `examples/resume_demo.py`.
- Tests under `tests/` for every rule above, including: self-approval by an AI actor; an AI
  attempting ACCEPTED or ADMITTED; an event edited after preservation; deleted, reordered and
  gapped events; cross-tenant open; unentitled principal; interrupted run then resume; partial
  result reported as complete; rejected hypothesis later supported; attempt to change
  governance issuers after genesis; graph rebuild equals live graph; bundle verification from
  the file alone; canonical JSON refusing NaN.
- Docs: README, docs/ARCHITECTURE.md, docs/SECURITY.md, docs/KNOWN_LIMITATIONS.md,
  docs/EXTERNAL_DEPENDENCIES.md, LICENSE, NOTICE, pyproject.toml, .gitignore.

### Changed after independent verification (same version, same day)

- Defect found by the verifier (EXECUTED, attack B1): a TRANSITION forged with
  `EventStore.append` that moved an AI-authored finding to ADMITTED with an AI actor was
  accepted on reopen, because the authority rules ran only when `Lab` wrote. Fix:
  `Graph.check(event)` validates every event against the shared lifecycle, edge, run and
  genesis rules; `Graph.apply()` calls it on every replay and `Lab._emit` calls it before every
  append. A violation raises the new `PolicyViolation` naming the seq. `Lab.open` refuses
  such a store; `verify_store()` (new, in `lab.py`), `Lab.verify()`, the CLI `verify`
  command, `export_bundle()` and `verify_bundle()` report it as a problem with
  `policy_checked` false. `VerifyResult` gained `policy_checked`. `Lab.verify()` also
  requires the replay to equal the live graph. The plan-closing check moved to
  `Graph.check_plan_closable`, shared by `Lab.transition` and replay.
- Tests: `tests/test_replay_policy.py` (26 tests) including the exact B1 attack, forged
  from/to, forged issuer, governance by AI kind, self-acceptance at replay, second GENESIS
  inserted with a valid hash, mismatched record digest, edge table violations, run events
  without a plan or task, re-running a completed step, unknown event types, and a legitimate
  full lifecycle that still replays. Pre-existing test edited:
  `tests/test_export.py::test_signed_bundle_verifies_with_signer` now builds its store through
  a `Lab` instead of appending a bare `NOTE` event, because replay refuses unknown event
  types; nothing else about it changed.
- README acceptance table rewritten with the owner's 15 criteria.
- docs/SECURITY.md: new section on replay validation and its limits.

### Changed after the second independent verification (same version, same day)

- Defect found by the verifier (EXECUTED, attack2.py cases D1b, D1c, D2a, D2b): a stale
  second Lab on the same file could append a transition that was valid on its stale view and
  invalid on the real state; the store accepted it (chain only), the Lab's apply then failed,
  and the store could never be opened again. Root cause: validation against a possibly stale
  in-memory graph, outside the append transaction, not enforced by the store. Fix: the store
  gains a `Validator` protocol (`Graph` implements it; `Lab` attaches its graph);
  `EventStore.append` catches the validator up to the real head, checks the candidate and
  inserts, all inside one `BEGIN IMMEDIATE` transaction, and applies to the validator only
  after commit. New `ConcurrentWriteConflict` when a stale caller's event is invalid on the
  real state; a stale caller's still-valid event is accepted after catch-up. `Lab._emit` is
  now the store append plus `Lab.refresh()` (new) on failure, so the graph and the log never
  disagree. Raw `EventStore.append` through a store with a validator is refused at write
  time with `PolicyViolation`; replay validation on open remains the backstop.
  `EventStore.snapshot()` (new) reads events and row count in one read transaction;
  `verify_store()` uses it and compares a live graph with the replay of the prefix it has
  seen, so concurrent writers do not produce false mismatches. Threads: a store and its Lab
  are bound to the opening thread; other threads get `ThreadAffinityError` (new) before
  anything is read or written (attack2.py case D3 previously surfaced a raw sqlite
  `ProgrammingError`).
- Tests: `tests/test_concurrency.py` (9 tests: D1, D2, stale-but-valid acceptance, graph
  equals rebuild after every failed write, a log poisoned outside the validated path refuses
  every writer, two processes appending to one store, 20 threads on one Lab failing closed,
  one Lab per thread working). `tests/test_replay_policy.py` restructured: forgeries now go
  through a bare `EventStore` opened without a validator (the unvalidated path) to exercise
  the replay backstop, and new tests prove the same forgeries are refused at write time
  through the Lab's store with the event count unchanged (31 tests, up from 25). No other
  pre-existing test changed.
- Docs: SECURITY.md (atomic validated append, what remains), KNOWN_LIMITATIONS.md item 7,
  ARCHITECTURE.md.

### Changed after the third independent verification (same version, same day)

- Finding E1 (medium): a bare `EventStore` opened without a validator could write a forged
  ADMITTED from another process; `Lab.open` then refused the store. Fix: the policy
  validator is mandatory. `EventStore.open` and `create` attach the standard Graph-based
  validator themselves (a fresh `Graph`, caught up from the log inside the first write
  transaction). `ConcurrentWriteConflict` is raised only when the validator had already been
  synced before the append (a stale caller), not on that initial load, so a bare store
  reports the same `PolicyViolation` the replay would. The test-only opt-out is
  `unsafe_unvalidated=True` on `open` and `create`.
- Owner's ruling on withdrawal (findings W1, W2, W3): `lifecycle.governance_required()`
  (new) names the transitions only a governance disposition may make: to ACCEPTED, to
  ADMITTED, or to WITHDRAWN from ACCEPTED or ADMITTED. `check_lab_transition` refuses them;
  `check_governance_transition` accepts them under the existing rules (genesis issuer,
  HUMAN or SYSTEM actor, not the author); replay uses the same functions. WITHDRAWN is
  terminal: the WITHDRAWN -> PROPOSED transition is removed. `Lab.supersede` returns a
  `Supersession` (new) and never retires a finding at ACCEPTED or ADMITTED, nor an entity
  already terminal; the replacement and the SUPERSEDES edge are still created. The edge
  table gains FINDING DERIVES_FROM FINDING so a retry may derive from a withdrawn finding.
- Tests: `tests/test_withdrawal.py` (14 tests) and `tests/test_mandatory_validator.py`
  (5 tests). Pre-existing tests edited, each for the intended change only:
  `tests/test_lifecycle.py::test_author_may_withdraw_own_finding_and_resubmit` renamed to
  `..._but_withdrawn_is_terminal` and now asserts the refusal (W3);
  `tests/test_lifecycle.py::test_governance_refuses_self_approval_wrong_kind_wrong_stage_and_table`
  matches the new message "not a governance transition" (W1);
  `tests/test_graph.py::test_supersede_keeps_old_entity_queryable` reads the `Supersession`
  return value (W2); `tests/test_store.py` (store fixture and two anchor tests) and
  `tests/test_signer.py::test_signed_store_verifies_and_wrong_key_fails` open their stores
  with `unsafe_unvalidated=True` because they append bare chain-layer "NOTE" events (E1);
  `tests/test_replay_policy.py` `raw` fixture and
  `tests/test_concurrency.py::test_a_poisoned_log_written_outside_the_validated_path_refuses_every_writer`
  use the opt-out to simulate corruption (E1).
- Docs: SECURITY.md, ARCHITECTURE.md, KNOWN_LIMITATIONS.md (7b, 7c), README rule bullets.

### Added after the owner approved challenge records (option A, same version, same day)

- `Kind.CHALLENGE`, `EdgeType.CHALLENGES` (challenge -> finding, challenge -> hypothesis;
  never challenge -> challenge), `lifecycle.ChallengeStatus` (OPEN, UPHELD, DISMISSED,
  WITHDRAWN; the last three terminal), `CHALLENGE_TRANSITIONS`, `check_challenge_filing`
  (non-empty reason, at least one provenance reference, exactly one CHALLENGES edge).
  `governance_required` now also names UPHELD and DISMISSED; `check_governance_transition`
  accepts challenges and refuses the filer; `check_lab_transition` lets only the filer set
  WITHDRAWN on a challenge. Filing never changes the target. Upholding does not withdraw the
  finding. `Graph._check_record` and `_check_edge_event` enforce the filing rules and refuse
  CHALLENGES edges outside filing, on write and on replay.
- Graph queries: `challenges_of`, `open_challenges`, `entities_with_open_challenges`,
  `findings_with_open_challenges`, `challenge_summary`. `Lab.file_challenge`. CLI
  `add challenge --target --text --evidence` and `show` now lists `open_challenges` and
  `challenges`. `Lab.supersede` never retires a challenge.
- Tests: `tests/test_challenges.py` (18 tests, 5 parametrised forged resolutions). No
  pre-existing test changed.
- Docs: SECURITY.md (challenges and the noise note), ARCHITECTURE.md, KNOWN_LIMITATIONS.md
  (7d), README (rules, modules, CLI, acceptance row 7 evidence text; no status moved).

### Test record for this version

See the builder's report for the exact command, counts and exit status (EXECUTED on Python
3.13.18 with pytest 9.1.1 loaded from a local cache; nothing installed). The suite was also
run on no other Python version; 3.11 and 3.12 compatibility is INFERRED from the language
features used, not EXECUTED.
