# Security notes (increment 1)

Labels: EXECUTED, INSPECTED, INFERRED, UNKNOWN. This file states what the code defends
against and, more importantly, what it does not. Nothing here is a production readiness
claim.

## What verify() detects (EXECUTED, tests/test_store.py and tests/test_export.py)

With file access to the SQLite store or a bundle, an attacker who edits one event's payload,
header or tenant, deletes an event, swaps two events, or inserts a second genesis is detected
because every hash is recomputed and every link checked. The same checks run on an exported
bundle from the file alone.

## Replay validation: the log is not trusted (EXECUTED, tests/test_replay_policy.py)

Found by independent verification after the first build: a TRANSITION event forged with
`EventStore.append` directly (bypassing `Lab`) that moved an AI-authored finding to ADMITTED
with an AI actor was accepted on reopen, because replay only materialised the log and the
authority rules ran only on the write path. That is fixed as follows.

`Graph.check(event)` validates every event against the same functions the write path uses
(`lifecycle.check_lab_transition`, `lifecycle.check_governance_transition`, the edge table,
the run state machine, `Record.verify_digest`, genesis immutability). It runs in two places:
before `Lab` appends an event, and inside `Graph.apply()` on every event of every replay.
`Lab.open`, `Lab.verify()`, `verify_store()`, the CLI `verify` command, `export_bundle()`
and `verify_bundle()` all replay. A violation raises `PolicyViolation` naming the seq and the
rule; `Lab.open` refuses the store rather than loading the forgery, and the verify paths
report `ok: false` with `policy violation: seq N: ...` in `problems` and `policy_checked`
false.

What replay checks per event type:

* GENESIS: only at seq 0; schema version; tenant equal to the header; issuers a list of ids;
  principals non-empty. A second GENESIS, even one inserted with a correct hash, is refused.
* RECORD: digest matches content; version 1 with no parents; disposition equals the fixed
  initial status (findings PROPOSED, threads OPEN); tenant equals the store's; entity id not
  already present; every edge in the edge table and pointing at an existing entity.
* TRANSITION: digest matches; version follows; kind, entity digest, body and evidence label
  unchanged; parents reference the previous version; event actor equals the record origin;
  `from` equals the entity's current status; record disposition equals `to`; a non-empty
  reason; then the lifecycle rules: lab transitions can never reach ACCEPTED or ADMITTED and
  can never withdraw a finding that is ACCEPTED or ADMITTED (owner's ruling W1), review
  stages by the author are refused, governance transitions (to ACCEPTED, to ADMITTED, or
  to WITHDRAWN from either) need an issuer in the genesis set, a HUMAN or SYSTEM actor, an
  actor other than the author, a table-legal move and provenance naming the issuer;
  WITHDRAWN is terminal (ruling W3); closing a plan needs every task COMPLETED.
* EDGE: both entities exist, not the same, combination in the edge table, actor and
  timestamp well formed.
* RUN_*: plan and task exist, task PART_OF plan, step and idempotency key match, attempt
  numbers follow, STARTED refused for a running or completed task (completed steps are never
  re-run), PROGRESS, COMPLETED, FAILED and INTERRUPTED only for a STARTED task, INTERRUPTED
  must mark outputs PARTIAL.
* Any other event type is refused.

What this protects and what it does not:

* With no signer and no anchor, someone who can rewrite the whole file can still produce a
  log that validates: they recompute the chain and keep every event within policy. They can
  no longer slip a policy-violating event past replay, whether appended through the store
  API or inserted with a valid hash. A finding reaches ADMITTED only through a sequence of
  events that the rules allow.
* With a signer whose key they do not hold, they cannot forge any event at all without
  `verify(require_signed=True)` failing.
* Replay validation does not authenticate identities. An event whose actor claims kind
  SYSTEM with a different id and a public issuer id passes the rules (the attack script's
  case A5). That remains the "identities are claims" limitation below.

## Atomic validated append: the store is the single enforcement point (EXECUTED, tests/test_concurrency.py)

Found by the second independent verification: two Labs on one file, one holding a stale
graph, could poison the store. The stale Lab validated against its stale view, the store
accepted the event (it checked only the chain), the Lab's in-memory apply then failed, and
the log held an event that no replay would accept, so the store could never be opened again.
That is fixed as follows.

`EventStore.append` takes the whole decision inside one write transaction
(`BEGIN IMMEDIATE`). With a validator attached (every Lab attaches its graph; a bare
`EventStore` may be given one too), the store first applies to the validator every event it
has not yet seen (catch-up, read inside the same transaction, so it is the real head), then
calls the validator's `check()` on the candidate, and only then inserts. If the check fails
nothing is written, the transaction is rolled back and the store stays openable. If the
caller's view was stale (catch-up applied at least one event) and the candidate is invalid on
the real state, the error is `ConcurrentWriteConflict`; the validator has already been caught
up, so the caller may rebuild its event and retry. If the caller's view was stale but the
candidate is still valid on the real state (the other writer touched other entities), the
event is accepted after catch-up: a transition on one entity is unaffected by writes to
another, and the version, `from` status and parent checks catch any clash on the same
entity. The validator is applied only after commit, so the Lab's graph and the log agree
after every append; on any failure `Lab.refresh()` brings the graph up to the log.

The validator is mandatory (finding E1 of the third verification: a bare `EventStore` in
another process, opened without a validator, could write a forged ADMITTED and lock the
tenant out of its own history). `EventStore.open` and `EventStore.create` attach the
standard Graph-based policy validator themselves; it starts empty and the store catches it
up from the log inside the first write transaction, so a bare store refuses an
out-of-policy append exactly as a Lab does, with the same `PolicyViolation` the replay
would raise (B1 and E1 are stopped before they reach the file). The only way to append
without validation is `unsafe_unvalidated=True` on `open` or `create`. It exists only for
tests that deliberately corrupt a log to exercise the replay backstop and for chain-layer
tests that use bare events; no production code path uses it. Replay validation on open stays
as the backstop for anything written that way or by direct SQL.

Threads: an `EventStore`, and the Lab around it, is bound to the thread that opened it.
Any use from another thread raises `ThreadAffinityError` before anything is read or
written. One Lab per thread works; the test proves both. This is deliberate: a shared Lab
would need a lock around the graph as well as the connection, and a per-thread Lab is the
simpler safe shape.

Verification under concurrent writers reads its events and row count in one read
transaction, and `Lab.verify()` compares the live graph with the replay of exactly the
prefix the graph has seen, so a writer in another process does not produce a false mismatch.

What remains:

* Anyone with file access can still drop the SQL triggers and rewrite the file. That is
  detected by a signer whose key they lack or by an anchor, never prevented.
* A fail-closed store means a file poisoned outside the validated path (a bare store with no
  validator, or direct SQL) cannot be opened as a Lab, and every validated writer on it is
  refused at its next catch-up. There is no repair tool in increment 1. Keep a verified
  bundle export.
* Identity is still a claim (see below).

## Challenge records: advice, never authority (EXECUTED, tests/test_challenges.py)

A challenge (kind `challenge`, edge `CHALLENGES` to a finding or hypothesis) lets anyone
entitled to the tenant, including an AI actor and the target's own author, record that an
accepted or admitted finding looks wrong. Filing never changes the target's status or
version. A challenge is OPEN when filed; only a governance disposition (same rules as
acceptance: genesis issuer, HUMAN or SYSTEM actor, never the filer, never an AI) resolves it
UPHELD or DISMISSED; only the filer may withdraw it. All three outcomes are terminal and
stay queryable forever. Upholding a challenge does not withdraw the finding: a separate
governance WITHDRAWN disposition on the finding is still required, and the log shows both
acts. A filing with an empty reason or no evidence reference is refused; a CHALLENGES edge
from anything but a challenge, or added after filing, is refused. The store's mandatory
validator and the replay backstop enforce all of this with the shared lifecycle functions.

Noise: because a challenge has no authority effect, spamming challenges is noise, not
control. An actor can clutter the governance view of findings with open challenges; it
cannot change a finding. No rate limit exists in increment 1; a future increment may cap
open challenges per actor.

## Sources (increment 2a): what a source is, and what it is not

A source is bytes the lab preserved, with where and when it got them. It is not evidence,
not verified knowledge, and its content is untrusted data: nothing in the lab executes or
interprets it. The native evidence owners (TIE, HERALD, CCC) keep their role; `BlobStore` is
a reproducibility cache so a run can be repeated against exactly the input it saw.

Host allowlist (SSRF-style controls, EXECUTED in tests/test_sources_github.py): `GitHubSource`
builds every URL from a constant base and then re-checks scheme `https`, host
`api.github.com`, default port and no userinfo on the final URL, independently of the
constant; redirects are never followed (a 3xx is refused with its target named); a timeout
and a response size cap apply; JSON must be an object with the expected fields and types,
base64 is decoded with validation, the declared size and the git blob sha are recomputed
from the decoded bytes. Any deviation is `SourceFormatError` with the raw response digest, so
the exact bytes can be examined. HTTP errors and rate limits become `SourceUnavailable` with
the status preserved. A token is read only from an environment variable the caller names in
`token_env`, sent only to the allowlisted host, and never stored, logged or recorded. The
User-Agent is a generic product string.

Path confinement (EXECUTED in tests/test_sources_local.py): `LocalFileSource` has no default
root. A path is resolved with realpath and must be inside a configured root; the open uses
O_NOFOLLOW and O_NONBLOCK and `fstat` must report a regular file, so directories, FIFOs,
devices and sockets are refused without being read and a FIFO cannot block the process.
Known gap: the resolved path can be swapped between realpath and open (TOCTOU) by someone
who can write inside the root; the last component is protected by O_NOFOLLOW, parents are
not.

Blob store: digests are validated before any path is built (no traversal through a digest),
one directory per tenant with a validated tenant name, atomic write, read-only mode, verify
on every read; a blob that no longer hashes to its name is refused and `verify_sources`
reports it. Anyone with file access can still delete or modify blobs; that is detected,
not prevented.

## The AI port (increment 2b): output is a proposal, never knowledge

Everything an AI port returns is untrusted text. The lab parses it with a strict schema
(unknown keys, wrong types, empty strings, oversize payloads and duplicate cites refused),
stores the raw text in the blob store before parsing so a rejected response is still
preserved with its digest, and records what survives as AI-origin proposals. An AI-origin
record can never carry the EXECUTED label, cannot be reviewed or accepted by its author,
and goes through the same governance rules as everything else; nothing it says changes any
other record.

Policy (attack 15, "research output cannot bypass WATCHER_MCU"): the investigation refuses,
before creating a plan or calling anything, every port whose kind the policy does not
allow. Under `STACK_PROFILE` only `watcher_mcu` is allowed, and the only port of that kind is
`WatcherAIPort`; an investigation that names the replay or baseline port, alone or beside
it, is refused (EXECUTED:
`tests/test_investigation.py::test_stack_profile_refuses_before_any_call` and
`tests/test_watcher_port.py::test_stack_profile_refuses_a_stand_in_beside_the_watcher_port_before_any_call`,
zero calls asserted). The kind is a string a port declares about itself: the policy does
not prove that a port of kind `watcher_mcu` really calls WATCHER_MCU, so a deployer who
hands `WatcherAIPort` another callable bypasses WATCHER_MCU; the adapter's strict check of
the wire response is a format check, not authentication. The policy is supplied by the deploying code, which means a deployer who passes
the development profile can run the non-vendor ports; moving the policy into the
tamper-evident genesis configuration is a later hardening.

Replay data: every recording the replay port accepts must declare
`origin: synthetic_test_data` in its header, and that origin is written into every record
derived from it. The recordings in this repository and in the demo are hand-written test
data, never a model's output. The deterministic baseline is keyword extraction; it is not a
model and its output is only as good as the heuristic.

Citation verification: a cite is VERIFIED when its quote appears verbatim, after whitespace
normalisation, in the preserved blob of the cited source entity of this tenant, and the
result records the character span of the match in the normalised source text so an
auditor can find the passage; otherwise it is UNVERIFIED with a reason (unknown source,
quote too short, quote not found, blob corrupt, blob missing) and kept, never dropped. A
verbatim quote of any length proves only that those words occur in the stored source. It
does not prove that the claim the quote supports is true, that the quote is in context, or
that the source is reliable. Short quotes are refused (fewer than `MIN_QUOTE_CHARS` = 20
characters or `MIN_QUOTE_TOKENS` = 4 words after normalisation, both overridable) to stop a
provider obtaining VERIFIED with a trivial substring such as "a" (found by the verifier's
attack7, case Q3). Case changes, quotes stitched from two places and quotes from another
source are UNVERIFIED. Agreement between proposals that cite a common source is not
validation; the investigation marks such pairs NOT_INDEPENDENT (attack 3).

Provider failure: one provider raising ProviderUnavailable, ProviderTimeout or
ProviderRefused, or returning a changed format, fails only its own task; the other ports
run; the plan cannot close until every task completed; a later retry completes it without
re-calling providers that already answered (idempotent by request digest).

What is not protected: a provider that returns well-formed JSON with verbatim quotes
chosen to mislead passes every check here; the checks are about form and provenance. No
live provider has been exercised. Credentials for a live provider are the adapter's
concern and are never recorded by the lab.

## What verify() does not detect

* **Full rewrite.** An attacker who rewrites the whole chain from genesis with fresh hashes
  produces a chain that verifies. Detection then depends on something the attacker does not
  hold: a signing key (`Signer`) or an external record of the head (`Anchor`). `HmacSigner`
  and `MemoryAnchor` are reference implementations; a durable anchor outside the host and a
  key held outside the process are deployment matters not built here.
* **Deleted tail.** Deleting the last N events leaves a shorter chain that verifies. Only an
  anchor of the head (EXECUTED: `test_deleted_tail_event_is_detected_by_anchor`) or an
  out-of-band count catches it.
* **HMAC is symmetric.** Anyone who can verify a signature can also forge one. `HmacSigner`
  proves "signed by a holder of this key", not "signed by this person". Asymmetric signing is
  not implemented.

## Identities are claims

A `Principal` id and an `Actor` id are strings the caller supplies. The store checks the
principal against the genesis entitlement set and the lifecycle checks actor ids against
authors and issuer ids, but nothing authenticates that the caller is who it says. Anyone with
file access and knowledge of an entitled id can open the store and, with a governance issuer
id and a HUMAN or SYSTEM actor kind, record a governance disposition. Authentication belongs to
the environment around this library or to a later increment. Do not read a governance
disposition in this log as proof that the named issuer acted.

## Append-only triggers are not a boundary

The SQLite triggers that refuse UPDATE and DELETE stop accidental edits through the normal
driver. Anyone who can write the file can drop them (the tests do exactly that). The
boundary is `verify()`, plus a signer or anchor against full rewrites.

## Keys

No key is hard-coded. No default key exists. `HmacSigner` refuses `None`, non-bytes, keys
shorter than 32 bytes and an empty key id. The key id is a label stored beside the signature;
it is not derived from the key and must not be treated as a secret. Supply keys from the
environment or a secret manager; never commit one.

## Clocks

Record timestamps come from an injected clock. A caller controls them, so a timestamp is not
evidence of when something happened. Order and integrity come from the chain sequence.

## Isolation: not yet built

Increment 1 runs no external code. Steps registered with the `Runner` run in-process with the
caller's privileges. There is no experiment runner, sandbox, subprocess confinement, rlimit,
network namespace or credential separation here. The proposal's isolation model (subprocess,
working-directory confinement, rlimits, no environment inheritance, `unshare` where available,
achieved level recorded per run) is designed only and belongs to increment 3.

## Network

The core makes no network calls and imports nothing outside the standard library (EXECUTED:
`tests/test_repo_hygiene.py`). Tests make no network calls.

## Threat notes for later increments

* AI output enters as PROPOSED records with origin kind AI. It is preserved, not accepted.
  Preservation and acceptance are different events, and the log shows which happened.
* A research agent that can write to the store can create records and lab transitions, but
  cannot accept or admit a finding, cannot review its own record, and cannot change issuers.
  It can still flood the log; rate and size limits are not implemented.
* Cross-tenant: one store, one tenant. There is no shared multi-tenant store, so the
  isolation is the file. File permissions are the deployment's job.
* SQLite WAL creates `-wal` and `-shm` side files beside the store. Protect and back up all
  three, or export a bundle.
