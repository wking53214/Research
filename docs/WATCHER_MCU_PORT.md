# The AI port contract a WATCHER_MCU implementation must satisfy

Status: **implemented on both sides, offline only, and not reviewed.** The lab side is
`WatcherAIPort` (`research_lab/ai/watcher.py`). The WATCHER_MCU side is a generic port,
`watcher/port.py`, on WATCHER_MCU branch `ccr-1d38b634-vzy1xp`: UNREVIEWED and UNMERGED
(proposal section 6, decision 1 is the owner's to make). The two agree on the wire format
below in offline tests. **The live path has never been executed, because no credential
exists:** no model has answered through this port, in a test or by hand. Acceptance item 3
is "partially implemented" on that basis and no further.

Labels: EXECUTED, INSPECTED, INFERRED, UNKNOWN.

## The contract (`research_lab/ai/port.py`, EXECUTED by tests/test_ai_port.py)

An implementation is any object with these attributes and one method:

| Member | Type | Meaning |
|---|---|---|
| `provider_id` | str | A label for this port instance, for example `watcher-mcu`. Recorded in every `ai_call` block. |
| `provider_kind` | str | The policy key. A WATCHER_MCU implementation uses `"watcher_mcu"` (`research_lab.ai.policy.WATCHER_MCU_KIND`). Only this kind is allowed under `STACK_PROFILE`. |
| `adapter_version` | str | Version of the adapter code. |
| `is_live` | bool | True when `complete()` reaches an external service. |
| `is_model` | bool | True when the output is, or replays, a model's output. Records produced from such output get origin kind AI. |
| `origin` | str | Short tag recorded in provenance: the live provider name for a live port, never `"live"` for a port that is not live. |
| `complete(request: AIRequest) -> AIResponse` | method | The only call. |

`AIRequest` (frozen): `purpose`, `instructions`, `inputs` (tuple of `SourceInput`:
`source_id`, `content_digest`, `excerpt` exactly as given to the model), `max_output_tokens`,
`settings` (canonical JSON), `request_digest` (SHA-256 over the canonical JSON of all of
these, computed by the request itself; an implementation never sets it). The implementation
must not mutate the request.

`AIResponse` (frozen): `text`, `provider_id`, `provider_kind`, `adapter_version`,
`model_requested`, `model_reported`, `request_digest` (echo of the request's),
`response_digest` (SHA-256 of `text` as UTF-8; checked on construction), `finish_reason`,
`usage` (canonical JSON), `latency_seconds` (int, from an injected clock),
`is_live`, `origin`. `research_lab.ai.port.build_response` fills the provenance fields
from the port and the request.

Errors, all subclasses of `AIError`: `ProviderUnavailable(reason, status)` (network,
outage, rate limit), `ProviderTimeout` (a subclass of `ProviderUnavailable`),
`ProviderRefused` (the provider or a policy declined; not a subclass of unavailable),
`ResponseFormatError(reason, response_digest)` (raised by the lab's parser, not by ports).
A port raises only these; anything else is a conformance failure.

The output text must be the strict JSON of `research_lab/ai/outputs.py`:
`{"questions":[{"text":...}],"hypotheses":[{"text":...,"cites":[{"source_id":...,"quote":...}]}]}`
with no other keys. Quotes must be verbatim from the excerpt of the cited source; the lab
verifies them against the preserved blob and flags the rest UNVERIFIED.

## The conformance suite (`research_lab/ai/conformance.py`)

```python
from research_lab.ai import assert_conformant
results = assert_conformant(port, request, unknown_request=None)
```

Checks, all required: `port_attributes`, `request_digest_deterministic`,
`error_classes_distinguishable`, `request_not_mutated`, `response_provenance`,
`same_request_same_provenance`, and `unknown_request_handled` when an unknown request is
given (it must be answered or refused through the defined errors only). The suite checks
provenance and behaviour, never text quality. The replay and baseline ports pass it
(EXECUTED: `tests/test_ai_port.py::test_conformance_baseline_and_replay`), `WatcherAIPort`
passes it over a fake of the wire contract
(`tests/test_watcher_port.py::test_conformance_over_a_fake_that_keeps_the_wire_contract`);
a deliberately broken port fails it (`test_conformance_reports_a_broken_port`).

## The wire format between the lab and WATCHER_MCU

Plain JSON-shaped mappings, so neither repository imports the other. The adapter is handed
a callable; `research_lab.ai.load_watcher_call()` returns `watcher.port.complete`,
importing it only when called.

Request, built by `research_lab.ai.watcher.wire_request` (EXECUTED:
`tests/test_watcher_port.py::test_the_wire_request_is_built_from_the_request_and_the_request_is_not_changed`):

| Key | Value |
|---|---|
| `instructions` | `AIRequest.instructions` |
| `inputs` | one string per `SourceInput`: a `source_id:` line, a `content_sha256:` line, then the excerpt |
| `model` | the model the port was constructed with |
| `max_output_tokens` | `AIRequest.max_output_tokens` |
| `request_digest` | `AIRequest.request_digest`, opaque to WATCHER_MCU, echoed back |
| `effort` | only when the port was constructed with one |

`purpose` and `settings` are not sent; the request digest covers them. WATCHER_MCU refuses
any other key, over 200000 bytes of UTF-8 in `instructions` and `inputs` together, and over
16000 output tokens (INSPECTED in `watcher/port.py`; EXECUTED only by the integration test).

Response: exactly the keys `text`, `provider_id` (`"watcher_mcu"`), `provider_kind`
(`"watcher_mcu"`), `adapter_version` (WATCHER_MCU's version), `model_requested`,
`model_reported` (string or null), `finish_reason`, `usage` (null, or `input_tokens` and
`output_tokens`), `request_digest` (the echo), `response_digest` (SHA-256 of `text` as
UTF-8), `is_live` (true). The adapter rejects anything else as `ResponseFormatError`: a
missing or extra key, a wrong type, a digest that does not match the text, an echo that is
not the lab's own request digest, a different `model_requested` (EXECUTED:
`test_a_response_that_breaks_the_wire_contract_is_rejected`, 21 cases, each also run
through the conformance suite). The error carries the raw text, and `run_investigation`
writes it to the blob store before the task fails
(`test_a_wire_violation_fails_the_task_and_the_raw_text_is_preserved`).

In the `AIResponse`: `provider_id` and `adapter_version` are the lab port's own (`"1"`),
`model_reported` null becomes `"unreported"`, WATCHER_MCU's version is kept in `usage` as
`watcher_adapter_version`, and `latency_seconds` comes from the lab's clock.

Failures are exceptions with a string attribute `code`:

| `code` | Meaning on the WATCHER_MCU side | Lab error |
|---|---|---|
| `refused` | the model declined | `ProviderRefused` |
| `too_large` | input bytes or output tokens over the cap; nothing sent | `ProviderRefused`, reason says too large |
| `format` | the wire request has the wrong shape; nothing sent | `ProviderRefused`, reason says malformed |
| `unavailable` | no credentials, SDK error, response that is not a message | `ProviderUnavailable` |
| any other code, or no `code` | not part of the contract | `ProviderUnavailable` naming the exception type only (its message is not copied into the event log) |

WATCHER_MCU does not apply its oath to this port and does not grade: the text comes back
unfiltered. The lab's own strict parser and citation check are what stand between the text
and a record.

Cross-repository check (EXECUTED once by the builder, not part of the default suite):

```
PYTHONPATH=/path/to/WATCHER_MCU:/path/to/CNS python -m pytest -m integration
```

It imports the real `watcher.port` and drives it with a fake narrator through
`WatcherAIPort`: conformance, the request as WATCHER_MCU's narrator receives it, each
failure code, the size cap, and one investigation under `STACK_PROFILE`. No network, no
model. CNS is on the path only because WATCHER_MCU imports it.

## What a WATCHER_MCU implementation also honours

* The cite-or-drop discipline of the Watcher applies to prose; here the output is JSON with
  quotes that the lab checks. Nothing in the lab grades a change or authorizes anything.
* The policy is supplied by the deploying code (`ProviderPolicy`), not fixed in genesis;
  the STACK profile allows only `watcher_mcu`.
* The port never receives credentials from the lab; credential handling stays in the
  adapter and is never recorded.
* Every call is recorded: request and raw response bytes in the blob store, an `ai_call`
  provenance block on every record derived from the output, `policy_profile` included.

## What this document does not claim

No live provider has been exercised through the port. Every answer in every test is
synthetic test data returned by a fake; `examples/live_watcher_demo.py` refuses to run
without `--live` and a credential WATCHER_MCU can see, and has never been run live. That
the real API accepts the call WATCHER_MCU makes for this port, and that a real model
returns the strict JSON the lab parses, are UNKNOWN. The WATCHER_MCU change adds a port
beside the narrator and leaves the narrator and its oath as they were (INSPECTED, and its
own suite is unchanged); whether the owner accepts WATCHER_MCU carrying a call it does not
filter is the owner's decision and is not made.
