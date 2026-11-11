# The AI port contract a WATCHER_MCU implementation must satisfy

Status: **no WATCHER_MCU implementation of this port exists.** Not in this repository, and
not in WATCHER_MCU, which would need a change the owner has not reviewed (proposal section 6,
decision 1). Under `STACK_PROFILE` the lab therefore refuses every investigation before any
provider is called. Acceptance item 3 stays "not addressed" until that implementation
exists and passes the suite below.

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
provenance and behaviour, never text quality. Both shipped ports pass it (EXECUTED:
`tests/test_ai_port.py::test_conformance_baseline_and_replay`); a deliberately broken port
fails it (`test_conformance_reports_a_broken_port`).

## What a WATCHER_MCU implementation would also need to honour

* The cite-or-drop discipline of the Watcher applies to prose; here the output is JSON with
  quotes that the lab checks. Nothing in the lab grades a change or authorizes anything.
* The policy is supplied by the deploying code (`ProviderPolicy`), not fixed in genesis;
  the STACK profile allows only `watcher_mcu`.
* The port never receives credentials from the lab; credential handling stays in the
  adapter and is never recorded.
* Every call is recorded: request and raw response bytes in the blob store, an `ai_call`
  provenance block on every record derived from the output, `policy_profile` included.

## What this document does not claim

No live provider has been exercised through the port. The two implementations that exist
are a replay of synthetic test data and a deterministic keyword extractor that is not a
model. Whether the WATCHER_MCU narrator can be adapted to this contract without changing its
own oath is UNKNOWN until the owner reviews that change.
