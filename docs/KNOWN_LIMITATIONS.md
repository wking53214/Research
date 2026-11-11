# Known limitations (increment 1)

Started with the first construction, as the proposal asked. Each item says whether it is a
design choice for now or a gap.

1. **Identities are not authenticated.** Principal and actor ids are claims (gap; see
   SECURITY.md).
2. **Entitlements are fixed at genesis.** The set of principals that may open a store cannot
   be changed afterwards. Adding a collaborator means a new store or a later increment that
   records entitlement changes as signed events (design choice for now).
3. **Review independence is thin.** Only the same-actor rule and the governance actor-kind
   rule exist. A second AI id may move a finding to REVIEWED, REPRODUCED or RECOMMENDED. The
   test `test_increment1_limitation_a_different_ai_may_review` records this on purpose (gap,
   increment 3).
4. **No full-rewrite detection without a signer or anchor.** See SECURITY.md (inherent to
   hash chains; mitigations exist as protocols with reference implementations).
5. **HMAC only.** No asymmetric signatures, no key rotation, no multiple keys per store.
6. **Graph is in memory and rebuilt on open.** Fine for increment 1 sizes; cost grows with the
   log. No incremental snapshot exists.
7. **Concurrency.** Several Labs (in one process or several) may write to one file; the store
   validates each append against the real head under its write lock, so a stale writer gets
   `ConcurrentWriteConflict` when its event is invalid on the real state and nothing is
   written (EXECUTED: `tests/test_concurrency.py`, including a two-process test). A Lab is
   bound to the thread that opened it; other threads get `ThreadAffinityError`. Not covered:
   a stale writer must call `Lab.refresh()` or retry to see what others wrote; a reader with a
   stale graph answers queries from that stale graph until it refreshes; write throughput is
   one writer at a time with SQLite's default busy timeout; a very long log makes every
   catch-up and open slower. No repair tool exists for a store poisoned outside the validated
   path (a bare store with no validator, or direct SQL).
7b. **The unvalidated opt-out exists.** `EventStore.open(..., unsafe_unvalidated=True)` and
   the same on `create` write without the policy validator. They exist for tests only; a
   deployment that wants to be sure should grep for the name. Direct SQL remains possible
   for anyone with file access regardless.
7c. **A bare store's default validator loads lazily.** Its first append replays the whole log
   inside the write transaction; on a long log that first append is slow.
7d. **Challenges are unlimited.** Any entitled actor may file any number of challenges; they
   have no authority effect, so this is noise, not control. No cap per actor exists yet.
7a. **Policy replay does not authenticate.** Replay validation (SECURITY.md) refuses events
   that break the rules, but an event whose actor claims a SYSTEM kind under a new id with a
   public issuer id is within the rules. Identity is the gap, not the rules.
8. **Bundle import and merge are not implemented.** Export and verify only.
9. **The CLI covers a subset.** `add` handles objective, question, hypothesis and evidence;
   governance dispositions, plans and runs are Python API only.
10. **Entity ids are prefixes.** A derived id is 16 hex characters of the entity digest; the
    full digest is stored and checked, and the store refuses a duplicate id, but two different
    seeds with the same 64-bit prefix would collide at add time with a refusal, not a merge.
11. **Timestamps are caller-controlled.** By design; see SECURITY.md.
12. **Canonical JSON is Python-shaped.** Float formatting follows Python's repr. Byte-for-byte
    agreement with another language's canonicaliser is not claimed.
13. **No isolation, no execution port, no source or AI adapters.** Designed only; see README.
14. **Runs tested on Python 3.13 only.** 3.11 and 3.12 support is INFERRED from the features
    used (PEP 604 unions, `str | None`, dataclasses, `sys.stdlib_module_names` exists since
    3.10), not EXECUTED.
15. **Acceptance list wording was not available to the builder.** The README table marks
    those rows UNKNOWN rather than guessing.
17. **Sources (increment 2a).** Two adapters only (GitHub REST, local files). GitHub: the
    contents endpoint returns base64 only for files up to 1 MB; a larger file comes back
    with another encoding and is refused as `SourceFormatError` (the git blobs endpoint is
    not used yet); annotated tags are refused; unauthenticated rate limit is low (60 per
    hour per address at capture time); no retry or backoff. Local files: TOCTOU between
    realpath and open on parent directories (see SECURITY.md). Blob store: no garbage
    collection, no quota beyond the per-blob cap, deletion by anyone with file access is
    detected, not prevented. `source_by_locator` scans every source node (linear).
    `record_source` does not verify that an existing blob for an idempotent re-fetch is
    intact; `verify_sources` does. The demo's local-file example depends on a sibling
    checkout of WATCHER_MCU being present; the test uses a stand-in file.
18. **AI port (increment 2b).** No live provider has ever been called: the contract is
    exercised only by a synthetic replay, a deterministic extractor and `WatcherAIPort`
    over fakes. The WATCHER_MCU side of that adapter (`watcher/port.py`) is on an
    UNREVIEWED, UNMERGED branch (`ccr-1d38b634-vzy1xp`); if it changes in review, the
    adapter and the wire format in `docs/WATCHER_MCU_PORT.md` must change with it, and only
    the `integration` test (deselected by default) would notice. Whether the real API
    accepts the call WATCHER_MCU makes for this port is not shown by anything here.
    `WatcherAIPort` sends `instructions` and the excerpts; the request's `purpose` and
    `settings` are not sent (the request digest covers them). The WATCHER_MCU version that
    answered is recorded inside `usage` as `watcher_adapter_version`, because `AIResponse`
    has no field for it. There is no timeout mapping: the wire has no timeout code, so a
    timeout arrives as `ProviderUnavailable`, never `ProviderTimeout`. A wire request the
    other side calls malformed or too large is a `ProviderRefused`. An exception with no
    known `code` becomes `ProviderUnavailable` naming only its type. After a failed
    provider is retried on resume, the `analyse` step is not re-run (it completed in the
    first run), so that provider's hypotheses get no independence check
    (`tests/test_watcher_port.py` asserts this as a recorded gap). The
    policy is supplied by the deployer, not by genesis. The baseline's sentence splitter
    and keyword overlap are crude; its proposals are quotes, not insight. Excerpts are the
    first `max_excerpt_chars` characters of each source, so a provider never sees the rest.
    Hypotheses from a port are linked to one framing question, not to the port's own
    questions. Contradictions are not detected by the runner; `record_contradiction`
    preserves what a person identifies. The independence check only compares cited
    sources; two providers trained on the same material are not detected. Citation checks
    use whitespace normalisation only (no Unicode folding, no fuzzy match), so a quote with
    a different dash or quotation mark is UNVERIFIED. A quote shorter than 20 characters or
    4 words is always UNVERIFIED, even when it is genuinely in the source. A long verbatim
    quote can still be cited for a claim it does not support; VERIFIED says the words are
    there at the recorded span, nothing more. Request and response blobs share the
    source blob store and count against the same cap. No `investigate` CLI command.
16. **ruff and bandit were not run** in the build environment (not installed, no installs
    allowed). The configuration in `pyproject.toml` is untested here.
