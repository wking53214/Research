# The governance port: signed grants

Status: implemented and tested offline (`tests/test_ed25519.py`,
`tests/test_governance_grants.py`, `tests/test_governance_modes.py`,
`tests/test_governance_cli.py`, `tests/test_governance_export.py`,
`tests/test_governance_vector.py`, `examples/governance_demo.py`). Every signature in those
tests is made by a test-only signer with public seeds. No real governance key, HSM, KMS or
CNS identity has ever signed a grant for this code; that path is specified here and has not
been exercised.

## The problem this closes

Before this port a governance disposition (a finding to ACCEPTED or ADMITTED, a governed
finding to WITHDRAWN, a challenge to UPHELD or DISMISSED) was authorized by a claim: an
actor object of kind HUMAN or SYSTEM plus an issuer id found in the genesis event. Genesis
issuer ids are public. An AI that invented an actor id, labelled it SYSTEM and quoted the
issuer id could record ACCEPTED or dismiss a challenge (attack A5, and Y2 for challenges).

The port separates three things that the claim mixed up:

* enrollment: which public keys speak for governance. Fixed in the genesis event.
* authorization: a governance body signs a grant, outside the lab, with its private key.
* enforcement: the lab verifies the grant and records the disposition, or refuses.

The lab holds public keys only. It can verify that a governance body issued a disposition.
It cannot forge one. There is no signer, no key generation and no private key handling in
the `research_lab` package or its command line.

## Modes

The mode is fixed in the genesis event and nothing changes it afterwards.

| Mode | Who it is for | How a disposition is authorized |
|---|---|---|
| `AUTHENTICATED` | every new store (the default) | a grant signed by a key the genesis enrolled; `Lab.apply_grant` |
| `UNAUTHENTICATED_LEGACY` | stores written before this port, and callers who opt out explicitly | the increment 1 claim (HUMAN or SYSTEM actor, issuer id in genesis); `Lab.govern` |

`UNAUTHENTICATED_LEGACY` is never chosen silently. In Python it must be passed as
`governance_mode="UNAUTHENTICATED_LEGACY"` and creating the store raises
`UnauthenticatedGovernanceWarning`. On the command line it is `init
--unauthenticated-governance`, which prints a warning to stderr. It is written into the
genesis, and `verify`, `show`, `Lab.verify()` and `verify_bundle()` report it together with
every disposition marked `authenticated: false`. Attacks A5 and Y2 still succeed in this
mode; that is what the mode means, and a test asserts it so it cannot be forgotten.

A genesis with `schema_version` 1 (written before this port: plain issuer ids, no mode
field) still opens and replays as it always did. It is read as `UNAUTHENTICATED_LEGACY`.
Nothing is rewritten and it cannot be upgraded in place: a second genesis is refused.

An `AUTHENTICATED` store may enroll no issuer at all. Then no governance disposition is
ever possible in it.

## Genesis schema version 2

```json
{
  "schema_version": 2,
  "tenant": "acme",
  "governance_mode": "AUTHENTICATED",
  "governance_issuers": [
    {
      "issuer_id": "governance-board",
      "kind": "human_body",
      "alg": "ed25519",
      "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "key_id": "ed25519:21fe31dfa154a261"
    }
  ],
  "grant_skew_seconds": 300,
  "principals": ["alice"]
}
```

* `kind` is `human_body` or `system`. Every other kind is refused at creation and on
  replay; `ai` and `model` are refused with a message that says an AI can never be a
  governance issuer. The kind is a label the enrolling party chose. The lab cannot check
  that a human body really holds the key.
* `alg` is `ed25519`. Nothing else is accepted.
* `public_key` is the 32-byte Ed25519 public key as 64 lowercase hex characters. It must be
  a canonical encoding of a curve point that is not of small order. One key cannot be
  enrolled under two issuer ids, and one issuer id cannot be enrolled twice.
* `key_id` is `"ed25519:"` plus the first 16 hex characters of the SHA-256 of the public
  key bytes. It is a display label. It is never an integrity input: verification always
  uses the full public key enrolled under the grant's `issuer_id`. A genesis whose label
  does not match its key is refused, so the label cannot mislead a reader.
* `grant_skew_seconds` (0 to 3600, default 300) is how far ahead of the lab clock a
  grant's `issued_at` may be. It lives in the genesis so that the write path and every
  replay use the same value.
* In `UNAUTHENTICATED_LEGACY` mode `governance_issuers` is a list of plain ids and there is
  no `grant_skew_seconds`.
* The field set is exact. A version 2 genesis with an unknown field is refused on replay.

Mode, issuers and keys are tamper-evident in the same sense as the rest of the log: the
genesis is event 0 of the hash chain, a second GENESIS is refused on write and on replay,
and no event type or API touches issuers, keys or mode. See "What the port does not prove"
for what tamper-evident does not cover.

## The GovernanceGrant

Eleven fields, all required, no others allowed:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | grant format version; `1` |
| `tenant` | string | the store's tenant |
| `entity_id` | string | the finding or challenge being disposed |
| `entity_version` | integer | the version being disposed; must be the entity's current version |
| `record_digest` | 64 hex | the full SHA-256 digest of that exact version |
| `to` | string | `ACCEPTED`, `ADMITTED`, `WITHDRAWN`, `UPHELD` or `DISMISSED` |
| `issuer_id` | string | the enrolled issuer whose key signs |
| `nonce` | hex | 16 to 32 bytes, lowercase hex, chosen by the signer, single use per tenant |
| `issued_at` | string | `YYYY-MM-DDTHH:MM:SSZ`, UTC |
| `expires_at` | string | same format; must be after `issued_at`; exclusive |
| `reason` | string | non-empty; recorded with the disposition |

A signed grant is the same object with one more field, `signature`: the 64-byte Ed25519
signature as 128 lowercase hex characters.

### The exact bytes that are signed

```
signing_bytes = b"research-lab/governance-grant/1\n" + canonical_json(grant_without_signature)
signature     = Ed25519.sign(private_key, signing_bytes)        (pure Ed25519, RFC 8032; no prehash)
```

`canonical_json` is the lab's existing canonical form (`research_lab/canonical.py`), which
for a grant comes down to:

* one JSON object with exactly the eleven fields, keys sorted by code point;
* no whitespace anywhere: separators are `,` and `:`;
* ASCII only: any non-ASCII character in a string is written as a `\uXXXX` escape (the
  form Python's `json.dumps(..., ensure_ascii=True)` writes);
* strings in Unicode NFC. A grant whose strings are not already NFC is refused, so the
  bytes a signer sees are the bytes the lab checks;
* integers written in plain decimal (`"v":1`, `"entity_version":4`);
* the 32 bytes of the domain line end with one line feed (0x0a) and there is no trailing
  newline after the JSON.

The domain line binds the signature to this purpose and this format version. The same key
signing some other protocol's message cannot produce a valid grant by accident.

Any Ed25519 signer that can sign an arbitrary byte string can produce a grant: sign
`signing_bytes`, hex-encode the 64-byte result in lowercase, add it as `signature`.
`Lab.grant_template(...)` builds the unsigned grant for an entity's current version,
`Lab.grant_signing_bytes(grant)` (or `research_lab.governance.grant_signing_bytes`) returns
the bytes, and `python -m research_lab governance sign-bytes` prints both. A signer should
read the grant it is about to sign, not only its hex.

### Worked example (a public test vector)

The key pair is the RFC 8032 section 7.1 TEST 1 pair. Its secret seed is published in the
RFC, so this is a test key by construction. Never enroll it anywhere real.

```
secret seed (PUBLIC TEST VALUE): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public key:                      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
key_id (label):                  ed25519:21fe31dfa154a261
```

The grant:

```json
{
  "v": 1,
  "tenant": "acme",
  "entity_id": "finding_0123456789abcdef",
  "entity_version": 4,
  "record_digest": "bee6b421074d7797be6caefdad0a38c47417c9b2c2f43e7c54b68344354225cd",
  "to": "ACCEPTED",
  "issuer_id": "governance-board",
  "nonce": "000102030405060708090a0b0c0d0e0f",
  "issued_at": "2026-06-01T12:00:00Z",
  "expires_at": "2026-06-02T12:00:00Z",
  "reason": "Reproduced twice; the board accepts."
}
```

Its canonical JSON, one line, 373 bytes:

```
{"entity_id":"finding_0123456789abcdef","entity_version":4,"expires_at":"2026-06-02T12:00:00Z","issued_at":"2026-06-01T12:00:00Z","issuer_id":"governance-board","nonce":"000102030405060708090a0b0c0d0e0f","reason":"Reproduced twice; the board accepts.","record_digest":"bee6b421074d7797be6caefdad0a38c47417c9b2c2f43e7c54b68344354225cd","tenant":"acme","to":"ACCEPTED","v":1}
```

The signing bytes (405 bytes: the 32-byte domain line, then the 373 bytes above), in hex:

```
72657365617263682d6c61622f676f7665726e616e63652d6772616e742f310a7b22656e746974795f6964223a2266696e64696e675f30313233343536373839616263646566222c22656e746974795f76657273696f6e223a342c22657870697265735f6174223a22323032362d30362d30325431323a30303a30305a222c226973737565645f6174223a22323032362d30362d30315431323a30303a30305a222c226973737565725f6964223a22676f7665726e616e63652d626f617264222c226e6f6e6365223a223030303130323033303430353036303730383039306130623063306430653066222c22726561736f6e223a22526570726f64756365642074776963653b2074686520626f61726420616363657074732e222c227265636f72645f646967657374223a2262656536623432313037346437373937626536636165666461643061333863343734313763396232633266343365376335346236383334343335343232356364222c2274656e616e74223a2261636d65222c22746f223a224143434550544544222c2276223a317d
```

```
SHA-256 of the signing bytes (the grant_digest): 0af6966582156a2bdf0f8492cc4db72fd5a982a564876b4428a1b0c10826e04c
Ed25519 signature:                               59c2f0558a576409f356a5e76511a7ebbe6341c36f73299522731a4d54a06e0aa245329a7cdbd1640bfc73bc20fdc525f1a29afdab23d94c390f859081df2a05
```

Ed25519 is deterministic, so any correct implementation produces this exact signature from
this seed and these bytes. `tests/test_governance_vector.py` checks every value above,
checks that the lab's verifier accepts the signature and rejects it after any field
changes, and checks that this document states the same values as the test. When the vector
was produced an independent Ed25519 library gave the same signature and verified it; that
cross-check is not part of the test suite, which uses the standard library only.

The entity id and record digest in the example are made up, so this grant verifies as a
signature but applies to no store.

## Verification

One function, `Graph.check_grant`, does all of it. It is called by `Lab.apply_grant` before
anything is built, by the store's validator inside the append transaction (under the write
lock, against the real head), and by every replay: `Lab.open`, `Lab.verify`,
`verify_store`, `verify_bundle`. A grant event that the write path would refuse is refused
on replay with the same message.

In order:

1. The store is `AUTHENTICATED`. A legacy store enrolls no keys and refuses every grant.
2. Shape: exactly the eleven fields, the types and formats above, NFC strings, a
   128-hex signature.
3. `tenant` equals the store's tenant.
4. `issuer_id` is enrolled in the genesis, and the signature verifies over the signing
   bytes under that issuer's public key (strict Ed25519, below). The key of a different
   enrolled issuer does not verify.
5. The nonce has never been used in this tenant. The used set is rebuilt from the log.
6. The entity exists; `entity_version` equals its current version; `record_digest` equals
   that version's digest. A grant signed for version 4 is refused once the entity is at
   version 5, even when the status is the same again.
7. `to` is a governance transition for that entity from its current status and is in the
   transition table (the same table and the same `governance_required` rule as before).
   The issuer id is not the entity author's id (for a challenge, not the filer's): the
   no-self-approval rule is kept.
8. Time, by the lab clock: refused when the lab time is at or after `expires_at`, and when
   `issued_at` is more than `grant_skew_seconds` after the lab time.

The event must then be exactly the transition the grant authorizes: the same entity, the
event's `to` and `reason` equal to the grant's, and the new version's provenance equal to
`{"type": "governance_disposition", "issuer_id", "reason", "grant_digest"}`, where
`grant_digest` is the full SHA-256 of the signing bytes. The record digest of the disposed
version therefore covers the grant.

On replay the "lab time" of step 8 is the `created_at` of the version the event writes,
which is the lab clock's reading when the grant was applied.

### Who may submit

Anyone entitled to write to the store, of any actor kind. An AI that was handed a signed
grant may relay it, and so may the finding's own author. Submitting a grant is not
authority; the signature is. In `AUTHENTICATED` mode the actor kind is no longer consulted
for governance, and the submitting actor is recorded as the origin of the new version so
the log shows both who authorized (the issuer) and who submitted (the actor).

### The event

```json
{
  "record": { "...": "the next version, origin = the submitting actor" },
  "from": "RECOMMENDED",
  "to": "ACCEPTED",
  "actor": { "id": "model-2", "kind": "AI", "provider": "vendor", "model_family": "family" },
  "reason": "Reproduced twice; the board accepts.",
  "governance": {
    "issuer_id": "governance-board",
    "grant": { "...": "the eleven fields" },
    "signature": "128 hex characters"
  }
}
```

The full grant and signature are stored, so any reader can verify offline: the genesis line
gives the public key, the event gives the grant and the signature.
`research_lab.governance.verify_grant_signature(grant, signature, keys)` is the stateless
check; `verify_bundle(path)` does the whole replay from the file alone.

### Strict Ed25519

`research_lab/crypto/ed25519.py` is a verify-only, standard-library implementation of pure
Ed25519 (RFC 8032). It returns False, and never raises, when:

* the public key is not 32 bytes or the signature is not 64 bytes;
* the public key or R is not a canonical encoding (y not below p, or x = 0 with the sign
  bit set) or is not on the curve;
* the public key or R is one of the 8 small-order points (this covers the identity and the
  all-zero key);
* S is not below the group order L (the malleable form S + L is refused);
* the cofactorless equation [S]B = R + [k]A does not hold.

It is not constant time and does not need to be: every input is public. It passes the RFC
8032 section 7.1 vectors TEST 1, TEST 2, TEST 3 and TEST SHA(abc). The 1023-byte TEST 1024
vector is not in the suite because it could not be obtained offline; this is a gap in the
vector coverage, not a known failure. A public key of mixed order (a prime-order point plus
a small-order component) is not rejected by a subgroup check.

## Lifecycle of a disposition

1. Enrollment, once: the store is created with the governance body's public key
   (`init --issuer ID:KIND:PUBKEYHEX`, or `Lab.create(..., governance_issuers=[make_issuer(...)])`).
   Record the genesis hash that `verify` prints somewhere outside the store.
2. Request: the lab reads the current state and prints what must be signed.

   ```sh
   python -m research_lab governance sign-bytes --db lab.sqlite --tenant acme --principal alice \
       --entity <FINDING_ID> --to ACCEPTED --issuer-id governance-board --reason "Reproduced twice; the board accepts."
   ```

   The output has `grant` (the eleven fields), `signing_bytes_hex`, `signing_bytes_utf8`,
   `grant_digest` and the enrolled key that must sign. `--nonce` supplies the signer's
   nonce; without it 16 fresh random bytes are generated and the output says so.
   `--issued-at` and `--expires-at` set the window (default: now, plus 24 hours). Nothing is
   written.
3. Signature: the governance body reviews the grant and signs the bytes with its own
   signer, outside the lab. It may change the nonce or the window first; it then signs the
   bytes of the grant as changed.
4. Submission: the grant plus `signature` goes into a JSON file and anyone submits it.

   ```sh
   python -m research_lab governance apply --db lab.sqlite --tenant acme --principal alice \
       --actor clerk-7 --actor-kind HUMAN --grant grant.json
   ```

5. The lab verifies and appends one TRANSITION event, or refuses and writes nothing.
6. Afterwards the grant is spent (nonce used, version moved on). `verify` and `show` list
   the disposition with `authenticated: true`, the issuer, the key label, the nonce and the
   grant digest. `export` carries it; `verify_bundle` re-verifies it from the file.

## API

| Call | Mode | What it does |
|---|---|---|
| `Lab.apply_grant(grant, actor)` | AUTHENTICATED | verifies and records the disposition; refused in a legacy store |
| `Lab.govern(entity_id, to, actor, issuer_id, reason)` | UNAUTHENTICATED_LEGACY | unchanged from increment 1; refused in an AUTHENTICATED store with a message that names `apply_grant` |
| `Lab.grant_template(entity_id, to, issuer_id, reason, nonce, issued_at=None, expires_at=None)` | AUTHENTICATED | the unsigned grant for the entity's current version; reads state, signs nothing |
| `Lab.grant_signing_bytes(grant)` / `governance.grant_signing_bytes(grant)` | any | the exact bytes to sign |
| `governance.make_issuer(issuer_id, kind, public_key_hex)` | creation | one validated issuer record for the genesis |
| `governance.verify_grant_signature(grant, signature, keys)` | any | the stateless signature check |
| `Graph.check_grant(signed_grant, applied_at)` | AUTHENTICATED | the full check against current state; shared by write and replay |
| `verify_store(..., expected_genesis_hash=, require_authenticated=)`, `verify_bundle(...)` likewise | any | make a wrong genesis or unauthenticated governance a verification failure |

`apply_grant` is a separate method, not a mode-aware `govern`: the two take different
arguments and mean different things, and a caller should not be able to believe it used
the authenticated path when it did not.

Refusals raise `GrantRefused` (a subclass of `AuthorityError`, so existing handlers still
catch it), `SelfReviewError` or `TransitionError` from the Lab, and `PolicyViolation` from
the store's validator and from replay.

## What the port proves

When a disposition is listed as `authenticated: true` in a store or bundle that verifies:

* a holder of the private key enrolled for that issuer in that genesis signed a statement
  authorizing this exact transition (`to`), of this exact entity, at this exact version
  with this exact content digest, in this tenant, with this reason, valid in the stated
  time window;
* the disposition was recorded once (the nonce is single use and the version moves on);
* nothing in the grant was altered after signing.

## What the port does not prove

* That the key holder is who the issuer id says. Enrollment is whatever the creator of the
  store wrote into the genesis. `kind: human_body` is a label.
* That the key is uncompromised. A stolen key signs valid grants.
* That the decision was wise, informed or made by due process. The port carries a
  decision; it does not make one. No quorum, seats or process exist here.
* That the grant was applied inside its time window by an honest clock. See clock trust
  below.
* That the genesis in front of you is the right one. See the next section.

## Limitations and design notes

* **No rotation and no revocation.** Issuer keys are fixed at genesis for the life of the
  store. A compromised or lost key cannot be replaced or revoked in this increment. The
  only remedy today is a new store with a new genesis. Design note for a later increment:
  rotation and revocation would themselves have to be grants (or a quorum of grants) signed
  by keys already enrolled, recorded as events and replayed in order, and a verifier would
  then need the pinned genesis plus the whole enrollment history; a revocation that takes
  effect "from seq N" does not undo dispositions recorded before N. None of that is built.
* **Key custody is external.** Where the private key lives and who can use it is outside
  this library. The library never sees it.
* **A whole-file rewrite defeats the chain, not the signatures.** The hash chain has no
  secret in it. Someone who can replace the entire store or bundle can recompute every
  hash. They still cannot alter or invent a grant under an enrolled key: tests rewrite a
  grant, swap a genesis key and recompute the chain, and the replay refuses each. What they
  can do is write a different genesis, one that enrolls their own key or that is
  `UNAUTHENTICATED_LEGACY`, and build a self-consistent file around it. Two tests assert
  exactly that as recorded gaps. The defence is the verifier's: pin the genesis hash
  obtained out of band (`verify --expect-genesis-hash`, `expected_genesis_hash=`) and
  require the mode (`--require-authenticated`, `require_authenticated=True`). An external
  anchor or a store signer (both already exist as protocols) also help for a live store.
* **Clock trust.** `expires_at` and `issued_at` are compared with the lab clock, which is
  injected and belongs to whoever runs the lab (`--at` on the command line). A submitter
  who controls that clock, or who writes an event directly, can present an expired but
  never used grant as applied in time. Expiry therefore limits how long an unused grant is
  useful to an honest lab; it is not a defence against a submitter who lies about the time.
  What bounds the damage is the rest of the binding: the grant still authorizes only that
  transition of that exact version, once.
  A test asserts this as a recorded gap.
* **Code inside the lab process is trusted.** The validator is in-process state. Code
  running in the lab's own process can overwrite the live graph's copy of an enrolled key,
  or use the store's unsafe test opt-out, and get a forged grant written. It does not
  verify afterwards: the next open and every `verify` read the genesis from the log and
  refuse the event, and with it the store. That is a way to poison a store, not a way to
  forge a disposition that passes verification. A test asserts this too. There is no repair
  tool for a poisoned store; keep verified bundle exports.
* **Legacy mode exists.** A store created with the opt-out, or before this port, has
  unauthenticated governance. It says so in every report.
* **Self-approval is by id.** The rule compares the issuer id with the author's actor id.
  Issuer ids and actor ids are separate namespaces chosen by people, so the rule catches
  the same name, not the same person.
* **A grant is not confidential.** It is stored in full in the log and in bundles.
* **Denial.** A grant can be made useless before it is applied by moving the entity to a
  new version with a lab transition (for example RECOMMENDED to REPRODUCED and back). That
  fails safe: the issuer signs again for the new version.
* **Speed.** Verification is pure Python, a few milliseconds per grant, and a replay
  verifies every grant in the log again.
* **Not exercised.** No external signer, hardware key or CNS identity has produced a grant
  for this code. Only the byte format and the public test vector connect it to one.
