"""The authenticated governance port: enrolled issuer keys, signed grants, verification.

A governance disposition (a finding to ACCEPTED or ADMITTED, a governed finding to
WITHDRAWN, a challenge to UPHELD or DISMISSED) is authorized by a GovernanceGrant: a small
statement signed with Ed25519 by a key that the genesis event enrolled. The lab holds
public keys only. It can verify that an enrolled key authorized one exact transition of one
exact version; it cannot produce a grant. Signing is external (HSM, KMS, hardware key, a
CNS identity). docs/GOVERNANCE_PORT.md specifies the bytes.

Two modes, fixed at genesis:

* AUTHENTICATED (the default for new stores): a governance disposition needs a grant. The
  actor that submits it can be anyone, an AI included; submission is not authority.
* UNAUTHENTICATED_LEGACY: the increment 1 behaviour, where authority is a claimed actor
  kind plus a public issuer id. It exists so that stores written before this port still
  open, and it must be chosen explicitly for a new store. Its dispositions are reported as
  unauthenticated everywhere.

This module is stateless. The stateful half of grant verification (current version,
legal transition, nonce single use, time) lives in Graph.check_grant so that the write path
and every replay run exactly the same code.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .canonical import CanonicalError, canonical_bytes, normalize, sha256_hex
from .clock import parse_utc
from .crypto import ed25519
from .lifecycle import AuthorityError

MODE_AUTHENTICATED = "AUTHENTICATED"
MODE_LEGACY = "UNAUTHENTICATED_LEGACY"
GOVERNANCE_MODES = (MODE_AUTHENTICATED, MODE_LEGACY)

LEGACY_SCHEMA_VERSION = 1  # plain issuer ids, no mode field: always UNAUTHENTICATED_LEGACY
CURRENT_SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = (LEGACY_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION)

ALG_ED25519 = "ed25519"
ISSUER_KINDS = ("human_body", "system")
REFUSED_ISSUER_KINDS = ("ai", "model")  # named so the refusal can say why; every other kind is refused too
ISSUER_FIELDS = frozenset({"issuer_id", "kind", "alg", "public_key", "key_id"})
KEY_ID_PREFIX = "ed25519:"
KEY_ID_HEX = 16  # a display label only; never an integrity input

GRANT_VERSION = 1
GRANT_DOMAIN = b"research-lab/governance-grant/1\n"
GRANT_FIELDS = (
    "v",
    "tenant",
    "entity_id",
    "entity_version",
    "record_digest",
    "to",
    "issuer_id",
    "nonce",
    "issued_at",
    "expires_at",
    "reason",
)
GRANT_SIGNATURE_FIELD = "signature"
NONCE_MIN_BYTES = 16
NONCE_MAX_BYTES = 32
DEFAULT_GRANT_SKEW_SECONDS = 300  # how far in the lab clock's future issued_at may be
MAX_GRANT_SKEW_SECONDS = 3600
DEFAULT_GRANT_TTL_SECONDS = 86400  # only a default for grant_template; the signer decides

LEGACY_WARNING = (
    "governance mode UNAUTHENTICATED_LEGACY: a governance disposition in this store is "
    "authorized by a claimed actor kind and a public issuer id, not by a signature. Anyone "
    "who can write to the store can record one. Its dispositions are reported as unauthenticated."
)


class GovernanceError(AuthorityError):
    """The governance configuration or a governance grant was refused."""


class GrantRefused(GovernanceError):
    """A governance grant did not verify or does not apply. Nothing was written."""


class UnauthenticatedGovernanceWarning(UserWarning):
    """Raised as a warning when a store is created in UNAUTHENTICATED_LEGACY mode."""


def _is_lower_hex(value: Any, length: int | None = None) -> bool:
    if not isinstance(value, str) or (length is not None and len(value) != length):
        return False
    return bool(value) and all(ch in "0123456789abcdef" for ch in value)


def key_fingerprint(public_key_hex: str) -> str:
    """Short display label for a public key. A label, never a MAC and never an integrity
    input: verification always uses the full public key enrolled under the issuer id."""
    return KEY_ID_PREFIX + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:KEY_ID_HEX]


def make_issuer(issuer_id: str, kind: str, public_key_hex: str) -> dict[str, str]:
    """Build and validate one issuer record for an AUTHENTICATED genesis."""
    if not _is_lower_hex(public_key_hex, 2 * ed25519.PUBLIC_KEY_BYTES):
        raise GovernanceError(f"issuer {issuer_id!r}: public_key must be 64 lowercase hex characters (32 bytes)")
    record = {
        "issuer_id": issuer_id,
        "kind": kind,
        "alg": ALG_ED25519,
        "public_key": public_key_hex,
        "key_id": key_fingerprint(public_key_hex),
    }
    return check_issuer(record)


def check_issuer(record: Any) -> dict[str, str]:
    """Validate one enrolled issuer record. Shared by store creation and by every replay."""
    if not isinstance(record, Mapping):
        raise GovernanceError(
            "an AUTHENTICATED store enrolls issuer records {issuer_id, kind, alg, public_key, key_id}, "
            f"not {record!r}; plain issuer ids need governance_mode {MODE_LEGACY!r}, chosen explicitly"
        )
    if set(record) != ISSUER_FIELDS:
        raise GovernanceError(f"issuer record fields must be exactly {sorted(ISSUER_FIELDS)}, got {sorted(record)}")
    issuer_id, kind = record["issuer_id"], record["kind"]
    if not isinstance(issuer_id, str) or not issuer_id.strip():
        raise GovernanceError("issuer_id must be a non-empty string")
    if kind not in ISSUER_KINDS:
        why = " (an AI or model can never be a governance issuer)" if str(kind).lower() in REFUSED_ISSUER_KINDS else ""
        raise GovernanceError(f"issuer {issuer_id!r}: kind {kind!r} is refused{why}; allowed kinds are {list(ISSUER_KINDS)}")
    if record["alg"] != ALG_ED25519:
        raise GovernanceError(f"issuer {issuer_id!r}: alg {record['alg']!r} is not {ALG_ED25519!r}")
    public_key = record["public_key"]
    if not _is_lower_hex(public_key, 2 * ed25519.PUBLIC_KEY_BYTES):
        raise GovernanceError(f"issuer {issuer_id!r}: public_key must be 64 lowercase hex characters (32 bytes)")
    if not ed25519.is_valid_public_key(bytes.fromhex(public_key)):
        raise GovernanceError(f"issuer {issuer_id!r}: public_key is not a valid Ed25519 public key (off curve or small order)")
    if record["key_id"] != key_fingerprint(public_key):
        raise GovernanceError(f"issuer {issuer_id!r}: key_id is not the fingerprint label of public_key")
    return {name: record[name] for name in sorted(ISSUER_FIELDS)}


@dataclass(frozen=True)
class GenesisGovernance:
    """What a genesis payload says about governance, validated."""

    schema_version: int
    mode: str
    issuer_ids: frozenset[str]
    keys: dict[str, dict[str, str]]  # issuer_id -> issuer record; empty in legacy mode
    skew_seconds: int

    @property
    def authenticated(self) -> bool:
        return self.mode == MODE_AUTHENTICATED


def _plain_ids(issuers: Any) -> frozenset[str]:
    if not isinstance(issuers, list) or not all(isinstance(item, str) and item for item in issuers):
        raise GovernanceError("governance_issuers must be a list of non-empty ids")
    return frozenset(issuers)


def check_skew(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_GRANT_SKEW_SECONDS:
        raise GovernanceError(f"grant_skew_seconds must be an integer from 0 to {MAX_GRANT_SKEW_SECONDS}")
    return value


def read_genesis(payload: Mapping[str, Any]) -> GenesisGovernance:
    """Validate the governance part of a genesis payload and say which mode it fixes.

    schema_version 1 (written before this port) carries plain issuer ids and no mode: it
    is UNAUTHENTICATED_LEGACY and is read exactly as it always was. schema_version 2 names
    its mode; AUTHENTICATED enrolls issuer records with public keys.
    """
    version = payload["schema_version"]
    if version == LEGACY_SCHEMA_VERSION and not isinstance(version, bool):
        if "governance_mode" in payload:
            raise GovernanceError("a schema_version 1 genesis has no governance_mode; it is always legacy")
        return GenesisGovernance(1, MODE_LEGACY, _plain_ids(payload["governance_issuers"]), {}, 0)
    if version != CURRENT_SCHEMA_VERSION or isinstance(version, bool):
        raise GovernanceError(f"schema_version {version!r} is not one of {list(SUPPORTED_SCHEMA_VERSIONS)}")
    mode = payload["governance_mode"]
    if mode == MODE_LEGACY:
        if "grant_skew_seconds" in payload:
            raise GovernanceError("grant_skew_seconds has no meaning in UNAUTHENTICATED_LEGACY mode")
        return GenesisGovernance(2, MODE_LEGACY, _plain_ids(payload["governance_issuers"]), {}, 0)
    if mode != MODE_AUTHENTICATED:
        raise GovernanceError(f"governance_mode {mode!r} is not one of {list(GOVERNANCE_MODES)}")
    issuers = payload["governance_issuers"]
    if not isinstance(issuers, list):
        raise GovernanceError("governance_issuers must be a list of issuer records")
    keys: dict[str, dict[str, str]] = {}
    seen_keys: set[str] = set()
    for item in issuers:
        record = check_issuer(item)
        if record["issuer_id"] in keys:
            raise GovernanceError(f"issuer {record['issuer_id']!r} is enrolled twice")
        if record["public_key"] in seen_keys:
            raise GovernanceError(f"issuer {record['issuer_id']!r}: public key is already enrolled under another issuer")
        seen_keys.add(record["public_key"])
        keys[record["issuer_id"]] = record
    return GenesisGovernance(2, MODE_AUTHENTICATED, frozenset(keys), keys, check_skew(payload["grant_skew_seconds"]))


def build_genesis_governance(
    governance_issuers: Sequence[Any], governance_mode: str, grant_skew_seconds: int
) -> dict[str, Any]:
    """The governance fields of a new (schema_version 2) genesis payload, validated."""
    if governance_mode not in GOVERNANCE_MODES:
        raise GovernanceError(f"governance_mode {governance_mode!r} is not one of {list(GOVERNANCE_MODES)}")
    if governance_issuers is None or isinstance(governance_issuers, (str, bytes, Mapping)):
        raise GovernanceError("governance_issuers must be a sequence (it may be empty)")
    issuers = list(governance_issuers)
    if governance_mode == MODE_LEGACY:
        if not all(isinstance(item, str) and item for item in issuers):
            raise GovernanceError("governance_issuers must be a sequence of non-empty issuer ids (may be empty)")
        fields: dict[str, Any] = {"governance_mode": MODE_LEGACY, "governance_issuers": sorted(set(issuers))}
    else:
        records = sorted((check_issuer(item) for item in issuers), key=lambda record: record["issuer_id"])
        fields = {
            "governance_mode": MODE_AUTHENTICATED,
            "governance_issuers": records,
            "grant_skew_seconds": check_skew(grant_skew_seconds),
        }
    read_genesis({"schema_version": CURRENT_SCHEMA_VERSION, **fields})  # duplicates and the rest
    return fields


# grants


def split_signed_grant(signed: Any) -> tuple[dict[str, Any], str]:
    """Split {grant fields..., "signature": hex} into (fields, signature hex), strictly."""
    if not isinstance(signed, Mapping):
        raise GrantRefused("a grant is a JSON object")
    signature = signed.get(GRANT_SIGNATURE_FIELD)
    if signature is None:
        raise GrantRefused("the grant has no signature")
    fields = {name: value for name, value in signed.items() if name != GRANT_SIGNATURE_FIELD}
    return check_grant_fields(fields), check_signature_hex(signature)


def check_signature_hex(signature: Any) -> str:
    if not _is_lower_hex(signature, 2 * ed25519.SIGNATURE_BYTES):
        raise GrantRefused("the grant signature must be 128 lowercase hex characters (64 bytes)")
    return signature


def check_grant_fields(grant: Any) -> dict[str, Any]:
    """Validate the shape of the signed fields. No signature and no state are checked here."""
    if not isinstance(grant, Mapping):
        raise GrantRefused("a grant is a JSON object")
    if set(grant) != set(GRANT_FIELDS):
        missing = sorted(set(GRANT_FIELDS) - set(grant))
        extra = sorted(set(grant) - set(GRANT_FIELDS))
        raise GrantRefused(f"grant fields must be exactly {list(GRANT_FIELDS)} (missing {missing}, unexpected {extra})")
    try:
        clean = normalize(dict(grant))
    except CanonicalError as exc:
        raise GrantRefused(f"grant is not canonical JSON: {exc}") from exc
    if clean != dict(grant):
        raise GrantRefused("grant strings must already be in Unicode NFC")
    if clean["v"] != GRANT_VERSION or isinstance(clean["v"], bool):
        raise GrantRefused(f"grant version {clean['v']!r} is not {GRANT_VERSION}")
    for name in ("tenant", "entity_id", "to", "issuer_id", "reason"):
        if not isinstance(clean[name], str) or not clean[name].strip():
            raise GrantRefused(f"grant {name} must be a non-empty string")
    version = clean["entity_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise GrantRefused("grant entity_version must be an integer >= 1")
    if not _is_lower_hex(clean["record_digest"], 64):
        raise GrantRefused("grant record_digest must be a full SHA-256 hex digest (64 lowercase hex characters)")
    nonce = clean["nonce"]
    if not _is_lower_hex(nonce) or len(nonce) % 2 or not NONCE_MIN_BYTES <= len(nonce) // 2 <= NONCE_MAX_BYTES:
        raise GrantRefused(f"grant nonce must be {NONCE_MIN_BYTES} to {NONCE_MAX_BYTES} bytes of lowercase hex")
    try:
        issued, expires = parse_utc(clean["issued_at"]), parse_utc(clean["expires_at"])
    except ValueError as exc:
        raise GrantRefused(f"grant issued_at and expires_at must be YYYY-MM-DDTHH:MM:SSZ: {exc}") from exc
    if expires <= issued:
        raise GrantRefused("grant expires_at must be after issued_at")
    return clean


def grant_signing_bytes(grant: Mapping[str, Any]) -> bytes:
    """The exact bytes an external signer signs: the domain line, then the canonical JSON of
    the eleven grant fields (sorted keys, compact separators, ASCII, no signature field)."""
    return GRANT_DOMAIN + canonical_bytes(check_grant_fields(grant))


def grant_digest(grant: Mapping[str, Any]) -> str:
    """Full SHA-256 of the signing bytes. Recorded in the disposed version's provenance."""
    return sha256_hex(grant_signing_bytes(grant))


def grant_provenance(grant: Mapping[str, Any]) -> dict[str, Any]:
    """The single provenance item a grant-authorized version carries."""
    return {
        "type": "governance_disposition",
        "issuer_id": grant["issuer_id"],
        "reason": grant["reason"],
        "grant_digest": grant_digest(grant),
    }


def verify_grant_signature(grant: Mapping[str, Any], signature: str, keys: Mapping[str, Mapping[str, str]]) -> dict[str, str]:
    """Check that the grant's issuer is enrolled and that its key signed these exact bytes.
    Returns the issuer record. Stateless: needs nothing but the genesis issuer records."""
    fields = check_grant_fields(grant)
    check_signature_hex(signature)
    issuer = keys.get(fields["issuer_id"])
    if issuer is None:
        raise GrantRefused(f"issuer {fields['issuer_id']!r} is not enrolled in the genesis governance issuer set")
    if issuer.get("alg") != ALG_ED25519:
        raise GrantRefused(f"issuer {fields['issuer_id']!r} has no ed25519 key")
    ok = ed25519.verify(bytes.fromhex(issuer["public_key"]), bytes.fromhex(signature), grant_signing_bytes(fields))
    if not ok:
        raise GrantRefused(
            f"grant signature does not verify under the enrolled key of issuer {fields['issuer_id']!r} ({issuer['key_id']})"
        )
    return dict(issuer)


def expectation_problems(report: Mapping[str, Any] | None, expected_genesis_hash: str | None, require_authenticated: bool) -> list[str]:
    """What a verifier that pins a genesis, or insists on authenticated governance, objects to.

    A file that verifies proves its own consistency, not that it is the store you meant:
    someone able to replace the whole file can write a different genesis (their own key, or
    legacy mode) and recompute every hash. Pinning the genesis hash obtained out of band, and
    requiring AUTHENTICATED mode, closes that for the verifier who does it."""
    problems: list[str] = []
    if expected_genesis_hash is None and not require_authenticated:
        return problems
    if report is None:
        return ["governance expectations could not be checked: the policy replay did not complete"]
    if expected_genesis_hash is not None and report.get("genesis_hash") != expected_genesis_hash:
        problems.append(f"genesis hash {report.get('genesis_hash')} is not the expected {expected_genesis_hash}")
    if require_authenticated:
        if report.get("mode") != MODE_AUTHENTICATED:
            problems.append(f"governance mode is {report.get('mode')}, but {MODE_AUTHENTICATED} is required")
        if report.get("unauthenticated"):
            problems.append(f"{report.get('unauthenticated')} governance disposition(s) are unauthenticated")
    return problems
