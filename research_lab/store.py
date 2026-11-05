"""Durable append-only event log in SQLite, hash chained with full SHA-256.

The store is the only writer. There is no update or delete API. SQLite triggers refuse
UPDATE and DELETE on the events table as a second line of defence; they are not a security
boundary, because anyone who can write the file can drop them. verify() is the boundary:
it recomputes every hash from the stored rows and detects an edited payload, a deleted
event (sequence gap), a reordered event, a second genesis and a wrong tenant.

Tenant scoping: a store belongs to exactly one tenant, named in its genesis event. Opening
it for another tenant is refused. Opening it by a Principal that does not claim that tenant,
or whose id is not in the genesis entitlement set, is refused (default deny).

Identities are claims in increment 1. A Principal or Actor id is not authenticated by this
module; authentication belongs to the caller's environment or a later increment.

Governance issuers are fixed in the genesis event. No API changes them afterwards; a second
GENESIS event is refused by append().
"""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Protocol, Sequence

from .canonical import CanonicalError, canonical_json, digest, normalize

SCHEMA_VERSION = 1
GENESIS = "GENESIS"
GENESIS_PREV_HASH = "0" * 64
MIN_KEY_BYTES = 32


class StoreError(Exception):
    """Base class for store failures."""


class AccessRefused(StoreError):
    """The principal or tenant is not entitled to this store."""


class AppendRefused(StoreError):
    """The event may not be appended."""


class IntegrityError(StoreError):
    """The chain did not verify."""


class ConcurrentWriteConflict(StoreError):
    """Another writer changed the store since this caller last synced, and the candidate event
    is not valid on the real state. Nothing was written. The caller's validator has been
    caught up to the real head, so it may rebuild the event and try again."""


class ThreadAffinityError(StoreError):
    """An EventStore (and the Lab around it) is bound to the thread that opened it."""


class Validator(Protocol):
    """State that must approve every event before the store writes it.

    applied_seq is the seq of the last event the validator has seen. Under the write lock the
    store first applies every event the validator has not seen (catch-up), then calls check()
    on the candidate, and only then inserts it. Graph in graph.py implements this.
    """

    applied_seq: int

    def apply(self, event: "Event") -> None: ...

    def check(self, event: "Event") -> None: ...


@dataclass(frozen=True)
class Principal:
    """A caller identity and the tenants it claims. Claims are not authenticated in increment 1."""

    id: str
    tenants: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise StoreError("principal id must be a non-empty string")
        if not isinstance(self.tenants, frozenset):
            object.__setattr__(self, "tenants", frozenset(self.tenants))


class Signer(Protocol):
    key_id: str

    def sign(self, data: bytes) -> str: ...

    def verify(self, data: bytes, signature: str) -> bool: ...


class Anchor(Protocol):
    """Records (tenant, seq, head hash) somewhere outside the store."""

    def anchor(self, tenant: str, seq: int, event_hash: str) -> None: ...

    def anchored(self, tenant: str) -> Sequence[tuple[int, str]]: ...


class HmacSigner:
    """Reference signer: HMAC-SHA256 over the event hash.

    Requires an explicit key of at least MIN_KEY_BYTES bytes and a key id. The key id is a
    label only: it is stored beside the signature so a verifier can pick the right key. It
    is never derived from the key and never a secret. There is no default key.
    """

    def __init__(self, key: bytes, key_id: str) -> None:
        if key is None or not isinstance(key, (bytes, bytearray)):
            raise StoreError("HmacSigner requires an explicit key (bytes); refusing to run without one")
        if len(key) < MIN_KEY_BYTES:
            raise StoreError(f"HmacSigner key must be at least {MIN_KEY_BYTES} bytes, got {len(key)}")
        if not isinstance(key_id, str) or not key_id.strip():
            raise StoreError("HmacSigner requires a non-empty key id label")
        self._key = bytes(key)
        self.key_id = key_id

    def sign(self, data: bytes) -> str:
        return hmac.new(self._key, data, "sha256").hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        if not isinstance(signature, str):
            return False
        return hmac.compare_digest(self.sign(data), signature)


class MemoryAnchor:
    """Reference anchor kept in process memory. Useful for tests; not durable."""

    def __init__(self) -> None:
        self._heads: dict[str, list[tuple[int, str]]] = {}

    def anchor(self, tenant: str, seq: int, event_hash: str) -> None:
        self._heads.setdefault(tenant, []).append((seq, event_hash))

    def anchored(self, tenant: str) -> Sequence[tuple[int, str]]:
        return tuple(self._heads.get(tenant, ()))


@dataclass(frozen=True)
class Event:
    seq: int
    tenant: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str
    key_id: str | None = None
    signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "tenant": self.tenant,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "key_id": self.key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        try:
            return cls(
                seq=int(data["seq"]),
                tenant=str(data["tenant"]),
                event_type=str(data["event_type"]),
                payload=dict(data["payload"]),
                prev_hash=str(data["prev_hash"]),
                hash=str(data["hash"]),
                key_id=data.get("key_id"),
                signature=data.get("signature"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreError(f"bad event: {exc}") from exc


def event_hash(seq: int, tenant: str, event_type: str, payload: Mapping[str, Any], prev_hash: str) -> str:
    """Full SHA-256 over the canonical JSON of the event header and payload."""
    return digest(
        {
            "seq": seq,
            "tenant": tenant,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
        }
    )


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    events_checked: int = 0
    signatures_checked: int = 0
    unverified_signatures: int = 0
    head_hash: str | None = None
    policy_checked: bool = False  # True once a replay validated every event against the lab's rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "problems": list(self.problems),
            "events_checked": self.events_checked,
            "signatures_checked": self.signatures_checked,
            "unverified_signatures": self.unverified_signatures,
            "head_hash": self.head_hash,
            "policy_checked": self.policy_checked,
        }


def verify_events(
    events: Sequence[Event],
    tenant: str | None,
    signer: Signer | None = None,
    require_signed: bool = False,
    anchor: Anchor | None = None,
) -> VerifyResult:
    """Check a sequence of events as a chain. Shared by the store and by bundle verification."""
    result = VerifyResult(ok=True)
    if not events:
        result.ok = False
        result.problems.append("no events: genesis missing")
        return result

    genesis = events[0]
    expected_tenant = tenant
    if genesis.event_type != GENESIS:
        result.problems.append(f"seq {genesis.seq}: first event is {genesis.event_type}, not {GENESIS}")
    else:
        payload = genesis.payload
        if payload.get("schema_version") != SCHEMA_VERSION:
            result.problems.append(f"genesis schema_version {payload.get('schema_version')!r} is not {SCHEMA_VERSION}")
        if not isinstance(payload.get("governance_issuers"), list):
            result.problems.append("genesis governance_issuers missing")
        if not isinstance(payload.get("principals"), list) or not payload.get("principals"):
            result.problems.append("genesis principals missing or empty")
        genesis_tenant = payload.get("tenant")
        if expected_tenant is None:
            expected_tenant = genesis_tenant
        if genesis_tenant != expected_tenant:
            result.problems.append(f"genesis tenant {genesis_tenant!r} is not {expected_tenant!r}")
        if genesis.tenant != genesis_tenant:
            result.problems.append("genesis header tenant differs from genesis payload tenant")
    if genesis.prev_hash != GENESIS_PREV_HASH:
        result.problems.append("genesis prev_hash is not the zero hash")

    prev_hash = GENESIS_PREV_HASH
    for position, ev in enumerate(events):
        if ev.seq != position:
            result.problems.append(f"position {position}: seq {ev.seq} (gap, deletion or reorder)")
        if position > 0 and ev.event_type == GENESIS:
            result.problems.append(f"seq {ev.seq}: second genesis")
        if expected_tenant is not None and ev.tenant != expected_tenant:
            result.problems.append(f"seq {ev.seq}: wrong tenant {ev.tenant!r}")
        if ev.prev_hash != prev_hash:
            result.problems.append(f"seq {ev.seq}: prev_hash does not match previous event")
        try:
            recomputed = event_hash(ev.seq, ev.tenant, ev.event_type, ev.payload, ev.prev_hash)
        except CanonicalError as exc:
            recomputed = ""
            result.problems.append(f"seq {ev.seq}: payload not canonical: {exc}")
        if recomputed != ev.hash:
            result.problems.append(f"seq {ev.seq}: hash mismatch (payload or header edited)")
        if ev.signature is not None:
            if signer is not None and ev.key_id == signer.key_id:
                if signer.verify(ev.hash.encode("ascii"), ev.signature):
                    result.signatures_checked += 1
                else:
                    result.problems.append(f"seq {ev.seq}: signature invalid for key id {ev.key_id!r}")
            else:
                result.unverified_signatures += 1
                if require_signed:
                    result.problems.append(f"seq {ev.seq}: signature present but no matching signer to verify it")
        elif require_signed:
            result.problems.append(f"seq {ev.seq}: unsigned event where signatures are required")
        prev_hash = ev.hash

    if anchor is not None and expected_tenant is not None:
        by_seq = {ev.seq: ev.hash for ev in events}
        for seq, anchored_hash in anchor.anchored(expected_tenant):
            if by_seq.get(seq) != anchored_hash:
                result.problems.append(f"anchor for seq {seq} does not match the stored event")

    result.events_checked = len(events)
    result.head_hash = events[-1].hash
    result.ok = not result.problems
    return result


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    key_id TEXT,
    signature TEXT
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
"""


class EventStore:
    """Append-only, hash-chained, tenant-scoped event log. Use create() or open()."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        principal: Principal,
        signer: Signer | None,
        anchor: Anchor | None,
        validator: Validator | None = None,
    ) -> None:
        self._conn = connection
        self.tenant = tenant
        self.principal = principal
        self._signer = signer
        self._anchor = anchor
        self._validator = validator
        # False until the validator has been caught up once by this store. A default
        # validator starts empty, so its first catch-up is an initial load, not evidence of
        # another writer; only a later catch-up means the caller's view was stale.
        self._validator_synced = False
        self._genesis: dict[str, Any] | None = None
        self._thread = threading.get_ident()

    def attach_validator(self, validator: Validator, synced: bool = True) -> None:
        """Make every later append pass through validator (catch-up, check, then insert).

        synced says whether the validator already reflects the log (a Lab's rebuilt graph
        does); if it does, any catch-up before an append means another writer got in."""
        self._validator = validator
        self._validator_synced = synced

    @staticmethod
    def _default_validator() -> Validator:
        # Imported here because graph.py imports this module. The default validator is an
        # empty Graph; the store catches it up from the log inside its first write transaction.
        from .graph import Graph

        return Graph()

    @property
    def validator(self) -> Validator | None:
        return self._validator

    def _check_thread(self) -> None:
        if threading.get_ident() != self._thread:
            raise ThreadAffinityError(
                "this EventStore is bound to the thread that opened it; open one Lab per thread"
            )

    # construction

    @staticmethod
    def _connect(path: str) -> sqlite3.Connection:
        conn = sqlite3.connect(path, isolation_level=None)
        if path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return conn

    @staticmethod
    def _check_claim(tenant: str, principal: Principal) -> None:
        if not isinstance(tenant, str) or not tenant.strip():
            raise StoreError("tenant must be a non-empty string")
        if not isinstance(principal, Principal):
            raise AccessRefused("a Principal is required to open a store")
        if tenant not in principal.tenants:
            raise AccessRefused(f"principal {principal.id!r} does not claim tenant {tenant!r}")

    @classmethod
    def create(
        cls,
        path: str,
        tenant: str,
        principal: Principal,
        governance_issuers: Sequence[str],
        principals: Sequence[str] | None = None,
        signer: Signer | None = None,
        anchor: Anchor | None = None,
        validator: Validator | None = None,
        unsafe_unvalidated: bool = False,
    ) -> "EventStore":
        """Create a new store and write its genesis event. Refuses a path that already has events.

        The genesis is written before any validator is consulted. Afterwards the standard
        Graph-based policy validator is attached (or the one given), so every later append is
        validated. unsafe_unvalidated=True attaches none: it exists only for tests that
        deliberately write a corrupted log to exercise the replay backstop."""
        cls._check_claim(tenant, principal)
        if governance_issuers is None or not all(isinstance(item, str) and item for item in governance_issuers):
            raise StoreError("governance_issuers must be a sequence of non-empty issuer ids (may be empty)")
        entitled = list(principals) if principals is not None else [principal.id]
        if principal.id not in entitled:
            raise AccessRefused("the creating principal must be in the entitled principal set")
        if path != ":memory:" and os.path.exists(path) and os.path.getsize(path) > 0:
            existing = cls._connect(path)
            try:
                count = existing.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            finally:
                existing.close()
            if count:
                raise StoreError(f"store at {path} already has events; refusing to re-create")
        conn = cls._connect(path)
        store = cls(conn, tenant, principal, signer, anchor)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "tenant": tenant,
            "governance_issuers": sorted(set(governance_issuers)),
            "principals": sorted(set(entitled)),
        }
        store._append(GENESIS, payload, allow_genesis=True)
        store._genesis = payload
        if not unsafe_unvalidated:
            store._validator = validator if validator is not None else cls._default_validator()
        return store

    @classmethod
    def open(
        cls,
        path: str,
        tenant: str,
        principal: Principal,
        signer: Signer | None = None,
        anchor: Anchor | None = None,
        validator: Validator | None = None,
        unsafe_unvalidated: bool = False,
    ) -> "EventStore":
        """Open an existing store for one tenant. Default deny on tenant or principal mismatch.

        The standard Graph-based policy validator is attached by default (or the one given),
        so a bare store refuses out-of-policy appends exactly as a Lab does; the store catches
        the validator up from the log inside each write transaction. unsafe_unvalidated=True
        attaches none and exists only for tests that deliberately corrupt a log."""
        cls._check_claim(tenant, principal)
        if path != ":memory:" and not os.path.exists(path):
            raise StoreError(f"no store at {path}")
        conn = cls._connect(path)
        row = conn.execute("SELECT event_type, payload FROM events WHERE seq = 0").fetchone()
        if row is None or row[0] != GENESIS:
            conn.close()
            raise StoreError("store has no genesis event")
        genesis = json.loads(row[1])
        if genesis.get("tenant") != tenant:
            conn.close()
            raise AccessRefused(f"store belongs to tenant {genesis.get('tenant')!r}, not {tenant!r}")
        if principal.id not in genesis.get("principals", []):
            conn.close()
            raise AccessRefused(f"principal {principal.id!r} is not entitled to tenant {tenant!r}")
        if validator is None and not unsafe_unvalidated:
            validator = cls._default_validator()
        store = cls(conn, tenant, principal, signer, anchor, validator)
        store._genesis = genesis
        return store

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # reading

    def genesis(self) -> dict[str, Any]:
        if self._genesis is None:
            raise StoreError("store not initialised")
        return dict(self._genesis)

    @property
    def governance_issuers(self) -> frozenset[str]:
        return frozenset(self.genesis()["governance_issuers"])

    def count(self) -> int:
        self._check_thread()
        return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def _row_to_event(self, row: tuple[Any, ...]) -> Event:
        return Event(
            seq=row[0],
            tenant=row[1],
            event_type=row[2],
            payload=json.loads(row[3]),
            prev_hash=row[4],
            hash=row[5],
            key_id=row[6],
            signature=row[7],
        )

    def events(self, start: int = 0) -> list[Event]:
        self._check_thread()
        rows = self._conn.execute(
            "SELECT seq, tenant, event_type, payload, prev_hash, hash, key_id, signature "
            "FROM events WHERE seq >= ? ORDER BY seq",
            (start,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def iter_events(self) -> Iterator[Event]:
        yield from self.events()

    def snapshot(self) -> tuple[list[Event], int]:
        """All events and the row count read in one read transaction, so a concurrent writer
        cannot make the two disagree."""
        self._check_thread()
        self._conn.execute("BEGIN")
        try:
            events = self.events()
            total = self.count()
        finally:
            self._conn.execute("COMMIT")
        return events, total

    def head(self) -> Event:
        self._check_thread()
        row = self._conn.execute(
            "SELECT seq, tenant, event_type, payload, prev_hash, hash, key_id, signature "
            "FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise StoreError("store is empty")
        return self._row_to_event(row)

    # writing

    def append(self, event_type: str, payload: Mapping[str, Any]) -> Event:
        """Append one event atomically. GENESIS is refused here: issuers are fixed at genesis.

        With a validator attached, the whole of catch-up, check and insert happens under one
        write lock (BEGIN IMMEDIATE), against the real head, so a stale caller cannot write an
        event that is invalid on the real state. Nothing is written when the check fails.
        """
        return self._append(event_type, payload, allow_genesis=False)

    def _catch_up(self, validator: Validator) -> int:
        """Apply, inside the write transaction, every event the validator has not seen."""
        rows = self._conn.execute(
            "SELECT seq, tenant, event_type, payload, prev_hash, hash, key_id, signature "
            "FROM events WHERE seq > ? ORDER BY seq",
            (validator.applied_seq,),
        ).fetchall()
        for row in rows:
            validator.apply(self._row_to_event(row))
        return len(rows)

    def _append(self, event_type: str, payload: Mapping[str, Any], allow_genesis: bool) -> Event:
        self._check_thread()
        if not isinstance(event_type, str) or not event_type:
            raise AppendRefused("event_type must be a non-empty string")
        if event_type == GENESIS and not allow_genesis:
            raise AppendRefused("a second GENESIS is refused: governance issuers are fixed at genesis")
        try:
            clean = normalize(dict(payload))
        except CanonicalError as exc:
            raise AppendRefused(f"payload is not canonical JSON: {exc}") from exc
        conn = self._conn
        validator = self._validator
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None:
                if not allow_genesis:
                    raise AppendRefused("store has no genesis")
                seq, prev_hash = 0, GENESIS_PREV_HASH
            else:
                if allow_genesis:
                    raise AppendRefused("genesis already written")
                seq, prev_hash = row[0] + 1, row[1]
            new_hash = event_hash(seq, self.tenant, event_type, clean, prev_hash)
            key_id = signature = None
            if self._signer is not None:
                key_id = self._signer.key_id
                signature = self._signer.sign(new_hash.encode("ascii"))
            event = Event(seq, self.tenant, event_type, clean, prev_hash, new_hash, key_id, signature)
            if validator is not None:
                was_synced = self._validator_synced
                caught_up = self._catch_up(validator)
                self._validator_synced = True
                try:
                    validator.check(event)
                except Exception as exc:
                    if caught_up and was_synced:
                        raise ConcurrentWriteConflict(
                            f"another writer appended {caught_up} event(s) since this caller last synced "
                            f"and the candidate is not valid on the real state: {exc}"
                        ) from exc
                    raise
            conn.execute(
                "INSERT INTO events (seq, tenant, event_type, payload, prev_hash, hash, key_id, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (seq, self.tenant, event_type, canonical_json(clean), prev_hash, new_hash, key_id, signature),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        if validator is not None:
            # The check passed on exactly this state, so apply cannot refuse; it only mutates.
            validator.apply(event)
        if self._anchor is not None:
            self._anchor.anchor(self.tenant, seq, new_hash)
        return event

    # integrity

    def verify(self, require_signed: bool = False, snapshot: tuple[list[Event], int] | None = None) -> VerifyResult:
        """Recompute the whole chain from the stored rows (or from a snapshot already taken)."""
        events, total = self.snapshot() if snapshot is None else snapshot
        result = verify_events(events, self.tenant, self._signer, require_signed, self._anchor)
        if total != len(events):
            result.problems.append(f"row count {total} differs from events read {len(events)}")
            result.ok = False
        return result
