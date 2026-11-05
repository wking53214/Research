"""Record envelope, actors, kinds and evidence labels.

A Record is an immutable version of an entity. Every version carries the stable entity_id,
its version number, the actor that produced that version (origin), a timestamp from an
injected clock, references to parent versions, provenance references, the disposition
(status) at that version, and a full SHA-256 digest over the canonical JSON of everything
except the digest itself.

The entity_id is a label. It is kind plus a 16-hex prefix of entity_digest, which is the
full SHA-256 of the version-1 seed content. The full entity_digest is stored on every
version and checked by verify_digest(), so no truncated hash provides integrity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .canonical import CanonicalError, digest, normalize
from .clock import parse_utc


class RecordError(ValueError):
    """A record could not be built or decoded."""


class ActorKind(str, Enum):
    HUMAN = "HUMAN"
    AI = "AI"
    SYSTEM = "SYSTEM"
    EXTERNAL = "EXTERNAL"


class Kind(str, Enum):
    OBJECTIVE = "objective"
    QUESTION = "question"
    HYPOTHESIS = "hypothesis"
    SOURCE = "source"
    EVIDENCE = "evidence"
    EXPERIMENT = "experiment"
    FINDING = "finding"
    CONTRADICTION = "contradiction"
    DECISION = "decision"
    CAPABILITY_PROPOSAL = "capability_proposal"
    PLAN = "plan"
    TASK = "task"
    REVIEW = "review"
    CHALLENGE = "challenge"


class EvidenceLabel(str, Enum):
    EXECUTED = "EXECUTED"
    INSPECTED = "INSPECTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


LABELLED_KINDS = frozenset({Kind.EVIDENCE, Kind.FINDING})
ENTITY_ID_PREFIX_HEX = 16


@dataclass(frozen=True)
class Actor:
    """Who produced a record version. In increment 1 an actor id is a claim, not authenticated."""

    id: str
    kind: ActorKind
    provider: str | None = None
    model_family: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise RecordError("actor id must be a non-empty string")
        if not isinstance(self.kind, ActorKind):
            raise RecordError(f"actor kind must be an ActorKind, got {self.kind!r}")
        for name in ("provider", "model_family"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise RecordError(f"actor {name} must be None or a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "kind": self.kind.value}
        if self.provider is not None:
            out["provider"] = self.provider
        if self.model_family is not None:
            out["model_family"] = self.model_family
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Actor":
        try:
            return cls(
                id=data["id"],
                kind=ActorKind(data["kind"]),
                provider=data.get("provider"),
                model_family=data.get("model_family"),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"bad actor: {exc}") from exc


@dataclass(frozen=True)
class Ref:
    """Reference to one version of an entity."""

    entity_id: str
    version: int

    def __post_init__(self) -> None:
        if not isinstance(self.entity_id, str) or not self.entity_id:
            raise RecordError("ref entity_id must be a non-empty string")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise RecordError("ref version must be an integer >= 1")

    def to_dict(self) -> dict[str, Any]:
        return {"entity_id": self.entity_id, "version": self.version}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Ref":
        try:
            return cls(entity_id=data["entity_id"], version=data["version"])
        except (KeyError, TypeError) as exc:
            raise RecordError(f"bad ref: {exc}") from exc


def _check_body(body: Any) -> dict[str, Any]:
    if not isinstance(body, Mapping):
        raise RecordError("body must be a mapping")
    try:
        return normalize(dict(body))
    except CanonicalError as exc:
        raise RecordError(f"body is not canonical JSON: {exc}") from exc


def _check_provenance(provenance: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    out = []
    for item in provenance:
        if not isinstance(item, Mapping):
            raise RecordError("each provenance item must be a mapping")
        try:
            out.append(normalize(dict(item)))
        except CanonicalError as exc:
            raise RecordError(f"provenance is not canonical JSON: {exc}") from exc
    return tuple(out)


@dataclass(frozen=True)
class Record:
    entity_id: str
    entity_digest: str
    version: int
    kind: Kind
    tenant: str
    body: dict[str, Any]
    origin: Actor
    created_at: str
    disposition: str
    parents: tuple[Ref, ...] = ()
    provenance: tuple[dict[str, Any], ...] = ()
    evidence_label: EvidenceLabel | None = None
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not isinstance(self.kind, Kind):
            raise RecordError(f"kind must be a Kind, got {self.kind!r}")
        if not isinstance(self.tenant, str) or not self.tenant.strip():
            raise RecordError("tenant must be a non-empty string")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise RecordError("version must be an integer >= 1")
        if not isinstance(self.disposition, str) or not self.disposition:
            raise RecordError("disposition must be a non-empty string")
        if not isinstance(self.origin, Actor):
            raise RecordError("origin must be an Actor")
        if self.evidence_label is not None and not isinstance(self.evidence_label, EvidenceLabel):
            raise RecordError("evidence_label must be an EvidenceLabel or None")
        if self.kind in LABELLED_KINDS and self.evidence_label is None:
            raise RecordError(f"{self.kind.value} records require an evidence_label")
        try:
            parse_utc(self.created_at)
        except ValueError as exc:
            raise RecordError(f"created_at: {exc}") from exc
        if len(self.entity_digest) != 64:
            raise RecordError("entity_digest must be a full SHA-256 hex digest")
        if not isinstance(self.entity_id, str) or not self.entity_id:
            raise RecordError("entity_id must be a non-empty string")
        if not self.digest:
            object.__setattr__(self, "digest", digest(self.content()))
        elif len(self.digest) != 64:
            raise RecordError("digest must be a full SHA-256 hex digest")

    def content(self) -> dict[str, Any]:
        """Everything that the digest covers."""
        out: dict[str, Any] = {
            "entity_id": self.entity_id,
            "entity_digest": self.entity_digest,
            "version": self.version,
            "kind": self.kind.value,
            "tenant": self.tenant,
            "body": self.body,
            "origin": self.origin.to_dict(),
            "created_at": self.created_at,
            "disposition": self.disposition,
            "parents": [ref.to_dict() for ref in self.parents],
            "provenance": list(self.provenance),
        }
        if self.evidence_label is not None:
            out["evidence_label"] = self.evidence_label.value
        return out

    def to_dict(self) -> dict[str, Any]:
        out = self.content()
        out["digest"] = self.digest
        return out

    def verify_digest(self) -> bool:
        """True when the stored digest matches the content and the id prefix matches entity_digest."""
        if digest(self.content()) != self.digest:
            return False
        derived = f"{self.kind.value}_{self.entity_digest[:ENTITY_ID_PREFIX_HEX]}"
        if self.entity_id.startswith(f"{self.kind.value}_") and self.entity_id != derived:
            # A derived-form id must match the full entity_digest it claims to abbreviate.
            return False
        return True

    @staticmethod
    def seed(
        kind: Kind,
        tenant: str,
        body: Mapping[str, Any],
        origin: Actor,
        created_at: str,
        parents: Sequence[Ref],
        provenance: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return {
            "kind": kind.value,
            "tenant": tenant,
            "body": dict(body),
            "origin": origin.to_dict(),
            "created_at": created_at,
            "parents": [ref.to_dict() for ref in parents],
            "provenance": list(provenance),
        }

    @classmethod
    def create(
        cls,
        kind: Kind,
        tenant: str,
        body: Mapping[str, Any],
        origin: Actor,
        created_at: str,
        disposition: str,
        parents: Sequence[Ref] = (),
        provenance: Sequence[Mapping[str, Any]] = (),
        evidence_label: EvidenceLabel | None = None,
        entity_id: str | None = None,
    ) -> "Record":
        """Build version 1 of a new entity."""
        if not isinstance(kind, Kind):
            raise RecordError(f"kind must be a Kind, got {kind!r}")
        if not isinstance(origin, Actor):
            raise RecordError("origin must be an Actor")
        clean_body = _check_body(body)
        clean_prov = _check_provenance(provenance)
        seed = cls.seed(kind, tenant, clean_body, origin, created_at, tuple(parents), clean_prov)
        entity_digest = digest(seed)
        if entity_id is None:
            entity_id = f"{kind.value}_{entity_digest[:ENTITY_ID_PREFIX_HEX]}"
        elif entity_id.startswith(f"{kind.value}_"):
            raise RecordError("a caller-supplied entity_id may not imitate the derived form kind_prefix")
        return cls(
            entity_id=entity_id,
            entity_digest=entity_digest,
            version=1,
            kind=kind,
            tenant=tenant,
            body=clean_body,
            origin=origin,
            created_at=created_at,
            disposition=disposition,
            parents=tuple(parents),
            provenance=clean_prov,
            evidence_label=evidence_label,
        )

    def next_version(
        self,
        origin: Actor,
        created_at: str,
        disposition: str,
        body: Mapping[str, Any] | None = None,
        provenance: Sequence[Mapping[str, Any]] = (),
    ) -> "Record":
        """Build the next version of this entity. The previous version becomes a parent."""
        clean_body = self.body if body is None else _check_body(body)
        return Record(
            entity_id=self.entity_id,
            entity_digest=self.entity_digest,
            version=self.version + 1,
            kind=self.kind,
            tenant=self.tenant,
            body=clean_body,
            origin=origin,
            created_at=created_at,
            disposition=disposition,
            parents=(Ref(self.entity_id, self.version),),
            provenance=_check_provenance(provenance),
            evidence_label=self.evidence_label,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Record":
        try:
            label = data.get("evidence_label")
            return cls(
                entity_id=data["entity_id"],
                entity_digest=data["entity_digest"],
                version=data["version"],
                kind=Kind(data["kind"]),
                tenant=data["tenant"],
                body=dict(data["body"]),
                origin=Actor.from_dict(data["origin"]),
                created_at=data["created_at"],
                disposition=data["disposition"],
                parents=tuple(Ref.from_dict(ref) for ref in data.get("parents", [])),
                provenance=tuple(dict(item) for item in data.get("provenance", [])),
                evidence_label=EvidenceLabel(label) if label is not None else None,
                digest=data["digest"],
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"bad record: {exc}") from exc
