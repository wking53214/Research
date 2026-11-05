"""Lab: the write path. Validates against lifecycle, authority and edge rules, appends to the
store, and applies the same event to the live graph.

The Lab never sets ACCEPTED or ADMITTED through transition(); only govern() can, and only
with a genesis governance issuer and a HUMAN or SYSTEM actor who is not the author. There is
no API anywhere to change the governance issuer set after genesis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .clock import Clock
from .graph import (
    EVENT_EDGE,
    EVENT_RECORD,
    EVENT_TRANSITION,
    Edge,
    EdgeType,
    Graph,
    GraphError,
    PolicyViolation,
    edge_allowed,
)
from .lifecycle import (
    GOVERNED_STAGES,
    ChallengeStatus,
    FindingStage,
    LifecycleError,
    ThreadStatus,
    check_governance_transition,
    check_lab_transition,
    initial_status,
    uses_challenge_statuses,
    uses_finding_stages,
)
from .records import Actor, EvidenceLabel, Kind, Record
from .store import Anchor, Event, EventStore, IntegrityError, Principal, Signer, VerifyResult

EdgeSpec = tuple[EdgeType | str, str]


@dataclass(frozen=True)
class Supersession:
    """What Lab.supersede did. retired is False when the old entity was left as it was:
    a finding at ACCEPTED or ADMITTED (only a governance disposition may withdraw it) or an
    entity already terminal (WITHDRAWN or SUPERSEDED)."""

    replacement: Record
    superseded_id: str
    old_status_before: str
    old_status_after: str
    retired: bool


def verify_store(store: EventStore, require_signed: bool = False, live_graph: Graph | None = None) -> VerifyResult:
    """Chain verification, then a policy replay of every event through Graph.check().

    A store whose chain verifies but which holds an event that breaks the lab's rules (for
    example a governance disposition by an AI actor appended behind the Lab's back) fails
    here with the offending seq in the problems. With live_graph, the replay must also equal
    the graph the caller holds.
    """
    snapshot = store.snapshot()
    result = store.verify(require_signed, snapshot=snapshot)
    if not result.ok:
        return result
    events = snapshot[0]
    replay = Graph()
    compared = live_graph is None
    try:
        for event in events:
            replay.apply(event)
            if live_graph is not None and event.seq == live_graph.applied_seq:
                # Another writer may have appended since the caller synced, so the live graph
                # is compared with the replay of exactly the prefix it has seen.
                compared = True
                if replay != live_graph:
                    result.problems.append(f"live graph differs from a replay of the log up to seq {event.seq}")
    except PolicyViolation as exc:
        result.problems.append(f"policy violation: {exc}")
        result.ok = False
        return result
    result.policy_checked = True
    if not compared:
        result.problems.append(f"live graph is ahead of the log (applied_seq {live_graph.applied_seq})")
    result.ok = not result.problems
    return result


class Lab:
    def __init__(self, store: EventStore, clock: Clock, verify: bool = True) -> None:
        """Wrap a store. By default the chain is verified before any of it is trusted; the
        replay that builds the graph validates every event against the lab's rules and raises
        PolicyViolation on the first event that breaks them, so the store is refused.

        The graph is then attached to the store as its validator: every append, from this Lab
        or from anyone calling store.append() on this store, is caught up, checked and
        inserted under the store's write lock, and applied to the graph only once committed.
        A Lab is bound to the thread that opened it (ThreadAffinityError otherwise)."""
        self.store = store
        self.clock = clock
        if verify:
            result = store.verify()
            if not result.ok:
                raise IntegrityError("store does not verify: " + "; ".join(result.problems))
        self.graph = Graph.rebuild(store.events())
        if self.graph.tenant != store.tenant:
            raise GraphError("graph tenant does not match store tenant")
        store.attach_validator(self.graph)

    @classmethod
    def create(
        cls,
        path: str,
        tenant: str,
        principal: Principal,
        governance_issuers: Sequence[str],
        clock: Clock,
        principals: Sequence[str] | None = None,
        signer: Signer | None = None,
        anchor: Anchor | None = None,
    ) -> "Lab":
        store = EventStore.create(path, tenant, principal, governance_issuers, principals, signer, anchor)
        return cls(store, clock)

    @classmethod
    def open(
        cls,
        path: str,
        tenant: str,
        principal: Principal,
        clock: Clock,
        signer: Signer | None = None,
        anchor: Anchor | None = None,
        verify: bool = True,
    ) -> "Lab":
        """Open an existing store. verify=False skips chain verification; only tools that
        report on a broken store should use it."""
        return cls(EventStore.open(path, tenant, principal, signer, anchor), clock, verify=verify)

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def tenant(self) -> str:
        return self.store.tenant

    # internals

    def _emit(self, event_type: str, payload: Mapping[str, Any]) -> Event:
        """Append through the store, which validates against the real head under its write
        lock and applies the event to this Lab's graph only after commit. Either the event is
        in the log and in the graph, or in neither. On any failure the graph is resynced
        from the log so it never disagrees with it."""
        try:
            return self.store.append(event_type, payload)
        except BaseException:
            self.refresh()
            raise

    def refresh(self) -> int:
        """Catch the in-memory graph up with the log. Returns the number of events applied.

        Another Lab (or process) may have appended since this one last synced; the graph is
        derived state, so it is brought forward by applying the missing events. If the graph
        is somehow ahead of the log it is rebuilt from scratch. A log that fails the policy
        replay raises PolicyViolation here, as it does at open."""
        head = self.store.head().seq
        if head < self.graph.applied_seq:
            self.graph = Graph.rebuild(self.store.events())
            self.store.attach_validator(self.graph)
            return head + 1
        missing = self.store.events(start=self.graph.applied_seq + 1)
        for event in missing:
            self.graph.apply(event)
        return len(missing)

    def _edge_specs(self, from_kind: Kind, from_id: str | None, edges: Sequence[EdgeSpec]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for raw_edge, to_id in edges:
            try:
                edge = EdgeType(raw_edge)
            except ValueError as exc:
                raise GraphError(f"unknown edge type {raw_edge!r}") from exc
            if from_id is not None and to_id == from_id:
                raise GraphError("an entity cannot point at itself")
            target = self.graph.node(to_id)
            if not edge_allowed(from_kind, edge, target.kind):
                raise GraphError(f"{from_kind.value} {edge.value} {target.kind.value} is not an allowed edge")
            out.append({"edge": edge.value, "to": to_id})
        return out

    @staticmethod
    def _status_value(to: Any) -> str:
        return to.value if isinstance(to, (ThreadStatus, FindingStage, ChallengeStatus)) else str(to)

    @staticmethod
    def _check_reason(reason: str) -> str:
        if not isinstance(reason, str) or not reason.strip():
            raise LifecycleError("a non-empty reason is required")
        return reason

    # writes

    def add(
        self,
        kind: Kind,
        body: Mapping[str, Any],
        origin: Actor,
        edges: Sequence[EdgeSpec] = (),
        evidence_label: EvidenceLabel | None = None,
        provenance: Sequence[Mapping[str, Any]] = (),
        entity_id: str | None = None,
    ) -> Record:
        """Add version 1 of a new entity. Its status is fixed by initial_status(kind)."""
        edge_specs = self._edge_specs(kind, None, edges)
        record = Record.create(
            kind=kind,
            tenant=self.tenant,
            body=body,
            origin=origin,
            created_at=self.clock.now(),
            disposition=initial_status(kind),
            provenance=provenance,
            evidence_label=evidence_label,
            entity_id=entity_id,
        )
        if self.graph.has(record.entity_id):
            raise GraphError(f"entity {record.entity_id} already exists")
        self._emit(EVENT_RECORD, {"record": record.to_dict(), "edges": edge_specs})
        return record

    def link(self, from_id: str, edge: EdgeType | str, to_id: str, actor: Actor) -> Edge:
        """Add a typed edge between two existing entities."""
        source = self.graph.node(from_id)
        spec = self._edge_specs(source.kind, from_id, [(edge, to_id)])[0]
        self._emit(
            EVENT_EDGE,
            {"from": from_id, "edge": spec["edge"], "to": to_id, "actor": actor.to_dict(), "created_at": self.clock.now()},
        )
        return self.graph.edges[-1]

    def transition(self, entity_id: str, to: str, actor: Actor, reason: str) -> Record:
        """A lab transition. Governance-only stages are refused here."""
        reason = self._check_reason(reason)
        to_value = self._status_value(to)
        node = self.graph.node(entity_id)
        from_status = node.status
        check_lab_transition(node.kind, from_status, to_value, actor, node.author.id)
        if node.kind is Kind.PLAN and to_value == ThreadStatus.CLOSED.value:
            self.graph.check_plan_closable(entity_id)
        record = node.latest.next_version(
            origin=actor,
            created_at=self.clock.now(),
            disposition=to_value,
            provenance=({"type": "transition", "reason": reason},),
        )
        self._emit(
            EVENT_TRANSITION,
            {
                "record": record.to_dict(),
                "from": from_status,
                "to": to_value,
                "actor": actor.to_dict(),
                "reason": reason,
                "governance": None,
            },
        )
        return record

    def govern(self, entity_id: str, to: str, actor: Actor, issuer_id: str, reason: str) -> Record:
        """Record a governance disposition: on a finding ACCEPTED, ADMITTED, or WITHDRAWN
        from ACCEPTED or ADMITTED; on a challenge UPHELD or DISMISSED.

        The issuer must be in the genesis issuer set, the actor HUMAN or SYSTEM and not the
        author (for a challenge, not the filer). This is the only code path that writes those
        transitions. It records the disposition; it does not authorize any production change,
        and upholding a challenge does not withdraw the challenged finding.
        """
        reason = self._check_reason(reason)
        to_value = self._status_value(to)
        node = self.graph.node(entity_id)
        from_status = node.status
        check_governance_transition(
            node.kind, from_status, to_value, actor, node.author.id, issuer_id, self.graph.governance_issuers
        )
        record = node.latest.next_version(
            origin=actor,
            created_at=self.clock.now(),
            disposition=to_value,
            provenance=({"type": "governance_disposition", "issuer_id": issuer_id, "reason": reason},),
        )
        self._emit(
            EVENT_TRANSITION,
            {
                "record": record.to_dict(),
                "from": from_status,
                "to": to_value,
                "actor": actor.to_dict(),
                "reason": reason,
                "governance": {"issuer_id": issuer_id},
            },
        )
        return record

    def file_challenge(
        self,
        target_id: str,
        reason: str,
        filer: Actor,
        evidence: Sequence[Mapping[str, Any]],
        extra: Mapping[str, Any] | None = None,
    ) -> Record:
        """File a challenge against a finding or hypothesis. Anyone entitled to the tenant may
        file, including an AI actor and the target's own author. Filing never changes the
        target's status or version; the challenge is advice that governance can read. Refused
        when the reason is empty or no evidence reference is given."""
        body = {**(extra or {}), "reason": reason}
        return self.add(Kind.CHALLENGE, body, filer, edges=[(EdgeType.CHALLENGES, target_id)], provenance=evidence)

    def supersede(
        self,
        old_id: str,
        body: Mapping[str, Any],
        origin: Actor,
        reason: str,
        edges: Sequence[EdgeSpec] = (),
        evidence_label: EvidenceLabel | None = None,
        provenance: Sequence[Mapping[str, Any]] = (),
    ) -> Supersession:
        """Add a replacement of the same kind and link it SUPERSEDES old.

        The old entity is retired through a lab transition only where the lab may do that:
        threads move to SUPERSEDED, findings below ACCEPTED move to WITHDRAWN. A finding at
        ACCEPTED or ADMITTED is left exactly as it is; only a governance disposition
        (Lab.govern to WITHDRAWN) may withdraw it. An entity already terminal (WITHDRAWN or
        SUPERSEDED) is also left as it is. The result says which happened. The old entity and
        all its versions stay in the graph.
        """
        old = self.graph.node(old_id)
        before = old.status
        if evidence_label is None:
            evidence_label = old.latest.evidence_label
        replacement = self.add(
            old.kind,
            body,
            origin,
            edges=[*edges, (EdgeType.SUPERSEDES, old_id)],
            evidence_label=evidence_label,
            provenance=provenance,
        )
        if uses_finding_stages(old.kind):
            governed = {stage.value for stage in GOVERNED_STAGES} | {FindingStage.WITHDRAWN.value}
            retire = None if before in governed else FindingStage.WITHDRAWN.value
        elif uses_challenge_statuses(old.kind):
            retire = None  # a challenge is resolved by governance or withdrawn by its filer, never superseded away
        else:
            retire = None if before == ThreadStatus.SUPERSEDED.value else ThreadStatus.SUPERSEDED.value
        if retire is not None:
            self.transition(old_id, retire, origin, reason)
        return Supersession(replacement, old_id, before, self.graph.node(old_id).status, retire is not None)

    # integrity

    def verify(self, require_signed: bool = False) -> VerifyResult:
        """Chain verification plus a policy replay; the live graph, first caught up with the
        log, must equal the replay of the prefix it has seen."""
        try:
            self.refresh()
        except PolicyViolation as exc:
            result = verify_store(self.store, require_signed)
            if result.ok:  # cannot happen: the same replay just failed, but never report ok here
                result.problems.append(f"policy violation: {exc}")
                result.ok = False
            return result
        return verify_store(self.store, require_signed, live_graph=self.graph)
