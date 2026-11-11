"""Materialized research graph: nodes and typed edges rebuilt from the event log.

The graph is derived state. Graph.rebuild(store) replays every event; Lab applies each event
it appends to its live graph through the same apply() method, and tests prove that the two
are equal. Nothing is ever removed from the graph: rejected, superseded, withdrawn and failed
entities stay as nodes with their full version history.

Edge direction: from the newer or dependent entity to the one it refers to. A question
DECOMPOSES an objective, so the edge runs question -> objective and children(objective)
returns the question.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .clock import parse_utc
from .governance import (
    CURRENT_SCHEMA_VERSION,
    MODE_AUTHENTICATED,
    GrantRefused,
    check_grant_fields,
    check_signature_hex,
    grant_provenance,
    read_genesis,
    verify_grant_signature,
)
from .lifecycle import (
    OPEN_THREAD_STATUSES,
    ChallengeStatus,
    IncompleteInvestigation,
    LifecycleError,
    ThreadStatus,
    check_challenge_filing,
    check_evidence_label,
    check_governance_transition,
    check_grant_transition,
    check_lab_transition,
    initial_status,
    uses_finding_stages,
)
from .records import Actor, Kind, Record, RecordError, Ref
from .store import GENESIS, Event

EVENT_RECORD = "RECORD"
EVENT_TRANSITION = "TRANSITION"
EVENT_EDGE = "EDGE"

RUN_STARTED = "RUN_STARTED"
RUN_PROGRESS = "RUN_PROGRESS"
RUN_COMPLETED = "RUN_COMPLETED"
RUN_FAILED = "RUN_FAILED"
RUN_INTERRUPTED = "RUN_INTERRUPTED"
RUN_EVENTS = frozenset({RUN_STARTED, RUN_PROGRESS, RUN_COMPLETED, RUN_FAILED, RUN_INTERRUPTED})


class TaskState(str, Enum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"


class OutputState(str, Enum):
    NONE = "NONE"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


@dataclass
class TaskRun:
    """Run state of one task, derived only from RUN_* events."""

    task_id: str
    step: str
    state: TaskState = TaskState.PENDING
    output_state: OutputState = OutputState.NONE
    attempts: int = 0
    output: Any = None
    partial: list[Any] = field(default_factory=list)
    all_checkpoints: list[Any] = field(default_factory=list)  # every checkpoint of every attempt
    error: str | None = None
    seqs: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "step": self.step,
            "state": self.state.value,
            "output_state": self.output_state.value,
            "attempts": self.attempts,
            "output": self.output,
            "partial": list(self.partial),
            "all_checkpoints": list(self.all_checkpoints),
            "error": self.error,
            "seqs": list(self.seqs),
        }

    def apply(self, event: Event) -> None:
        self.seqs.append(event.seq)
        if event.event_type == RUN_STARTED:
            self.attempts += 1
            self.state = TaskState.STARTED
            self.output_state = OutputState.NONE
            self.partial = []
            self.error = None
        elif event.event_type == RUN_PROGRESS:
            self.output_state = OutputState.PARTIAL
            self.partial.append(event.payload.get("data"))
            self.all_checkpoints.append(event.payload.get("data"))
        elif event.event_type == RUN_COMPLETED:
            self.state = TaskState.COMPLETED
            self.output_state = OutputState.COMPLETE
            self.output = event.payload.get("output")
        elif event.event_type == RUN_FAILED:
            self.state = TaskState.FAILED
            self.error = event.payload.get("error")
        elif event.event_type == RUN_INTERRUPTED:
            self.state = TaskState.INTERRUPTED
            self.output_state = OutputState.PARTIAL


class GraphError(ValueError):
    """The graph refused an operation."""


class PolicyViolation(GraphError):
    """An event in the log breaks the lab's rules (lifecycle, authority, edges, runs or genesis).

    Raised by Graph.check(), which runs both before Lab appends an event and on every replay,
    so a forged event appended behind the Lab's back is refused when the store is reopened.
    """


class EdgeType(str, Enum):
    DECOMPOSES = "DECOMPOSES"
    ANSWERS = "ANSWERS"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    CITES = "CITES"
    TESTS = "TESTS"
    DERIVES_FROM = "DERIVES_FROM"
    INVOLVES = "INVOLVES"
    RESOLVES = "RESOLVES"
    SUPERSEDES = "SUPERSEDES"
    PURSUES = "PURSUES"
    PART_OF = "PART_OF"
    REVIEWS = "REVIEWS"
    CHALLENGES = "CHALLENGES"


K = Kind
E = EdgeType

# Allowed (from_kind, edge, to_kind) combinations. SUPERSEDES is allowed for every kind onto
# the same kind and is handled in edge_allowed().
EDGE_TABLE: frozenset[tuple[Kind, EdgeType, Kind]] = frozenset(
    {
        (K.QUESTION, E.DECOMPOSES, K.OBJECTIVE),
        (K.QUESTION, E.DECOMPOSES, K.QUESTION),
        (K.HYPOTHESIS, E.ANSWERS, K.QUESTION),
        (K.EVIDENCE, E.SUPPORTS, K.HYPOTHESIS),
        (K.EVIDENCE, E.CONTRADICTS, K.HYPOTHESIS),
        (K.EVIDENCE, E.SUPPORTS, K.FINDING),
        (K.EVIDENCE, E.CONTRADICTS, K.FINDING),
        (K.EVIDENCE, E.CITES, K.SOURCE),
        (K.FINDING, E.CITES, K.SOURCE),
        (K.HYPOTHESIS, E.CITES, K.SOURCE),
        (K.EVIDENCE, E.DERIVES_FROM, K.EXPERIMENT),
        (K.EXPERIMENT, E.TESTS, K.HYPOTHESIS),
        (K.FINDING, E.DERIVES_FROM, K.EXPERIMENT),
        (K.FINDING, E.DERIVES_FROM, K.EVIDENCE),
        (K.FINDING, E.DERIVES_FROM, K.FINDING),
        (K.CONTRADICTION, E.INVOLVES, K.HYPOTHESIS),
        (K.CONTRADICTION, E.INVOLVES, K.EVIDENCE),
        (K.CONTRADICTION, E.INVOLVES, K.FINDING),
        (K.DECISION, E.RESOLVES, K.CONTRADICTION),
        (K.DECISION, E.RESOLVES, K.QUESTION),
        (K.CAPABILITY_PROPOSAL, E.DERIVES_FROM, K.FINDING),
        (K.PLAN, E.PURSUES, K.OBJECTIVE),
        (K.PLAN, E.PURSUES, K.QUESTION),
        (K.TASK, E.PART_OF, K.PLAN),
        (K.REVIEW, E.REVIEWS, K.FINDING),
        (K.REVIEW, E.REVIEWS, K.HYPOTHESIS),
        # A challenge targets a finding or a hypothesis, never another challenge: a reply to a
        # challenge is a new challenge on the same target or a governance resolution, and
        # nesting would make "open challenges on this finding" ambiguous and invite loops.
        (K.CHALLENGE, E.CHALLENGES, K.FINDING),
        (K.CHALLENGE, E.CHALLENGES, K.HYPOTHESIS),
    }
)


def edge_allowed(from_kind: Kind, edge: EdgeType, to_kind: Kind) -> bool:
    if edge is EdgeType.SUPERSEDES:
        return from_kind is to_kind
    return (from_kind, edge, to_kind) in EDGE_TABLE


@dataclass(frozen=True)
class Edge:
    from_id: str
    edge: EdgeType
    to_id: str
    actor_id: str
    created_at: str
    seq: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_id,
            "edge": self.edge.value,
            "to": self.to_id,
            "actor_id": self.actor_id,
            "created_at": self.created_at,
            "seq": self.seq,
        }


@dataclass
class Node:
    entity_id: str
    kind: Kind
    versions: list[Record] = field(default_factory=list)

    @property
    def latest(self) -> Record:
        return self.versions[-1]

    @property
    def status(self) -> str:
        return self.latest.disposition

    @property
    def author(self) -> Actor:
        return self.versions[0].origin

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind.value,
            "status": self.status,
            "author": self.author.to_dict(),
            "versions": [record.to_dict() for record in self.versions],
        }


class Graph:
    def __init__(self) -> None:
        self.tenant: str | None = None
        self.governance_issuers: frozenset[str] = frozenset()
        self.governance_mode: str | None = None
        self.governance_keys: dict[str, dict[str, str]] = {}  # enrolled id -> record; AUTHENTICATED only
        self.grant_skew_seconds: int = 0
        self.used_grant_nonces: set[str] = set()
        self.dispositions: list[dict[str, Any]] = []  # every governance disposition, in log order
        self.genesis_hash: str | None = None
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.runs: dict[str, dict[str, TaskRun]] = {}
        self.applied_seq: int = -1

    # construction

    @classmethod
    def rebuild(cls, events: Iterable[Event]) -> "Graph":
        graph = cls()
        for event in events:
            graph.apply(event)
        return graph

    def apply(self, event: Event) -> None:
        """Validate one event against the lab's rules, then apply it.

        The log is not trusted: check() enforces on replay exactly what Lab enforces on write
        (shared lifecycle functions, edge table, run state machine, genesis immutability).
        """
        if event.seq != self.applied_seq + 1:
            raise GraphError(f"event seq {event.seq} applied out of order (expected {self.applied_seq + 1})")
        self.check(event)
        if event.event_type == GENESIS:
            genesis = read_genesis(event.payload)
            self.tenant = event.payload["tenant"]
            self.governance_issuers = genesis.issuer_ids
            self.governance_mode = genesis.mode
            self.governance_keys = genesis.keys
            self.grant_skew_seconds = genesis.skew_seconds
            self.genesis_hash = event.hash
        elif event.event_type == EVENT_RECORD:
            record = Record.from_dict(event.payload["record"])
            self._add_version(record)
            for item in event.payload.get("edges", []):
                self._add_edge(record.entity_id, item["edge"], item["to"], record.origin.id, record.created_at, event.seq)
        elif event.event_type == EVENT_TRANSITION:
            record = Record.from_dict(event.payload["record"])
            self._add_version(record)
            governance = event.payload.get("governance")
            if governance is not None:
                self._note_disposition(event, record, governance)
        elif event.event_type == EVENT_EDGE:
            payload = event.payload
            self._add_edge(payload["from"], payload["edge"], payload["to"], payload["actor"]["id"], payload["created_at"], event.seq)
        elif event.event_type in RUN_EVENTS:
            payload = event.payload
            plan_runs = self.runs.setdefault(payload["plan"], {})
            run = plan_runs.get(payload["task"])
            if run is None:
                run = plan_runs[payload["task"]] = TaskRun(payload["task"], payload["step"])
            run.apply(event)
        self.applied_seq = event.seq

    def _add_version(self, record: Record) -> None:
        node = self.nodes.get(record.entity_id)
        if node is None:
            if record.version != 1:
                raise GraphError(f"first version of {record.entity_id} must be 1, got {record.version}")
            self.nodes[record.entity_id] = Node(record.entity_id, record.kind, [record])
            return
        if record.version != node.latest.version + 1:
            raise GraphError(f"{record.entity_id}: version {record.version} does not follow {node.latest.version}")
        if record.kind is not node.kind:
            raise GraphError(f"{record.entity_id}: kind cannot change between versions")
        node.versions.append(record)

    def _add_edge(self, from_id: str, edge: str, to_id: str, actor_id: str, created_at: str, seq: int) -> None:
        self.edges.append(Edge(from_id, EdgeType(edge), to_id, actor_id, created_at, seq))

    def _note_disposition(self, event: Event, record: Record, governance: dict[str, Any]) -> None:
        """Remember a governance disposition and whether a signed grant authenticated it.
        Called only after check() accepted the event, so in AUTHENTICATED mode the grant has
        just been verified by this replay."""
        authenticated = self.governance_mode == MODE_AUTHENTICATED
        entry: dict[str, Any] = {
            "seq": event.seq,
            "entity_id": record.entity_id,
            "version": record.version,
            "from": event.payload["from"],
            "to": event.payload["to"],
            "issuer_id": governance["issuer_id"],
            "submitted_by": record.origin.to_dict(),
            "at": record.created_at,
            "authenticated": authenticated,
        }
        if authenticated:
            grant = governance["grant"]
            self.used_grant_nonces.add(grant["nonce"])
            entry["key_id"] = self.governance_keys[grant["issuer_id"]]["key_id"]
            entry["grant_nonce"] = grant["nonce"]
            entry["grant_digest"] = record.provenance[0]["grant_digest"]
        self.dispositions.append(entry)

    # replay validation (shared with the write path)

    def check(self, event: Event) -> None:
        """Raise PolicyViolation unless the event is legal in the graph's current state.

        Does not mutate. Lab calls this before appending; apply() calls it on every event.
        """
        try:
            self._check(event)
        except PolicyViolation:
            raise
        except KeyError as exc:
            raise PolicyViolation(f"seq {event.seq}: {event.event_type}: missing field {exc}") from exc
        except (LifecycleError, GraphError, RecordError, TypeError, ValueError) as exc:
            raise PolicyViolation(f"seq {event.seq}: {event.event_type}: {exc}") from exc

    def _check(self, event: Event) -> None:
        payload = event.payload
        if event.event_type == GENESIS:
            if self.applied_seq != -1:
                raise GraphError("second genesis: tenant, issuers and principals are fixed at genesis")
            self._check_genesis(event)
            return
        if self.tenant is None:
            raise GraphError("the first event must be GENESIS")
        if event.tenant != self.tenant:
            raise GraphError(f"event tenant {event.tenant!r} is not the store tenant {self.tenant!r}")
        if event.event_type == EVENT_RECORD:
            self._check_record(payload)
        elif event.event_type == EVENT_TRANSITION:
            self._check_transition(payload)
        elif event.event_type == EVENT_EDGE:
            self._check_edge_event(payload)
        elif event.event_type in RUN_EVENTS:
            self._check_run(event.event_type, payload)
        else:
            raise GraphError(f"unknown event type {event.event_type!r}")

    @staticmethod
    def _check_genesis(event: Event) -> None:
        payload = event.payload
        genesis = read_genesis(payload)  # schema version, mode, issuer ids or issuer records
        if genesis.schema_version == CURRENT_SCHEMA_VERSION:
            expected = {"schema_version", "tenant", "governance_mode", "governance_issuers", "principals"}
            if genesis.authenticated:
                expected.add("grant_skew_seconds")
            if set(payload) != expected:
                raise GraphError(f"genesis fields must be exactly {sorted(expected)}, got {sorted(payload)}")
        tenant = payload["tenant"]
        if not isinstance(tenant, str) or not tenant.strip() or tenant != event.tenant:
            raise GraphError("genesis tenant is missing or differs from the event header")
        principals = payload["principals"]
        if not isinstance(principals, list) or not principals or not all(isinstance(p, str) and p for p in principals):
            raise GraphError("principals must be a non-empty list of ids")

    def _check_edge(self, from_kind: Kind, from_id: str, edge: str, to_id: str) -> None:
        try:
            edge_type = EdgeType(edge)
        except ValueError as exc:
            raise GraphError(f"unknown edge type {edge!r}") from exc
        if to_id == from_id:
            raise GraphError("an entity cannot point at itself")
        target = self.node(to_id)
        if not edge_allowed(from_kind, edge_type, target.kind):
            raise GraphError(f"{from_kind.value} {edge_type.value} {target.kind.value} is not an allowed edge")

    def _check_record(self, payload: dict[str, Any]) -> None:
        record = Record.from_dict(payload["record"])
        if not record.verify_digest():
            raise GraphError(f"{record.entity_id}: digest does not match content")
        if record.tenant != self.tenant:
            raise GraphError(f"{record.entity_id}: record tenant {record.tenant!r} is not {self.tenant!r}")
        if record.version != 1 or record.parents:
            raise GraphError(f"{record.entity_id}: a RECORD event must carry version 1 with no parents")
        expected = initial_status(record.kind)
        if record.disposition != expected:
            raise GraphError(f"{record.entity_id}: a new {record.kind.value} must start {expected}, not {record.disposition}")
        if record.entity_id in self.nodes:
            raise GraphError(f"entity {record.entity_id} already exists")
        check_evidence_label(record.origin.kind, record.evidence_label)
        edges = payload.get("edges", [])
        for item in edges:
            self._check_edge(record.kind, record.entity_id, item["edge"], item["to"])
        if record.kind is Kind.CHALLENGE:
            challenges = sum(1 for item in edges if item["edge"] == EdgeType.CHALLENGES.value)
            check_challenge_filing(record.body, record.provenance, challenges)

    def _check_transition(self, payload: dict[str, Any]) -> None:
        record = Record.from_dict(payload["record"])
        if not record.verify_digest():
            raise GraphError(f"{record.entity_id}: digest does not match content")
        if record.tenant != self.tenant:
            raise GraphError(f"{record.entity_id}: record tenant {record.tenant!r} is not {self.tenant!r}")
        node = self.node(record.entity_id)
        latest = node.latest
        if record.version != latest.version + 1:
            raise GraphError(f"{record.entity_id}: version {record.version} does not follow {latest.version}")
        if record.kind is not node.kind:
            raise GraphError(f"{record.entity_id}: kind cannot change between versions")
        if record.entity_digest != latest.entity_digest:
            raise GraphError(f"{record.entity_id}: entity_digest changed between versions")
        if record.body != latest.body or record.evidence_label is not latest.evidence_label:
            raise GraphError(f"{record.entity_id}: a transition may not change body or evidence label")
        if record.parents != (Ref(record.entity_id, latest.version),):
            raise GraphError(f"{record.entity_id}: transition parents must reference version {latest.version}")
        actor = Actor.from_dict(payload["actor"])
        if actor != record.origin:
            raise GraphError(f"{record.entity_id}: event actor differs from the record origin")
        from_status, to_status = payload["from"], payload["to"]
        if from_status != node.status:
            raise GraphError(f"{record.entity_id}: from {from_status} but the entity is {node.status}")
        if record.disposition != to_status:
            raise GraphError(f"{record.entity_id}: record disposition {record.disposition} is not the event's to {to_status}")
        reason = payload["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise GraphError(f"{record.entity_id}: a non-empty reason is required")
        governance = payload["governance"]
        if governance is None:
            check_lab_transition(node.kind, from_status, to_status, actor, node.author.id)
            if node.kind is Kind.PLAN and to_status == ThreadStatus.CLOSED.value:
                self.check_plan_closable(node.entity_id)
            return
        if self.governance_mode == MODE_AUTHENTICATED:
            self._check_granted_transition(record, payload, governance)
            return
        issuer_id = governance["issuer_id"]
        check_governance_transition(
            node.kind, from_status, to_status, actor, node.author.id, issuer_id, self.governance_issuers
        )
        provenance = record.provenance
        if (
            not provenance
            or provenance[0].get("type") != "governance_disposition"
            or provenance[0].get("issuer_id") != issuer_id
        ):
            raise GraphError(f"{record.entity_id}: governance provenance does not name the issuer")

    def _check_granted_transition(self, record: Record, payload: dict[str, Any], governance: Any) -> None:
        """AUTHENTICATED mode: the event must carry a grant that verifies, and the record it
        writes must be exactly the transition that grant authorizes. The actor's kind is not
        consulted: submitting a grant is not authority, the signature is."""
        if not isinstance(governance, dict) or "grant" not in governance or "signature" not in governance:
            raise GrantRefused(
                "this store is AUTHENTICATED: a governance disposition needs a signed grant; "
                "an actor kind and an issuer id are a claim, not authority"
            )
        if set(governance) != {"issuer_id", "grant", "signature"}:
            raise GrantRefused("governance must be exactly {issuer_id, grant, signature}")
        check_grant_fields(governance["grant"])  # exactly the eleven fields; nothing rides along inside the event
        grant = self.check_grant({**governance["grant"], "signature": governance["signature"]}, record.created_at)
        if governance["issuer_id"] != grant["issuer_id"]:
            raise GrantRefused("governance issuer_id differs from the grant's issuer_id")
        if grant["entity_id"] != record.entity_id:
            raise GrantRefused(f"the grant is for entity {grant['entity_id']!r}, not {record.entity_id!r}")
        if payload["to"] != grant["to"] or payload["reason"] != grant["reason"]:
            raise GrantRefused("the event's to and reason must be exactly the grant's")
        if list(record.provenance) != [grant_provenance(grant)]:
            raise GrantRefused(f"{record.entity_id}: governance provenance must be exactly the grant's issuer, reason and digest")

    def check_grant(self, signed_grant: Any, applied_at: str) -> dict[str, Any]:
        """Verify a signed grant against the graph's current state. Returns the grant fields.

        Shared by Lab.apply_grant, by the store's write-time validator and by every replay
        (applied_at is then the created_at of the version the event writes, which is the lab
        clock's reading when the grant was applied). Does not mutate. Raises GrantRefused,
        a lifecycle error or GraphError; nothing is written when it raises.
        """
        if self.governance_mode != MODE_AUTHENTICATED:
            raise GrantRefused(
                f"this store's governance mode is {self.governance_mode}: it enrolls no keys, so no grant can be verified"
            )
        if not isinstance(signed_grant, dict):
            raise GrantRefused("a grant is a JSON object")
        if signed_grant.get("signature") is None:
            raise GrantRefused("the grant has no signature")
        grant = check_grant_fields({name: value for name, value in signed_grant.items() if name != "signature"})
        signature = check_signature_hex(signed_grant["signature"])
        if grant["tenant"] != self.tenant:
            raise GrantRefused(f"the grant is for tenant {grant['tenant']!r}, not this store's tenant {self.tenant!r}")
        verify_grant_signature(grant, signature, self.governance_keys)
        if grant["nonce"] in self.used_grant_nonces:
            raise GrantRefused("the grant's nonce was already used in this tenant; a grant is single use")
        node = self.node(grant["entity_id"])
        latest = node.latest
        if grant["entity_version"] != latest.version:
            raise GrantRefused(
                f"{node.entity_id}: the grant disposes version {grant['entity_version']} but the current version is "
                f"{latest.version}; a grant is valid only for the exact version it names"
            )
        if grant["record_digest"] != latest.digest:
            raise GrantRefused(f"{node.entity_id}: the grant's record_digest is not the digest of version {latest.version}")
        check_grant_transition(node.kind, node.status, grant["to"], node.author.id, grant["issuer_id"])
        now = parse_utc(applied_at)
        if now >= parse_utc(grant["expires_at"]):
            raise GrantRefused(f"the grant expired at {grant['expires_at']} (lab clock {applied_at})")
        if (parse_utc(grant["issued_at"]) - now).total_seconds() > self.grant_skew_seconds:
            raise GrantRefused(
                f"the grant is issued in the future: issued_at {grant['issued_at']} is more than "
                f"{self.grant_skew_seconds}s after the lab clock {applied_at}"
            )
        return grant

    def governance_report(self) -> dict[str, Any]:
        """Governance mode, enrolled key labels and every disposition with its authentication."""
        authenticated = sum(1 for item in self.dispositions if item["authenticated"])
        if self.governance_mode == MODE_AUTHENTICATED:
            enrolled: list[dict[str, Any]] = [
                {name: record[name] for name in ("issuer_id", "kind", "alg", "key_id")}
                for _, record in sorted(self.governance_keys.items())
            ]
        else:  # legacy: ids only, no keys
            enrolled = [{"issuer_id": item, "kind": None, "alg": None, "key_id": None} for item in sorted(self.governance_issuers)]
        return {
            "mode": self.governance_mode,
            "genesis_hash": self.genesis_hash,
            "enrolled": enrolled,
            "authenticated": authenticated,
            "unauthenticated": len(self.dispositions) - authenticated,
            "dispositions": [dict(item) for item in self.dispositions],
        }

    def _check_edge_event(self, payload: dict[str, Any]) -> None:
        source = self.node(payload["from"])
        Actor.from_dict(payload["actor"])
        parse_utc(payload["created_at"])
        if payload["edge"] == EdgeType.CHALLENGES.value:
            raise GraphError("a CHALLENGES edge is created only when the challenge is filed, never added later")
        self._check_edge(source.kind, source.entity_id, payload["edge"], payload["to"])

    def _check_run(self, event_type: str, payload: dict[str, Any]) -> None:
        plan = self.node(payload["plan"])
        if plan.kind is not Kind.PLAN:
            raise GraphError(f"{plan.entity_id} is a {plan.kind.value}, not a plan")
        task = self.node(payload["task"])
        if task.kind is not Kind.TASK:
            raise GraphError(f"{task.entity_id} is a {task.kind.value}, not a task")
        if not any(edge.to_id == plan.entity_id for edge in self.edges_from(task.entity_id, EdgeType.PART_OF)):
            raise GraphError(f"task {task.entity_id} is not part of plan {plan.entity_id}")
        step = payload["step"]
        if task.latest.body.get("step") != step:
            raise GraphError(f"task {task.entity_id} is step {task.latest.body.get('step')!r}, not {step!r}")
        if payload["idempotency_key"] != f"{plan.entity_id}:{step}":
            raise GraphError("idempotency_key does not match plan and step")
        Actor.from_dict(payload["actor"])
        parse_utc(payload["created_at"])
        attempt = payload["attempt"]
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise GraphError("attempt must be an integer >= 1")
        run = self.runs.get(plan.entity_id, {}).get(task.entity_id) or TaskRun(task.entity_id, step)
        if event_type == RUN_STARTED:
            if run.state in (TaskState.STARTED, TaskState.COMPLETED):
                raise GraphError(f"task {task.entity_id} is {run.state.value}; completed or running steps are never re-run")
            if attempt != run.attempts + 1:
                raise GraphError(f"attempt {attempt} does not follow {run.attempts}")
            return
        if run.state is not TaskState.STARTED:
            raise GraphError(f"{event_type} for task {task.entity_id} that is {run.state.value}, not STARTED")
        if attempt != run.attempts:
            raise GraphError(f"attempt {attempt} is not the running attempt {run.attempts}")
        if event_type == RUN_INTERRUPTED and payload.get("output_state") != OutputState.PARTIAL.value:
            raise GraphError("an interrupted run must mark its outputs PARTIAL")

    def check_plan_closable(self, plan_id: str) -> None:
        """A plan closes only when every task's run state is COMPLETED. Shared by the write
        path and replay, so no code path can report a partial investigation as done."""
        offenders = [run for run in self.run_states(plan_id).values() if run.state is not TaskState.COMPLETED]
        if offenders:
            detail = ", ".join(f"{run.step}={run.state.value}/{run.output_state.value}" for run in offenders)
            raise IncompleteInvestigation(f"plan {plan_id} cannot be closed: {detail}")

    # comparison and export

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "governance_issuers": sorted(self.governance_issuers),
            "governance_mode": self.governance_mode,
            "governance_keys": [record for _, record in sorted(self.governance_keys.items())],
            "grant_skew_seconds": self.grant_skew_seconds,
            "used_grant_nonces": sorted(self.used_grant_nonces),
            "dispositions": [dict(item) for item in self.dispositions],
            "applied_seq": self.applied_seq,
            "nodes": {entity_id: node.to_dict() for entity_id, node in sorted(self.nodes.items())},
            "edges": [edge.to_dict() for edge in self.edges],
            "runs": {
                plan_id: {task_id: run.to_dict() for task_id, run in sorted(tasks.items())}
                for plan_id, tasks in sorted(self.runs.items())
            },
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Graph):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    # queries

    def node(self, entity_id: str) -> Node:
        try:
            return self.nodes[entity_id]
        except KeyError as exc:
            raise GraphError(f"unknown entity {entity_id!r}") from exc

    def has(self, entity_id: str) -> bool:
        return entity_id in self.nodes

    def history(self, entity_id: str) -> list[Record]:
        """Every version of the entity, oldest first. Rejections and withdrawals stay in it."""
        return list(self.node(entity_id).versions)

    def edges_from(self, entity_id: str, edge: EdgeType | None = None) -> list[Edge]:
        return [item for item in self.edges if item.from_id == entity_id and (edge is None or item.edge is edge)]

    def edges_to(self, entity_id: str, edge: EdgeType | None = None) -> list[Edge]:
        return [item for item in self.edges if item.to_id == entity_id and (edge is None or item.edge is edge)]

    def children(self, entity_id: str, edge: EdgeType | None = None) -> list[Node]:
        """Nodes that point at entity_id (a question decomposing an objective is its child)."""
        self.node(entity_id)
        seen: list[str] = []
        for item in self.edges_to(entity_id, edge):
            if item.from_id not in seen:
                seen.append(item.from_id)
        return [self.nodes[child] for child in seen]

    def ancestors(self, entity_id: str) -> list[Node]:
        """Transitive closure following outgoing edges, breadth first, nearest first."""
        self.node(entity_id)
        order: list[str] = []
        queue: deque[str] = deque([entity_id])
        visited = {entity_id}
        while queue:
            current = queue.popleft()
            for item in self.edges_from(current):
                if item.to_id not in visited:
                    visited.add(item.to_id)
                    order.append(item.to_id)
                    queue.append(item.to_id)
        return [self.nodes[item] for item in order]

    def contradictions_involving(self, entity_id: str) -> list[Node]:
        """Contradiction records that INVOLVE the entity, whatever its kind."""
        return [child for child in self.children(entity_id, EdgeType.INVOLVES) if child.kind is Kind.CONTRADICTION]

    def contradictions_of(self, hypothesis_id: str) -> dict[str, list[Node]]:
        """Evidence that CONTRADICTS the hypothesis and contradiction records that INVOLVE it."""
        node = self.node(hypothesis_id)
        if node.kind is not Kind.HYPOTHESIS:
            raise GraphError(f"{hypothesis_id} is a {node.kind.value}, not a hypothesis")
        return {
            "contradicting_evidence": self.children(hypothesis_id, EdgeType.CONTRADICTS),
            "contradiction_records": [
                child for child in self.children(hypothesis_id, EdgeType.INVOLVES) if child.kind is Kind.CONTRADICTION
            ],
        }

    def plan_tasks(self, plan_id: str) -> list[Node]:
        """Tasks PART_OF a plan, in step index order."""
        plan = self.node(plan_id)
        if plan.kind is not Kind.PLAN:
            raise GraphError(f"{plan_id} is a {plan.kind.value}, not a plan")
        tasks = [node for node in self.children(plan_id, EdgeType.PART_OF) if node.kind is Kind.TASK]
        return sorted(tasks, key=lambda node: node.latest.body["index"])

    def run_states(self, plan_id: str) -> dict[str, TaskRun]:
        """Run state of every task of the plan; tasks never started are PENDING."""
        known = self.runs.get(plan_id, {})
        return {
            node.entity_id: known.get(node.entity_id) or TaskRun(node.entity_id, node.latest.body["step"])
            for node in self.plan_tasks(plan_id)
        }

    # challenges (advice to governance; they never change their target)

    def challenges_of(self, entity_id: str) -> list[Node]:
        """Every challenge ever filed against the entity, oldest first, whatever its status."""
        self.node(entity_id)
        return [child for child in self.children(entity_id, EdgeType.CHALLENGES) if child.kind is Kind.CHALLENGE]

    def open_challenges(self, entity_id: str) -> list[Node]:
        return [node for node in self.challenges_of(entity_id) if node.status == ChallengeStatus.OPEN.value]

    def entities_with_open_challenges(self, kind: Kind | None = None) -> list[Node]:
        """Targets that have at least one OPEN challenge; the view governance reads."""
        targets: list[str] = []
        for edge in self.edges:
            if edge.edge is EdgeType.CHALLENGES and self.nodes[edge.from_id].status == ChallengeStatus.OPEN.value:
                if edge.to_id not in targets:
                    targets.append(edge.to_id)
        nodes = [self.nodes[target] for target in targets]
        return nodes if kind is None else [node for node in nodes if node.kind is kind]

    def findings_with_open_challenges(self) -> list[Node]:
        return self.entities_with_open_challenges(Kind.FINDING)

    def challenge_summary(self, entity_id: str) -> list[dict[str, Any]]:
        """Each challenge against the entity with its filer, reason, status and resolution."""
        out = []
        for node in self.challenges_of(entity_id):
            latest = node.latest
            resolution = None
            if node.status in {status.value for status in ChallengeStatus} - {ChallengeStatus.OPEN.value}:
                resolution = {
                    "status": node.status,
                    "by": latest.origin.to_dict(),
                    "at": latest.created_at,
                    "provenance": list(latest.provenance),
                }
            out.append(
                {
                    "challenge_id": node.entity_id,
                    "filer": node.author.to_dict(),
                    "filed_at": node.versions[0].created_at,
                    "reason": node.versions[0].body.get("reason"),
                    "evidence": list(node.versions[0].provenance),
                    "status": node.status,
                    "resolution": resolution,
                }
            )
        return out

    # sources (preserved inputs; never evidence by themselves)

    def sources(self) -> list[Node]:
        return [node for node in self.nodes.values() if node.kind is Kind.SOURCE]

    def source_by_locator(self, locator: str) -> Node | None:
        """The current (not superseded) source record for a locator, or None."""
        current = None
        for node in self.sources():
            if node.latest.body.get("locator") == locator and node.status != ThreadStatus.SUPERSEDED.value:
                current = node
        return current

    def sources_cited_by(self, entity_id: str) -> list[Node]:
        self.node(entity_id)
        out: list[Node] = []
        for edge in self.edges_from(entity_id, EdgeType.CITES):
            target = self.nodes[edge.to_id]
            if target.kind is Kind.SOURCE and target not in out:
                out.append(target)
        return out

    def shared_sources(self, a: str, b: str) -> list[Node]:
        """Sources both entities cite, in the order a cites them. Input for correlated-source
        detection in a later round; a shared source is a fact, not a verdict."""
        cited_by_b = {node.entity_id for node in self.sources_cited_by(b)}
        return [node for node in self.sources_cited_by(a) if node.entity_id in cited_by_b]

    def open_threads(self) -> list[Node]:
        open_values = {status.value for status in OPEN_THREAD_STATUSES}
        return [
            node
            for node in self.nodes.values()
            if not uses_finding_stages(node.kind) and node.status in open_values
        ]

    def traceability(self, objective_id: str) -> list[dict[str, Any]]:
        """Chains objective -> question -> hypothesis -> experiment -> finding -> capability_proposal.

        Every chain that exists is returned as far as it goes, with complete=True only when it
        reaches a capability proposal. Partial chains are reported, never hidden.
        """
        root = self.node(objective_id)
        if root.kind is not Kind.OBJECTIVE:
            raise GraphError(f"{objective_id} is a {root.kind.value}, not an objective")
        steps = (
            ("question", EdgeType.DECOMPOSES, Kind.QUESTION),
            ("hypothesis", EdgeType.ANSWERS, Kind.HYPOTHESIS),
            ("experiment", EdgeType.TESTS, Kind.EXPERIMENT),
            ("finding", EdgeType.DERIVES_FROM, Kind.FINDING),
            ("capability_proposal", EdgeType.DERIVES_FROM, Kind.CAPABILITY_PROPOSAL),
        )
        chains: list[dict[str, Any]] = []

        def extend(chain: dict[str, Any], current_id: str, depth: int) -> None:
            if depth == len(steps):
                chains.append({**chain, "complete": True})
                return
            label, edge, kind = steps[depth]
            nexts = [child for child in self.children(current_id, edge) if child.kind is kind]
            if not nexts:
                chains.append({**chain, "complete": False})
                return
            for child in nexts:
                extend({**chain, label: child.entity_id}, child.entity_id, depth + 1)

        extend({"objective": objective_id}, objective_id, 0)
        return chains
