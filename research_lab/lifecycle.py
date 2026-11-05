"""Lifecycle statuses, the transition table and the authority rules, enforced in code.

Two vocabularies:

* threads (every kind except finding): OPEN, DEFERRED, CLOSED, SUPERSEDED, REJECTED, REOPENED;
* findings: the epistemic stages PROPOSED, REVIEWED, REPRODUCED, RECOMMENDED (lab-settable),
  ACCEPTED, ADMITTED (governance-only) and WITHDRAWN.

Rules (each has a positive and a negative test in tests/test_lifecycle.py):

* Lab code paths can never set ACCEPTED or ADMITTED. check_lab_transition refuses them.
* ACCEPTED and ADMITTED are written only through check_governance_transition, which requires
  an issuer id from the genesis governance issuer set and an actor of kind HUMAN or SYSTEM.
  An AI actor is refused even with a valid issuer id.
* A review transition (to REVIEWED, REPRODUCED or RECOMMENDED) or a governance transition by
  the same actor id as the entity's author is refused: no self-approval.
* Every finding starts at PROPOSED. AI-origin records therefore enter as proposals, and an
  AI author cannot move its own record's review state (it is the author).
* A hypothesis is a thread. Whatever its author, it never becomes a finding by transition;
  findings are separate records that derive from experiments or evidence.
* A challenge (kind challenge) flags that a finding or hypothesis looks wrong. It has its own
  small vocabulary: OPEN when filed; UPHELD or DISMISSED only through a governance
  disposition (same rules as acceptance, and never by the filer); WITHDRAWN only by the
  filer. All three are terminal. A challenge never changes its target's status: upholding a
  challenge does not withdraw the finding, a separate governance WITHDRAWN does. Filing
  requires a non-empty reason and at least one provenance reference.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .records import Actor, ActorKind, Kind


class LifecycleError(ValueError):
    """A lifecycle rule refused the operation."""


class TransitionError(LifecycleError):
    """The transition is not in the table."""


class AuthorityError(LifecycleError):
    """The actor lacks the authority to make this transition."""


class SelfReviewError(AuthorityError):
    """The reviewer is the author."""


class IncompleteInvestigation(LifecycleError):
    """A plan cannot be closed while any of its tasks is not COMPLETED."""


class ThreadStatus(str, Enum):
    OPEN = "OPEN"
    DEFERRED = "DEFERRED"
    CLOSED = "CLOSED"
    SUPERSEDED = "SUPERSEDED"
    REJECTED = "REJECTED"
    REOPENED = "REOPENED"


class FindingStage(str, Enum):
    PROPOSED = "PROPOSED"
    REVIEWED = "REVIEWED"
    REPRODUCED = "REPRODUCED"
    RECOMMENDED = "RECOMMENDED"
    ACCEPTED = "ACCEPTED"
    ADMITTED = "ADMITTED"
    WITHDRAWN = "WITHDRAWN"


class ChallengeStatus(str, Enum):
    OPEN = "OPEN"
    UPHELD = "UPHELD"
    DISMISSED = "DISMISSED"
    WITHDRAWN = "WITHDRAWN"


CHALLENGE_TRANSITIONS: dict[ChallengeStatus, frozenset[ChallengeStatus]] = {
    ChallengeStatus.OPEN: frozenset({ChallengeStatus.UPHELD, ChallengeStatus.DISMISSED, ChallengeStatus.WITHDRAWN}),
    ChallengeStatus.UPHELD: frozenset(),
    ChallengeStatus.DISMISSED: frozenset(),
    ChallengeStatus.WITHDRAWN: frozenset(),
}
CHALLENGE_RESOLUTIONS = frozenset({ChallengeStatus.UPHELD, ChallengeStatus.DISMISSED})


THREAD_TRANSITIONS: dict[ThreadStatus, frozenset[ThreadStatus]] = {
    ThreadStatus.OPEN: frozenset(
        {ThreadStatus.DEFERRED, ThreadStatus.CLOSED, ThreadStatus.SUPERSEDED, ThreadStatus.REJECTED}
    ),
    ThreadStatus.DEFERRED: frozenset(
        {ThreadStatus.REOPENED, ThreadStatus.CLOSED, ThreadStatus.SUPERSEDED, ThreadStatus.REJECTED}
    ),
    ThreadStatus.CLOSED: frozenset({ThreadStatus.REOPENED, ThreadStatus.SUPERSEDED}),
    ThreadStatus.REJECTED: frozenset({ThreadStatus.REOPENED, ThreadStatus.SUPERSEDED}),
    ThreadStatus.SUPERSEDED: frozenset(),
    ThreadStatus.REOPENED: frozenset(
        {ThreadStatus.DEFERRED, ThreadStatus.CLOSED, ThreadStatus.SUPERSEDED, ThreadStatus.REJECTED}
    ),
}

FINDING_TRANSITIONS: dict[FindingStage, frozenset[FindingStage]] = {
    FindingStage.PROPOSED: frozenset({FindingStage.REVIEWED, FindingStage.WITHDRAWN}),
    FindingStage.REVIEWED: frozenset({FindingStage.REPRODUCED, FindingStage.PROPOSED, FindingStage.WITHDRAWN}),
    FindingStage.REPRODUCED: frozenset({FindingStage.RECOMMENDED, FindingStage.REVIEWED, FindingStage.WITHDRAWN}),
    FindingStage.RECOMMENDED: frozenset({FindingStage.ACCEPTED, FindingStage.REPRODUCED, FindingStage.WITHDRAWN}),
    FindingStage.ACCEPTED: frozenset({FindingStage.ADMITTED, FindingStage.WITHDRAWN}),
    FindingStage.ADMITTED: frozenset({FindingStage.WITHDRAWN}),
    # WITHDRAWN is terminal. To try again the lab adds a new finding that SUPERSEDES or
    # DERIVES_FROM the withdrawn one; the withdrawal history stays on the old entity.
    FindingStage.WITHDRAWN: frozenset(),
}

GOVERNANCE_ONLY_STAGES = frozenset({FindingStage.ACCEPTED, FindingStage.ADMITTED})
# Withdrawing a finding that governance has accepted or admitted is itself a governance act.
GOVERNED_STAGES = GOVERNANCE_ONLY_STAGES
REVIEW_STAGES = frozenset({FindingStage.REVIEWED, FindingStage.REPRODUCED, FindingStage.RECOMMENDED})
LAB_SETTABLE_STAGES = frozenset(FindingStage) - GOVERNANCE_ONLY_STAGES
GOVERNANCE_ACTOR_KINDS = frozenset({ActorKind.HUMAN, ActorKind.SYSTEM})

OPEN_THREAD_STATUSES = frozenset({ThreadStatus.OPEN, ThreadStatus.REOPENED})


def uses_finding_stages(kind: Kind) -> bool:
    return kind is Kind.FINDING


def uses_challenge_statuses(kind: Kind) -> bool:
    return kind is Kind.CHALLENGE


def vocabulary(kind: Kind) -> type[ThreadStatus] | type[FindingStage] | type[ChallengeStatus]:
    if uses_finding_stages(kind):
        return FindingStage
    if uses_challenge_statuses(kind):
        return ChallengeStatus
    return ThreadStatus


def initial_status(kind: Kind) -> str:
    """Every finding starts PROPOSED; every thread and every challenge starts OPEN. Callers
    cannot choose."""
    return FindingStage.PROPOSED.value if uses_finding_stages(kind) else ThreadStatus.OPEN.value


def parse_status(kind: Kind, value: str) -> ThreadStatus | FindingStage | ChallengeStatus:
    enum = vocabulary(kind)
    try:
        return enum(value)
    except ValueError as exc:
        names = {FindingStage: "finding stage", ChallengeStatus: "challenge status", ThreadStatus: "thread status"}
        raise TransitionError(f"{value!r} is not a {names[enum]} for kind {kind.value}") from exc


def allowed_targets(kind: Kind, current: str) -> frozenset[str]:
    status = parse_status(kind, current)
    if isinstance(status, FindingStage):
        return frozenset(item.value for item in FINDING_TRANSITIONS[status])
    if isinstance(status, ChallengeStatus):
        return frozenset(item.value for item in CHALLENGE_TRANSITIONS[status])
    return frozenset(item.value for item in THREAD_TRANSITIONS[status])


def check_challenge_filing(body: Mapping[str, Any], provenance: Sequence[Mapping[str, Any]], challenges_edges: int) -> None:
    """A challenge is refused when empty: it needs a non-empty reason, at least one provenance
    reference (the evidence it rests on) and exactly one CHALLENGES edge to its target."""
    reason = body.get("reason") if isinstance(body, Mapping) else None
    if not isinstance(reason, str) or not reason.strip():
        raise LifecycleError("a challenge needs a non-empty reason in its body")
    if not provenance or not all(isinstance(item, Mapping) and item for item in provenance):
        raise LifecycleError("a challenge needs at least one provenance reference (its evidence)")
    if challenges_edges != 1:
        raise LifecycleError("a challenge is filed with exactly one CHALLENGES edge to its target")


def _check_in_table(kind: Kind, current: str, target: str) -> None:
    parse_status(kind, target)
    if target not in allowed_targets(kind, current):
        raise TransitionError(f"{kind.value}: {current} -> {target} is not an allowed transition")


def governance_required(kind: Kind, current: str, target: str) -> bool:
    """True when only a governance disposition may make this transition: reaching ACCEPTED or
    ADMITTED, withdrawing a finding that is ACCEPTED or ADMITTED, or resolving a challenge
    (UPHELD or DISMISSED)."""
    if uses_challenge_statuses(kind):
        return target in {status.value for status in CHALLENGE_RESOLUTIONS}
    if not uses_finding_stages(kind):
        return False
    governance_values = {stage.value for stage in GOVERNANCE_ONLY_STAGES}
    governed_values = {stage.value for stage in GOVERNED_STAGES}
    if target in governance_values:
        return True
    return target == FindingStage.WITHDRAWN.value and current in governed_values


def check_lab_transition(kind: Kind, current: str, target: str, actor: Actor, author_id: str) -> None:
    """Refuse or allow a transition made by lab code. Raises on refusal, returns None otherwise."""
    review_values = {stage.value for stage in REVIEW_STAGES}
    if governance_required(kind, current, target):
        raise AuthorityError(f"{current} -> {target} is governance-only; lab code paths cannot set it")
    _check_in_table(kind, current, target)
    if uses_finding_stages(kind) and target in review_values and actor.id == author_id:
        raise SelfReviewError(f"actor {actor.id!r} authored this finding and may not review it")
    if uses_challenge_statuses(kind) and target == ChallengeStatus.WITHDRAWN.value and actor.id != author_id:
        raise AuthorityError(f"only the filer may withdraw a challenge; actor {actor.id!r} is not the filer {author_id!r}")


def check_governance_transition(
    kind: Kind,
    current: str,
    target: str,
    actor: Actor,
    author_id: str,
    issuer_id: str,
    governance_issuers: Iterable[str],
) -> None:
    """Refuse or allow a governance disposition. Raises on refusal."""
    if not (uses_finding_stages(kind) or uses_challenge_statuses(kind)):
        raise AuthorityError(f"governance dispositions apply to findings and challenges, not {kind.value}")
    parse_status(kind, target)
    if not governance_required(kind, current, target):
        raise AuthorityError(f"{current} -> {target} is not a governance transition; use a lab transition")
    if issuer_id not in set(governance_issuers):
        raise AuthorityError(f"issuer {issuer_id!r} is not in the genesis governance issuer set")
    if actor.kind not in GOVERNANCE_ACTOR_KINDS:
        raise AuthorityError(f"actor kind {actor.kind.value} may not record a governance disposition")
    if actor.id == author_id:
        verb = "resolve" if uses_challenge_statuses(kind) else "accept"
        noun = "filed this challenge" if uses_challenge_statuses(kind) else "authored this finding"
        raise SelfReviewError(f"actor {actor.id!r} {noun} and may not {verb} it")
    _check_in_table(kind, current, target)
