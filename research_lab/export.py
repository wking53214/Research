"""Deterministic JSON-lines bundle export and stand-alone bundle verification.

Line 1 is a header: bundle schema, store schema version, tenant, event count, head hash,
the governance mode and the genesis governance issuers (plain ids in a legacy store, issuer
records with public keys in an AUTHENTICATED one). Every following line is one event, in
sequence order, as canonical JSON. The same store produces the same bytes.

export_bundle() verifies the store first and refuses to write a bundle of a store that does
not verify. verify_bundle() re-checks the whole chain, the tenant and the lab policy from
the file alone. In an AUTHENTICATED bundle that replay re-verifies every governance grant's
Ed25519 signature against the public keys in the bundle's own genesis event; nothing but
the file is needed. What the file alone cannot prove is that its genesis is the right one:
compare result.governance["genesis_hash"] (or the enrolled public keys) with a value
obtained out of band.

Importing or merging bundles is not implemented in increment 1. There is no function for it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .governance import GovernanceError, expectation_problems, read_genesis
from .graph import Graph, PolicyViolation
from .lab import verify_store
from .store import GENESIS, Event, EventStore, Signer, StoreError, VerifyResult, verify_events

BUNDLE_SCHEMA = "research_lab.bundle/1"


class ExportRefused(StoreError):
    """The store did not verify, so no bundle was written."""


class BundleError(StoreError):
    """The bundle file is malformed."""


@dataclass(frozen=True)
class BundleInfo:
    path: str
    tenant: str
    event_count: int
    head_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "tenant": self.tenant, "event_count": self.event_count, "head_hash": self.head_hash}


def export_bundle(store: EventStore, path: str, require_signed: bool = False) -> BundleInfo:
    result = verify_store(store, require_signed=require_signed)
    if not result.ok:
        raise ExportRefused("store does not verify; refusing to export: " + "; ".join(result.problems))
    events = store.events()
    genesis = events[0].payload
    header = {
        "bundle_schema": BUNDLE_SCHEMA,
        "store_schema_version": genesis["schema_version"],
        "tenant": store.tenant,
        "event_count": len(events),
        "head_hash": events[-1].hash,
        "governance_mode": store.governance_mode,
        "governance_issuers": genesis["governance_issuers"],
    }
    lines = [canonical_json(header)] + [canonical_json(event.to_dict()) for event in events]
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    return BundleInfo(path, store.tenant, len(events), events[-1].hash)


def read_bundle(path: str) -> tuple[dict[str, Any], list[Event]]:
    with open(path, encoding="ascii") as handle:
        raw_lines = [line for line in handle.read().split("\n") if line]
    if not raw_lines:
        raise BundleError("bundle is empty")
    try:
        header = json.loads(raw_lines[0])
        events = [Event.from_dict(json.loads(line)) for line in raw_lines[1:]]
    except (json.JSONDecodeError, StoreError) as exc:
        raise BundleError(f"bundle is malformed: {exc}") from exc
    if not isinstance(header, dict) or header.get("bundle_schema") != BUNDLE_SCHEMA:
        raise BundleError(f"bundle header schema is not {BUNDLE_SCHEMA}")
    return header, events


def _issuer_set(issuers: Any) -> list[str] | None:
    """Order-insensitive form of an issuer list (plain ids or issuer records) for comparison."""
    if not isinstance(issuers, list):
        return None
    try:
        return sorted(canonical_json(item) for item in issuers)
    except ValueError:
        return None


def verify_bundle(
    path: str,
    signer: Signer | None = None,
    require_signed: bool = False,
    *,
    expected_genesis_hash: str | None = None,
    require_authenticated: bool = False,
) -> VerifyResult:
    """Verify chain, tenant, header consistency and lab policy using nothing but the file.

    The policy replay re-verifies every governance grant against the public keys in the
    file's own genesis. expected_genesis_hash (a value obtained out of band) and
    require_authenticated make the result fail when the file is some other store, or one
    whose governance is not authenticated."""
    header, events = read_bundle(path)
    tenant = header.get("tenant")
    result = verify_events(events, tenant if isinstance(tenant, str) else None, signer, require_signed)
    if result.ok:
        try:
            replay = Graph.rebuild(events)
            result.policy_checked = True
            result.governance = replay.governance_report()
        except PolicyViolation as exc:
            result.problems.append(f"policy violation: {exc}")
    result.problems.extend(expectation_problems(result.governance, expected_genesis_hash, require_authenticated))
    genesis_payload = events[0].payload if events and events[0].event_type == GENESIS else {}
    if header.get("store_schema_version") != genesis_payload.get("schema_version"):
        result.problems.append("header store_schema_version mismatch")
    if header.get("event_count") != len(events):
        result.problems.append(f"header event_count {header.get('event_count')} differs from {len(events)} events in file")
    if events and header.get("head_hash") != events[-1].hash:
        result.problems.append("header head_hash differs from last event")
    if events and events[0].event_type == GENESIS:
        if _issuer_set(header.get("governance_issuers", [])) != _issuer_set(genesis_payload.get("governance_issuers", [])):
            result.problems.append("header governance_issuers differ from genesis")
        try:
            genesis_mode = read_genesis(genesis_payload).mode
        except (GovernanceError, KeyError, TypeError):
            genesis_mode = None  # the policy replay above has already reported the genesis
        # A bundle written before the governance port has no governance_mode in its header;
        # that is accepted only for a schema_version 1 (legacy) genesis.
        legacy_header = "governance_mode" not in header and genesis_payload.get("schema_version") == 1
        if genesis_mode is not None and not legacy_header and header.get("governance_mode") != genesis_mode:
            result.problems.append("header governance_mode differs from genesis")
    result.ok = not result.problems
    return result
