"""Deterministic JSON-lines bundle export and stand-alone bundle verification.

Line 1 is a header: bundle schema, store schema version, tenant, event count, head hash and
the genesis governance issuers. Every following line is one event, in sequence order, as
canonical JSON. The same store produces the same bytes.

export_bundle() verifies the store first and refuses to write a bundle of a store that does
not verify. verify_bundle() re-checks the whole chain and the tenant from the file alone.

Importing or merging bundles is not implemented in increment 1. There is no function for it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .graph import Graph, PolicyViolation
from .lab import verify_store
from .store import GENESIS, SCHEMA_VERSION, Event, EventStore, Signer, StoreError, VerifyResult, verify_events

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
    header = {
        "bundle_schema": BUNDLE_SCHEMA,
        "store_schema_version": SCHEMA_VERSION,
        "tenant": store.tenant,
        "event_count": len(events),
        "head_hash": events[-1].hash,
        "governance_issuers": sorted(store.governance_issuers),
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


def verify_bundle(path: str, signer: Signer | None = None, require_signed: bool = False) -> VerifyResult:
    """Verify chain, tenant, header consistency and lab policy using nothing but the file."""
    header, events = read_bundle(path)
    tenant = header.get("tenant")
    result = verify_events(events, tenant if isinstance(tenant, str) else None, signer, require_signed)
    if result.ok:
        try:
            Graph.rebuild(events)
            result.policy_checked = True
        except PolicyViolation as exc:
            result.problems.append(f"policy violation: {exc}")
    if header.get("store_schema_version") != SCHEMA_VERSION:
        result.problems.append("header store_schema_version mismatch")
    if header.get("event_count") != len(events):
        result.problems.append(f"header event_count {header.get('event_count')} differs from {len(events)} events in file")
    if events and header.get("head_hash") != events[-1].hash:
        result.problems.append("header head_hash differs from last event")
    if events and events[0].event_type == GENESIS:
        genesis_issuers = sorted(events[0].payload.get("governance_issuers", []))
        if sorted(header.get("governance_issuers", [])) != genesis_issuers:
            result.problems.append("header governance_issuers differ from genesis")
    result.ok = not result.problems
    return result
