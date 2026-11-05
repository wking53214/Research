"""Thin command line: init, add, transition, show, verify, export.

Every command prints one JSON document to stdout. Refusals print a JSON error to stderr and
exit 1. Usage errors exit 2 (argparse). The principal is a claim: --principal names it and the
store checks it against the genesis entitlement set.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .clock import Clock, FixedClock, SystemClock
from .export import export_bundle
from .graph import EdgeType, GraphError
from .lab import Lab, verify_store
from .lifecycle import LifecycleError
from .records import Actor, ActorKind, EvidenceLabel, Kind, RecordError
from .store import EventStore, Principal, StoreError

ADDABLE = ("objective", "question", "hypothesis", "evidence", "challenge")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, help="path to the SQLite store")
    parser.add_argument("--tenant", required=True, help="tenant the store belongs to")
    parser.add_argument("--principal", required=True, help="principal id (a claim; checked against genesis)")
    parser.add_argument("--at", default=None, help="timestamp YYYY-MM-DDTHH:MM:SSZ; default is the wall clock")


def _actor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--actor", required=True, help="actor id")
    parser.add_argument("--actor-kind", required=True, choices=[kind.value for kind in ActorKind])
    parser.add_argument("--provider", default=None)
    parser.add_argument("--model-family", default=None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m research_lab", description="research_lab command line")
    parser.add_argument("--version", action="version", version=f"research_lab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create a store and its genesis event")
    _common(p_init)
    p_init.add_argument("--issuer", action="append", default=[], help="governance issuer id (repeatable)")
    p_init.add_argument("--entitle", action="append", default=[], help="additional entitled principal id (repeatable)")

    p_add = sub.add_parser("add", help="add an objective, question, hypothesis or evidence record")
    p_add.add_argument("kind", choices=ADDABLE)
    _common(p_add)
    _actor_args(p_add)
    p_add.add_argument("--title", default=None, help="title (objective)")
    p_add.add_argument("--text", default=None, help="text (question, hypothesis, evidence)")
    p_add.add_argument("--decomposes", default=None, help="objective or question id a question decomposes")
    p_add.add_argument("--answers", default=None, help="question id a hypothesis answers")
    p_add.add_argument("--supports", default=None, help="hypothesis id the evidence supports")
    p_add.add_argument("--contradicts", default=None, help="hypothesis id the evidence contradicts")
    p_add.add_argument("--cites", default=None, help="source id the evidence cites")
    p_add.add_argument("--label", default=None, choices=[label.value for label in EvidenceLabel], help="evidence label")
    p_add.add_argument("--target", default=None, help="finding or hypothesis id a challenge is filed against")
    p_add.add_argument("--evidence", action="append", default=[], help="evidence reference for a challenge (repeatable)")

    p_tr = sub.add_parser("transition", help="move an entity to a new status (lab transitions only)")
    _common(p_tr)
    _actor_args(p_tr)
    p_tr.add_argument("--entity", required=True)
    p_tr.add_argument("--to", required=True)
    p_tr.add_argument("--reason", required=True)

    p_show = sub.add_parser("show", help="show an entity, its history and edges")
    _common(p_show)
    p_show.add_argument("--entity", required=True)

    p_verify = sub.add_parser("verify", help="verify the store's hash chain and tenant")
    _common(p_verify)

    p_export = sub.add_parser("export", help="write a verified JSON-lines bundle")
    _common(p_export)
    p_export.add_argument("--out", required=True)
    return parser


def _clock(args: argparse.Namespace) -> Clock:
    return FixedClock(args.at) if args.at else SystemClock()


def _principal(args: argparse.Namespace) -> Principal:
    return Principal(args.principal, frozenset({args.tenant}))


def _actor(args: argparse.Namespace) -> Actor:
    return Actor(args.actor, ActorKind(args.actor_kind), args.provider, args.model_family)


def _emit(data: object) -> None:
    sys.stdout.write(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _add(lab: Lab, args: argparse.Namespace) -> dict:
    actor = _actor(args)
    kind = Kind(args.kind)
    edges: list[tuple[EdgeType, str]] = []
    label = None
    if kind is Kind.OBJECTIVE:
        if not args.title:
            raise RecordError("an objective needs --title")
        body = {"title": args.title}
    elif kind is Kind.QUESTION:
        if not args.text or not args.decomposes:
            raise RecordError("a question needs --text and --decomposes")
        body = {"text": args.text}
        edges.append((EdgeType.DECOMPOSES, args.decomposes))
    elif kind is Kind.HYPOTHESIS:
        if not args.text or not args.answers:
            raise RecordError("a hypothesis needs --text and --answers")
        body = {"text": args.text}
        edges.append((EdgeType.ANSWERS, args.answers))
    elif kind is Kind.CHALLENGE:
        if not args.text or not args.target or not args.evidence:
            raise RecordError("a challenge needs --text (the reason), --target and at least one --evidence")
        record = lab.file_challenge(args.target, args.text, actor, [{"type": "evidence_ref", "ref": ref} for ref in args.evidence])
        return {"record": record.to_dict(), "edges": [{"edge": EdgeType.CHALLENGES.value, "to": args.target}]}
    else:
        if not args.text or not args.label:
            raise RecordError("evidence needs --text and --label")
        if not (args.supports or args.contradicts or args.cites):
            raise RecordError("evidence needs at least one of --supports, --contradicts, --cites")
        body = {"text": args.text}
        label = EvidenceLabel(args.label)
        if args.supports:
            edges.append((EdgeType.SUPPORTS, args.supports))
        if args.contradicts:
            edges.append((EdgeType.CONTRADICTS, args.contradicts))
        if args.cites:
            edges.append((EdgeType.CITES, args.cites))
    record = lab.add(kind, body, actor, edges=edges, evidence_label=label)
    return {"record": record.to_dict(), "edges": [{"edge": edge.value, "to": to} for edge, to in edges]}


def _show(lab: Lab, args: argparse.Namespace) -> dict:
    node = lab.graph.node(args.entity)
    return {
        "entity_id": node.entity_id,
        "kind": node.kind.value,
        "status": node.status,
        "author": node.author.to_dict(),
        "history": [
            {"version": record.version, "disposition": record.disposition, "created_at": record.created_at,
             "origin": record.origin.to_dict(), "provenance": list(record.provenance), "digest": record.digest}
            for record in node.versions
        ],
        "body": node.latest.body,
        "edges_out": [edge.to_dict() for edge in lab.graph.edges_from(node.entity_id)],
        "edges_in": [edge.to_dict() for edge in lab.graph.edges_to(node.entity_id)],
        "open_challenges": [c.entity_id for c in lab.graph.open_challenges(node.entity_id)],
        "challenges": lab.graph.challenge_summary(node.entity_id),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            principals = [args.principal, *args.entitle]
            with Lab.create(args.db, args.tenant, _principal(args), args.issuer, _clock(args), principals) as lab:
                _emit({"created": args.db, "genesis": lab.store.genesis(), "head_hash": lab.store.head().hash})
            return 0
        if args.command == "verify":
            # Opened as a bare store, not a Lab, so a store that fails verification is reported
            # rather than refused at open. verify_store adds the policy replay.
            with EventStore.open(args.db, args.tenant, _principal(args)) as store:
                result = verify_store(store)
            _emit(result.to_dict())
            return 0 if result.ok else 1
        with Lab.open(args.db, args.tenant, _principal(args), _clock(args)) as lab:
            if args.command == "add":
                _emit(_add(lab, args))
            elif args.command == "transition":
                record = lab.transition(args.entity, args.to, _actor(args), args.reason)
                _emit({"record": record.to_dict()})
            elif args.command == "show":
                _emit(_show(lab, args))
            elif args.command == "export":
                info = export_bundle(lab.store, args.out)
                _emit(info.to_dict())
        return 0
    except (StoreError, LifecycleError, GraphError, RecordError, ValueError) as exc:
        sys.stderr.write(json.dumps({"error": type(exc).__name__, "message": str(exc)}) + "\n")
        return 1
