"""Thin command line: init, add, transition, show, verify, export, governance.

Every command prints one JSON document to stdout. Refusals print a JSON error to stderr and
exit 1. Usage errors exit 2 (argparse). The principal is a claim: --principal names it and the
store checks it against the genesis entitlement set.

Governance. `init --issuer ID:KIND:PUBKEYHEX` enrolls a governance public key (AUTHENTICATED
mode, the default). `governance sign-bytes` prints the bytes an external signer must sign
for one disposition; `governance apply --grant FILE` submits the signed grant. This command
line never generates a key and never reads, holds or asks for a private key.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import warnings
from typing import Any, Sequence

from . import __version__
from .clock import Clock, FixedClock, SystemClock
from .export import export_bundle
from .governance import (
    LEGACY_WARNING,
    MODE_AUTHENTICATED,
    MODE_LEGACY,
    NONCE_MIN_BYTES,
    GovernanceError,
    UnauthenticatedGovernanceWarning,
    grant_digest,
    grant_signing_bytes,
    make_issuer,
)
from .graph import EdgeType, GraphError
from .lab import Lab, verify_store
from .lifecycle import LifecycleError
from .records import Actor, ActorKind, EvidenceLabel, Kind, RecordError
from .sources import FixtureTransport, GitHubSource, LocalFileSource, SourceError, urllib_transport
from .store import EventStore, Principal, StoreError

ADDABLE = ("objective", "question", "hypothesis", "evidence", "challenge", "source")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, help="path to the SQLite store")
    parser.add_argument("--tenant", required=True, help="tenant the store belongs to")
    parser.add_argument("--principal", required=True, help="principal id (a claim; checked against genesis)")
    parser.add_argument("--at", default=None, help="timestamp YYYY-MM-DDTHH:MM:SSZ; default is the wall clock")
    parser.add_argument("--blob-root", default=None, help="blob store directory for sources; default is <db>.blobs")


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
    p_init.add_argument(
        "--issuer",
        action="append",
        default=[],
        help="governance issuer to enroll as ID:KIND:PUBKEYHEX (repeatable): KIND is human_body or system, "
        "PUBKEYHEX is the 32-byte Ed25519 public key in lowercase hex. With --unauthenticated-governance, a plain issuer id.",
    )
    p_init.add_argument(
        "--unauthenticated-governance",
        action="store_true",
        help="explicit opt-out: create the store in UNAUTHENTICATED_LEGACY mode, where a governance disposition is "
        "authorized by a claimed actor kind and a public issuer id instead of a signature. Recorded in the genesis.",
    )
    p_init.add_argument("--grant-skew-seconds", type=int, default=None, help="how far in the future a grant's issued_at may be (default 300)")
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
    p_add.add_argument("--kind", dest="source_kind", default=None, choices=["github", "file"], help="source adapter (source)")
    p_add.add_argument("--repo", default=None, help="owner/name of a GitHub repository (source --kind github)")
    p_add.add_argument("--path", default=None, help="file path in the repository, or absolute local path (source)")
    p_add.add_argument("--ref", default=None, help="branch, tag or commit sha; default is the repository's default branch")
    p_add.add_argument("--allow-root", action="append", default=[], help="allowed root for local files (repeatable, required for --kind file)")
    p_add.add_argument(
        "--github-fixtures",
        default=None,
        help="offline mode: serve GitHub responses from this directory of recorded fixtures instead of the network",
    )

    p_tr = sub.add_parser("transition", help="move an entity to a new status (lab transitions only)")
    _common(p_tr)
    _actor_args(p_tr)
    p_tr.add_argument("--entity", required=True)
    p_tr.add_argument("--to", required=True)
    p_tr.add_argument("--reason", required=True)

    p_show = sub.add_parser("show", help="show an entity, its history and edges")
    _common(p_show)
    p_show.add_argument("--entity", required=True)

    p_verify = sub.add_parser("verify", help="verify the store's hash chain, tenant, lab policy and governance grants")
    _common(p_verify)
    p_verify.add_argument("--expect-genesis-hash", default=None, help="fail unless the genesis event has this hash (pin it out of band)")
    p_verify.add_argument("--require-authenticated", action="store_true", help="fail unless the store is AUTHENTICATED")

    p_export = sub.add_parser("export", help="write a verified JSON-lines bundle")
    _common(p_export)
    p_export.add_argument("--out", required=True)

    p_gov = sub.add_parser("governance", help="signed governance grants (AUTHENTICATED stores)")
    gov_sub = p_gov.add_subparsers(dest="governance_command", required=True)
    p_bytes = gov_sub.add_parser(
        "sign-bytes", help="print the exact bytes an external signer must sign for one disposition (signs nothing)"
    )
    _common(p_bytes)
    p_bytes.add_argument("--entity", required=True, help="finding or challenge id; its current version is the one disposed")
    p_bytes.add_argument("--to", required=True, help="ACCEPTED, ADMITTED, WITHDRAWN, UPHELD or DISMISSED")
    p_bytes.add_argument("--issuer-id", required=True, help="the enrolled issuer that will sign")
    p_bytes.add_argument("--reason", required=True)
    p_bytes.add_argument("--nonce", default=None, help="16 to 32 bytes of lowercase hex, single use; default is 16 fresh random bytes")
    p_bytes.add_argument("--issued-at", default=None, help="default is the clock (--at or the wall clock)")
    p_bytes.add_argument("--expires-at", default=None, help="default is issued-at plus 24 hours")
    p_apply = gov_sub.add_parser("apply", help="submit a signed grant; the submitting actor may be anyone")
    _common(p_apply)
    _actor_args(p_apply)
    p_apply.add_argument("--grant", required=True, help="path of a JSON file: the grant fields plus signature (128 hex)")
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
    elif kind is Kind.SOURCE:
        return _add_source(lab, args, actor)
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


def _add_source(lab: Lab, args: argparse.Namespace, actor: Actor) -> dict:
    if args.source_kind == "github":
        if not args.repo or "/" not in args.repo or not args.path:
            raise RecordError("a github source needs --repo owner/name and --path")
        owner, _, name = args.repo.partition("/")
        transport = FixtureTransport(args.github_fixtures) if args.github_fixtures else urllib_transport
        document = GitHubSource(transport, lab.clock).fetch_file(owner, name, args.path, args.ref)
    elif args.source_kind == "file":
        if not args.path or not args.allow_root:
            raise RecordError("a file source needs --path and at least one --allow-root")
        document = LocalFileSource(args.allow_root, lab.clock).fetch(args.path)
    else:
        raise RecordError("a source needs --kind github or --kind file")
    done = lab.record_source(document, actor)
    return {
        "record": done.record.to_dict(),
        "created": done.created,
        "changed": done.changed,
        "previous": done.previous_id,
        "blob_digest": done.record.body["blob_digest"],
        "offline_fixtures": bool(args.source_kind == "github" and args.github_fixtures),
    }


def _parse_issuers(args: argparse.Namespace) -> tuple[list[Any], str]:
    """--issuer values as genesis issuers, and the governance mode they imply."""
    if args.unauthenticated_governance:
        return list(args.issuer), MODE_LEGACY
    records = []
    for value in args.issuer:
        parts = value.rsplit(":", 2)
        if len(parts) != 3 or not all(parts):
            raise GovernanceError(
                f"--issuer {value!r} is not ID:KIND:PUBKEYHEX. A new store is AUTHENTICATED and enrolls a public key "
                "per issuer; a plain issuer id is accepted only with --unauthenticated-governance"
            )
        records.append(make_issuer(parts[0], parts[1], parts[2]))
    return records, MODE_AUTHENTICATED


def _mode_note(mode: str) -> dict[str, Any]:
    out: dict[str, Any] = {"governance_mode": mode}
    if mode == MODE_LEGACY:
        out["governance_warning"] = LEGACY_WARNING
    return out


def _sign_bytes(lab: Lab, args: argparse.Namespace) -> dict:
    if lab.governance_mode != MODE_AUTHENTICATED:
        raise GovernanceError(f"this store's governance mode is {lab.governance_mode}: it enrolls no keys, so there is nothing to sign for")
    issuer = lab.graph.governance_keys.get(args.issuer_id)
    if issuer is None:
        raise GovernanceError(f"issuer {args.issuer_id!r} is not enrolled in the genesis governance issuer set")
    nonce = args.nonce if args.nonce is not None else secrets.token_hex(NONCE_MIN_BYTES)
    grant = lab.grant_template(args.entity, args.to, args.issuer_id, args.reason, nonce, args.issued_at, args.expires_at)
    data = grant_signing_bytes(grant)
    return {
        "grant": grant,
        "nonce_source": "given" if args.nonce is not None else "generated",
        "signing_bytes_hex": data.hex(),
        "signing_bytes_utf8": data.decode("ascii"),
        "grant_digest": grant_digest(grant),
        "sign_with": {name: issuer[name] for name in ("issuer_id", "kind", "alg", "key_id", "public_key")},
        "current_status": lab.graph.node(args.entity).status,
        "next": "sign signing_bytes_hex (the raw bytes, not the hex text) with Ed25519 outside this tool, add the "
        "128-hex signature to the grant object as \"signature\", and submit it with: governance apply --grant FILE",
    }


def _apply_grant(lab: Lab, args: argparse.Namespace) -> dict:
    try:
        with open(args.grant, encoding="utf-8") as handle:
            grant = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"cannot read grant file {args.grant!r}: {exc}") from exc
    record = lab.apply_grant(grant, _actor(args))
    return {"record": record.to_dict(), "governance": lab.graph.dispositions[-1]}


def _blob_root(args: argparse.Namespace) -> str | None:
    """The blob root given, else <db>.blobs when it exists or is about to be created."""
    if args.blob_root:
        return args.blob_root
    default = os.path.abspath(args.db + ".blobs")
    if os.path.isdir(default) or (args.command == "add" and args.kind == "source"):
        return default
    return None


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
        "ai_calls": [item for record in node.versions for item in record.provenance if item.get("type") == "ai_call"],
        "citations": node.latest.body.get("citations", []),
        "contradictions": [c.entity_id for c in lab.graph.contradictions_involving(node.entity_id)],
        **_mode_note(lab.governance_mode),
        "governance_dispositions": [item for item in lab.graph.dispositions if item["entity_id"] == node.entity_id],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            principals = [args.principal, *args.entitle]
            issuers, mode = _parse_issuers(args)
            options: dict[str, Any] = {"governance_mode": mode}
            if args.grant_skew_seconds is not None:
                options["grant_skew_seconds"] = args.grant_skew_seconds
            if mode == MODE_LEGACY:
                sys.stderr.write(json.dumps({"warning": "UnauthenticatedGovernance", "message": LEGACY_WARNING}) + "\n")
            with warnings.catch_warnings():
                # The CLI has just printed the same warning as JSON; do not print it twice.
                warnings.simplefilter("ignore", UnauthenticatedGovernanceWarning)
                lab = Lab.create(args.db, args.tenant, _principal(args), issuers, _clock(args), principals, **options)
            with lab:
                _emit({"created": args.db, "genesis": lab.store.genesis(), "head_hash": lab.store.head().hash, **_mode_note(mode)})
            return 0
        if args.command == "verify":
            # Opened as a bare store, not a Lab, so a store that fails verification is reported
            # rather than refused at open. verify_store adds the policy replay.
            with EventStore.open(args.db, args.tenant, _principal(args)) as store:
                result = verify_store(
                    store, expected_genesis_hash=args.expect_genesis_hash, require_authenticated=args.require_authenticated
                )
                try:
                    mode_note = _mode_note(store.governance_mode)  # from the genesis as stored, verified or not
                except StoreError:
                    mode_note = {"governance_mode": None}
            output = {**result.to_dict(), **mode_note}
            blob_root = _blob_root(args)
            sources_ok = True
            if result.ok and blob_root is not None:
                with Lab.open(args.db, args.tenant, _principal(args), _clock(args), blob_root=blob_root) as lab:
                    sources = lab.verify_sources()
                output["sources"] = sources.to_dict()
                sources_ok = sources.ok
            elif result.ok:
                output["sources"] = {"checked": 0, "skipped": "no blob store: give --blob-root or create <db>.blobs"}
            _emit(output)
            return 0 if result.ok and sources_ok else 1
        blob_root = _blob_root(args) if args.command == "add" else None
        with Lab.open(args.db, args.tenant, _principal(args), _clock(args), blob_root=blob_root) as lab:
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
            elif args.command == "governance" and args.governance_command == "sign-bytes":
                _emit(_sign_bytes(lab, args))
            elif args.command == "governance":
                _emit(_apply_grant(lab, args))
        return 0
    except (StoreError, LifecycleError, GraphError, RecordError, SourceError, ValueError) as exc:
        sys.stderr.write(json.dumps({"error": type(exc).__name__, "message": str(exc)}) + "\n")
        return 1
