"""The AI port: one provider-neutral contract through which all AI interaction passes.

No vendor SDK lives in this package. Three implementations ship: ReplayAIPort (recorded,
synthetic test data), ExtractiveBaselinePort (deterministic keyword extraction, not a
model) and WatcherAIPort, an adapter that sends the request through WATCHER_MCU's generic
port as plain mappings without importing WATCHER_MCU. No live call has been made through
it; see docs/WATCHER_MCU_PORT.md for the contract, the wire format and the conformance suite.

AI output is always a proposal. It enters the lab as AI-origin records whose citations are
checked against preserved sources; a verbatim quote proves the source contains the words,
not that the claim is true.
"""

from .baseline import ExtractiveBaselinePort
from .citations import MIN_QUOTE_CHARS, MIN_QUOTE_TOKENS, UNVERIFIED, VERIFIED, CitationCheck, normalize_ws, verify_citations
from .conformance import ConformanceResult, assert_conformant, run_conformance
from .outputs import Cite, HypothesisProposal, Proposals, parse_proposals, render_proposals
from .policy import STACK_PROFILE, STANDALONE_DEV_PROFILE, WATCHER_MCU_KIND, ProviderPolicy, check_port_allowed
from .port import (
    AIError,
    AIPort,
    AIRequest,
    AIResponse,
    ProviderRefused,
    ProviderTimeout,
    ProviderUnavailable,
    ResponseFormatError,
    SourceInput,
)
from .replay import RECORDING_SCHEMA, SYNTHETIC_ORIGIN, ReplayAIPort, write_recording
from .watcher import WatcherAIPort, load_watcher_call

__all__ = [
    "AIError",
    "AIPort",
    "AIRequest",
    "AIResponse",
    "Cite",
    "CitationCheck",
    "ConformanceResult",
    "ExtractiveBaselinePort",
    "HypothesisProposal",
    "MIN_QUOTE_CHARS",
    "MIN_QUOTE_TOKENS",
    "Proposals",
    "ProviderPolicy",
    "ProviderRefused",
    "ProviderTimeout",
    "ProviderUnavailable",
    "RECORDING_SCHEMA",
    "ReplayAIPort",
    "ResponseFormatError",
    "STACK_PROFILE",
    "STANDALONE_DEV_PROFILE",
    "SYNTHETIC_ORIGIN",
    "SourceInput",
    "UNVERIFIED",
    "VERIFIED",
    "WATCHER_MCU_KIND",
    "WatcherAIPort",
    "assert_conformant",
    "check_port_allowed",
    "load_watcher_call",
    "normalize_ws",
    "parse_proposals",
    "render_proposals",
    "run_conformance",
    "verify_citations",
    "write_recording",
]
