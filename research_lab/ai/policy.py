"""Provider policy: which provider kinds a deployment allows the investigation to call.

The policy is supplied by the deploying code, not fixed in genesis. Moving it into the
tamper-evident genesis configuration is a later hardening. Under STACK_PROFILE only the
WATCHER_MCU kind is allowed: WatcherAIPort (research_lab/ai/watcher.py) is of that kind,
and an investigation that names any other port is refused before any provider is called.
"""

from __future__ import annotations

from dataclasses import dataclass

from .port import AIPort, ProviderRefused

WATCHER_MCU_KIND = "watcher_mcu"


@dataclass(frozen=True)
class ProviderPolicy:
    name: str
    allowed_kinds: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("policy name must be a non-empty string")
        object.__setattr__(self, "allowed_kinds", frozenset(self.allowed_kinds))

    def allows(self, provider_kind: str) -> bool:
        return provider_kind in self.allowed_kinds


STACK_PROFILE = ProviderPolicy("stack", frozenset({WATCHER_MCU_KIND}))
STANDALONE_DEV_PROFILE = ProviderPolicy("standalone-dev", frozenset({"replay", "deterministic_baseline"}))


def check_port_allowed(port: AIPort, policy: ProviderPolicy) -> None:
    """Raise ProviderRefused unless the policy allows the port's provider kind."""
    if not policy.allows(port.provider_kind):
        raise ProviderRefused(
            f"policy profile {policy.name!r} does not allow provider kind {port.provider_kind!r} "
            f"(port {port.provider_id!r}); allowed kinds: {sorted(policy.allowed_kinds)}"
        )
