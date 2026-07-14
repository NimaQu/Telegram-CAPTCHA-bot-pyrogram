from __future__ import annotations

import logging
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Protocol

import httpx

from captcha_bot.config import ConfigStore, DefaultPolicy
from captcha_bot.db.repository import GroupOverrides

logger = logging.getLogger(__name__)


class PolicyRepository(Protocol):
    def get_group_overrides(self, group_id: int) -> Awaitable[GroupOverrides | None]: ...


class PolicyService:
    def __init__(self, config: ConfigStore, repository: PolicyRepository) -> None:
        self.config = config
        self.repository = repository

    async def get(self, chat_id: int) -> DefaultPolicy:
        defaults = self.config.settings.defaults
        override = await self.repository.get_group_overrides(chat_id)
        if override is None:
            return defaults
        return defaults.model_copy(update=_override_values(override))


def _override_values(override: GroupOverrides) -> dict[str, object]:
    return {
        "challenge_timeout": override.challenge_timeout,
        "challenge_timeout_action": override.challenge_timeout_action,
        "challenge_failed_action": override.challenge_failed_action,
        "challenge_type": override.challenge_type,
        "enable_global_blacklist": override.enable_global_blacklist,
    }


@dataclass(frozen=True, slots=True)
class TurnstileResult:
    success: bool
    error_codes: tuple[str, ...] = ()


class TurnstileService:
    def __init__(self, client: httpx.AsyncClient, config: ConfigStore) -> None:
        self.client = client
        self.config = config

    async def verify(self, response_token: str, remote_ip: str) -> TurnstileResult:
        settings = self.config.settings.turnstile
        try:
            response = await self.client.post(
                settings.verify_url,
                data={
                    "response": response_token,
                    "secret": settings.secret_key.get_secret_value(),
                    "remoteip": remote_ip,
                },
                timeout=settings.timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError, ValueError, TypeError:
            logger.exception("Turnstile verification request failed")
            return TurnstileResult(False, ("verification-unavailable",))
        errors = tuple(str(value) for value in payload.get("error-codes", []))
        return TurnstileResult(bool(payload.get("success")), errors)
