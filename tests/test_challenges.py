from __future__ import annotations

import asyncio
import random

import pytest

from captcha_bot.challenges import ChallengeKind, ChallengeRegistry, ChallengeSession, MathChallenge


def session(key: str = "-1|1", *, token: str | None = "token") -> ChallengeSession:
    return ChallengeSession(key, ChallengeKind.TURNSTILE, -1, 1, "chat", turnstile_id=token)


@pytest.mark.asyncio
async def test_registry_claim_is_single_use_and_cancels_timeout() -> None:
    registry = ChallengeRegistry()
    called: list[str] = []

    async def timeout(item: ChallengeSession) -> None:
        called.append(item.key)

    item = session()
    assert await registry.register(item, 10, timeout)
    assert not await registry.register(session(), 10, timeout)
    assert await registry.find(1, -1) is item
    assert await registry.get_by_turnstile_id("token") is item
    assert await registry.claim_by_turnstile_id("token") is item
    assert await registry.claim(item.key) is None
    await asyncio.sleep(0)
    assert called == []


@pytest.mark.asyncio
async def test_registry_timeout_claims_before_callback() -> None:
    registry = ChallengeRegistry()
    finished = asyncio.Event()

    async def timeout(item: ChallengeSession) -> None:
        assert await registry.get(item.key) is None
        finished.set()

    assert await registry.register(session(), 0, timeout)
    await asyncio.wait_for(finished.wait(), timeout=1)
    assert await registry.count() == 0


@pytest.mark.asyncio
async def test_registry_shutdown_cancels_everything() -> None:
    registry = ChallengeRegistry()

    async def timeout(_item: ChallengeSession) -> None:
        raise AssertionError("must not run")

    await registry.register(session("a", token="a"), 60, timeout)
    await registry.register(ChallengeSession("b", ChallengeKind.MATH, -2, 2, "b"), 60, timeout)
    await registry.shutdown()
    assert await registry.count() == 0


def test_math_challenge_has_answer_and_keyboards() -> None:
    challenge = MathChallenge(random.Random(42))
    assert challenge.answer in challenge.choices
    assert "What is the result" in challenge.question
    assert len(challenge.group_keyboard("yes", "no").inline_keyboard) == 2
    callback = challenge.join_request_keyboard(-123).inline_keyboard[0][0].callback_data
    assert callback
    assert callback.endswith(b"|-123") if isinstance(callback, bytes) else callback.endswith("|-123")
