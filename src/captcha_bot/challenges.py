from __future__ import annotations

import asyncio
import logging
import random
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum

from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup

logger = logging.getLogger(__name__)


class ChallengeKind(StrEnum):
    MATH = "math"
    TURNSTILE = "turnstile"
    AUTO_KICK = "auto_kick"


@dataclass(slots=True)
class ChallengeSession:
    key: str
    kind: ChallengeKind
    chat_id: int
    user_id: int
    chat_title: str
    message_id: int | None = None
    answer: int | None = None
    turnstile_id: str | None = None
    join_request: bool = False
    timeout_task: asyncio.Task[None] | None = field(default=None, repr=False)


TimeoutCallback = Callable[[ChallengeSession], Awaitable[None]]


class ChallengeRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ChallengeSession] = {}
        self._turnstile_keys: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def register(self, session: ChallengeSession, delay_seconds: float, callback: TimeoutCallback) -> bool:
        async with self._lock:
            if session.key in self._sessions or any(
                existing.chat_id == session.chat_id and existing.user_id == session.user_id
                for existing in self._sessions.values()
            ):
                return False
            self._sessions[session.key] = session
            if session.turnstile_id:
                self._turnstile_keys[session.turnstile_id] = session.key
            session.timeout_task = asyncio.create_task(
                self._run_timeout(session.key, delay_seconds, callback),
                name=f"challenge-timeout:{session.key}",
            )
            return True

    async def _run_timeout(self, key: str, delay_seconds: float, callback: TimeoutCallback) -> None:
        try:
            await asyncio.sleep(delay_seconds)
            session = await self.claim(key, cancel_timeout=False)
            if session is not None:
                await callback(session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("challenge timeout failed", extra={"challenge_key": key})

    async def get(self, key: str) -> ChallengeSession | None:
        async with self._lock:
            return self._sessions.get(key)

    async def get_by_turnstile_id(self, turnstile_id: str) -> ChallengeSession | None:
        async with self._lock:
            key = self._turnstile_keys.get(turnstile_id)
            return self._sessions.get(key) if key else None

    async def find(self, user_id: int, chat_id: int) -> ChallengeSession | None:
        async with self._lock:
            return next(
                (
                    session
                    for session in self._sessions.values()
                    if session.user_id == user_id and session.chat_id == chat_id
                ),
                None,
            )

    async def claim(self, key: str, *, cancel_timeout: bool = True) -> ChallengeSession | None:
        async with self._lock:
            session = self._sessions.pop(key, None)
            if session is None:
                return None
            if session.turnstile_id:
                self._turnstile_keys.pop(session.turnstile_id, None)
            task = session.timeout_task
            if cancel_timeout and task and task is not asyncio.current_task() and not task.done():
                task.cancel()
            return session

    async def claim_by_turnstile_id(self, turnstile_id: str) -> ChallengeSession | None:
        async with self._lock:
            key = self._turnstile_keys.get(turnstile_id)
        return await self.claim(key) if key else None

    async def contains_user(self, user_id: int, chat_id: int) -> bool:
        return await self.find(user_id, chat_id) is not None

    async def shutdown(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._turnstile_keys.clear()
        tasks = [
            session.timeout_task for session in sessions if session.timeout_task and not session.timeout_task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def count(self) -> int:
        async with self._lock:
            return len(self._sessions)


class MathChallenge:
    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.SystemRandom()
        operation = self._rng.choice(["加上(plus)", "减去(minus)", "乘以(time)", "除以(divide)"])
        if operation in {"加上(plus)", "减去(minus)"}:
            a, b = sorted((self._rng.randint(0, 50), self._rng.randint(0, 50)), reverse=True)
            answer = a + b if operation == "加上(plus)" else a - b
        elif operation == "乘以(time)":
            a, b = self._rng.randint(0, 9), self._rng.randint(0, 9)
            answer = a * b
        else:
            answer, b = self._rng.randint(0, 9), self._rng.randint(1, 9)
            a = answer * b
        choices = self._rng.sample(range(100), self._rng.randint(3, 5))
        if answer not in choices:
            choices[0] = answer
        self._rng.shuffle(choices)
        self.a, self.b, self.operation, self.answer, self.choices = a, b, operation, answer, choices

    @property
    def question(self) -> str:
        return (
            f"{self.a} {self.operation} {self.b} 的结果是多少？\n"
            f"What is the result of {self.a} {self.operation} {self.b}"
        )

    def group_keyboard(self, approve: str, refuse: str) -> InlineKeyboardMarkup:
        answers = [InlineKeyboardButton(str(choice), callback_data=str(choice).encode()) for choice in self.choices]
        return InlineKeyboardMarkup(
            [
                answers,
                [InlineKeyboardButton(approve, callback_data=b"+"), InlineKeyboardButton(refuse, callback_data=b"-")],
            ]
        )

    def join_request_keyboard(self, chat_id: int) -> InlineKeyboardMarkup:
        answers = [
            InlineKeyboardButton(str(choice), callback_data=f"{choice}|{chat_id}".encode()) for choice in self.choices
        ]
        return InlineKeyboardMarkup([answers])


def new_turnstile_id() -> str:
    return uuid.uuid4().hex


def turnstile_auth_url(base_url: str, turnstile_id: str) -> str:
    return f"{base_url.rstrip('/')}/recaptcha?challenge={turnstile_id}"


def turnstile_auth_keyboard(url: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(text="开始验证", url=url)]])


def turnstile_group_keyboard(bot_username: str, chat_id: int, approve: str, refuse: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(text="开始验证", url=f"https://t.me/{bot_username}?start={chat_id}")],
            [InlineKeyboardButton(approve, callback_data=b"+"), InlineKeyboardButton(refuse, callback_data=b"-")],
        ]
    )
