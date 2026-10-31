"""TypeSafe jev(System One)客户端，见 https://docs.typesafe.ai/api"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from enum import StrEnum

import httpx

logger = logging.getLogger(__name__)

IMAGES_HEADER = "TypeSafe-Danger-Zone-Images"
# 余额不足时的返回格式没有公开文档，先按关键词宽泛匹配
KEY_ERROR_WORDS = ("quota", "balance", "credit", "billing", "insufficient", "payment")
MAX_RETRY_AFTER_SECONDS = 10.0


class ErrorKind(StrEnum):
    # token 无效、无权限或余额不足：立即关闭
    KEY = "key"
    # 请求格式问题(400/422)：不算 token 失败
    BAD_REQUEST = "bad_request"
    # 限流(429/529)：不算 token 失败
    RATE_LIMITED = "rate_limited"
    # 其他一切：计一次失败，连续多次后关闭
    FAILURE = "failure"


class JevError(Exception):
    def __init__(self, kind: ErrorKind, message: str, status: int | None = None, *, retry_after: float = 1.0) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status
        self.retry_after = retry_after

    def describe(self) -> str:
        prefix = f"HTTP {self.status}: " if self.status is not None else ""
        return f"{prefix}{self.message}"


def classify_error(status: int, body: str) -> ErrorKind:
    if status in {401, 402, 403} or any(word in body.lower() for word in KEY_ERROR_WORDS):
        return ErrorKind.KEY
    if status in {400, 422}:
        return ErrorKind.BAD_REQUEST
    if status in {429, 529}:
        return ErrorKind.RATE_LIMITED
    return ErrorKind.FAILURE


@dataclass(frozen=True, slots=True)
class Question:
    name: str
    instructions: str
    yes: str
    no: str

    def to_json(self) -> dict[str, object]:
        return {"type": "noul", "instructions": self.instructions, "criteria": {"true": self.yes, "false": self.no}}


@dataclass(frozen=True, slots=True)
class Image:
    data: bytes
    format: str

    @classmethod
    def detect(cls, data: bytes) -> Image | None:
        """jev 只接受 png/jpeg，其他格式(如贴纸的 webp)直接丢弃。"""
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return cls(data, "png")
        if data.startswith(b"\xff\xd8\xff"):
            return cls(data, "jpeg")
        return None


@dataclass(frozen=True, slots=True)
class JevResult:
    answers: dict[str, float]
    input_tokens: int


class JevClient:
    def __init__(self, http: httpx.AsyncClient, *, url: str, model: str, timeout: float) -> None:
        self.http = http
        self.url = url
        self.model = model
        self.timeout = timeout

    async def evaluate(
        self,
        api_key: str,
        state: object,
        questions: list[Question],
        images: dict[str, Image] | None = None,
    ) -> JevResult:
        payload: dict[str, object] = {
            "model": self.model,
            "state": state,
            "questions": {question.name: question.to_json() for question in questions},
        }
        headers = {"Authorization": f"Bearer {api_key}"}
        if images:
            payload["assets"] = {
                name: {"type": "image", "format": image.format, "data_base64": base64.b64encode(image.data).decode()}
                for name, image in images.items()
            }
            headers[IMAGES_HEADER] = "true"
        try:
            return await self._post(payload, headers)
        except JevError as exc:
            if exc.kind != ErrorKind.RATE_LIMITED:
                raise
            await asyncio.sleep(exc.retry_after)
            return await self._post(payload, headers)

    async def _post(self, payload: dict[str, object], headers: dict[str, str]) -> JevResult:
        try:
            response = await self.http.post(self.url, json=payload, headers=headers, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise JevError(ErrorKind.FAILURE, f"{type(exc).__name__}: {exc}".rstrip(": ")) from exc
        if response.status_code != 200:
            body = response.text[:500]
            raise JevError(
                classify_error(response.status_code, body),
                body or response.reason_phrase,
                response.status_code,
                retry_after=_retry_after(response),
            )
        try:
            data = response.json()
            answers = {
                name: float(answer["noul"]) for name, answer in data["answers"].items() if answer.get("type") == "noul"
            }
            usage = data.get("usage") or {}
            input_tokens = int(usage.get("input_tokens") or 0)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise JevError(ErrorKind.FAILURE, f"无法解析 jev 响应: {response.text[:200]}", 200) from exc
        return JevResult(answers, input_tokens)


def _retry_after(response: httpx.Response) -> float:
    try:
        return min(float(response.headers.get("Retry-After", "1")), MAX_RETRY_AFTER_SECONDS)
    except ValueError:
        return 1.0
