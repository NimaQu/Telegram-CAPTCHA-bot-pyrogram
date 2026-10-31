"""按群 AI 反垃圾：分类器定义、群配置、jev 调用与判定。"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import StrEnum
from typing import Self

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from captcha_bot.config import AntispamSettings, ConfigStore
from captcha_bot.db.repository import AntispamRecord, AntispamRules, Repository
from captcha_bot.jev import ErrorKind, Image, JevClient, JevError, JevResult, Question

logger = logging.getLogger(__name__)

# 通过验证后多久内的第一条消息才送检
PENDING_MAX_AGE = timedelta(days=30)
MAX_MESSAGE_IMAGES = 4
MAX_TEXT_LENGTH = 2000
# 连续失败这么多次，或从第一次失败起这么久都没成功过，就自动关闭
FAILURE_LIMIT = 3
FAILURE_WINDOW = timedelta(minutes=30)


class AntispamAction(StrEnum):
    DELETE = "delete"
    MUTE = "mute"
    KICK = "kick"
    BAN = "ban"


ACTION_LABELS = {
    AntispamAction.DELETE: "仅删除消息",
    AntispamAction.MUTE: "删除并禁言",
    AntispamAction.KICK: "删除并移出群组",
    AntispamAction.BAN: "删除并封禁",
}


@dataclass(frozen=True, slots=True)
class Classifier:
    id: str
    name: str
    yes: str
    no: str
    default_enabled: bool


BUILTIN_CLASSIFIERS: tuple[Classifier, ...] = (
    Classifier(
        "ad",
        "广告引流",
        "推广频道、群组、网站或其他平台，拉人进群、让人加好友或私聊",
        "正常聊天、提问，或分享与讨论内容相关的链接",
        True,
    ),
    Classifier(
        "scam",
        "诈骗钓鱼",
        "虚假投资、刷单返利、冒充官方或客服、钓鱼链接、索要账号或验证码",
        "没有欺骗或诱导意图的正常内容",
        True,
    ),
    Classifier("porn", "色情", "色情内容、色情引流或招嫖", "不含色情内容", True),
    Classifier(
        "gambling",
        "博彩/币圈喊单",
        "博彩、代币推广、带单喊单、空投拉人头",
        "正常讨论加密货币或游戏，没有推广或拉人意图",
        True,
    ),
    Classifier(
        "flood",
        "刷屏/无关垃圾",
        "重复的、与群主题无关的，或大量 @ 别人的垃圾信息",
        "与群聊相关的正常发言",
        True,
    ),
    Classifier(
        "trade",
        "商品买卖",
        "消息目的是出售或收购具体商品、账号或虚拟物品，例如带价格、写着「出」「收」、留联系方式或要求私聊交易",
        "只是在聊天中提到商品，例如问别人多少钱买的、讨论值不值得买、分享使用体验",
        False,
    ),
    Classifier(
        "service",
        "服务推广",
        "推销代办、代充、接单、机场或 VPN 等付费服务",
        "只是在聊天中提到或讨论某项服务",
        False,
    ),
)
BUILTIN_BY_ID = {classifier.id: classifier for classifier in BUILTIN_CLASSIFIERS}


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClassifierSetting(StrictPayload):
    enabled: bool = Field(strict=True)
    # 留空时使用群的处置阈值
    threshold: int | None = Field(default=None, ge=1, le=100, strict=True)


class CustomClassifier(StrictPayload):
    name: str = Field(min_length=1, max_length=20)
    yes: str = Field(min_length=1, max_length=200)
    no: str = Field(min_length=1, max_length=200)
    enabled: bool = Field(default=True, strict=True)
    threshold: int | None = Field(default=None, ge=1, le=100, strict=True)

    @field_validator("name", "yes", "no")
    @classmethod
    def strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("不能为空")
        return value


class AntispamConfigModel(StrictPayload):
    builtin: dict[str, ClassifierSetting]
    custom: list[CustomClassifier] = Field(default_factory=list, max_length=3)
    action: AntispamAction = AntispamAction.MUTE
    act_threshold: int = Field(default=85, ge=1, le=100, strict=True)
    log_threshold: int = Field(default=50, ge=0, le=100, strict=True)
    daily_limit: int = Field(default=500, ge=1, le=100_000, strict=True)
    rules: str = Field(default="", max_length=300)
    # 举报需要多少人同意才交给 jev；0 表示关闭 /report
    report_votes: int = Field(default=3, ge=0, le=20, strict=True)

    @field_validator("builtin")
    @classmethod
    def known_classifiers(cls, value: dict[str, ClassifierSetting]) -> dict[str, ClassifierSetting]:
        unknown = set(value) - set(BUILTIN_BY_ID)
        if unknown:
            raise ValueError(f"未知的分类器: {sorted(unknown)}")
        # 缺省的内置分类器按默认开关补齐
        return {
            classifier.id: value.get(classifier.id, ClassifierSetting(enabled=classifier.default_enabled))
            for classifier in BUILTIN_CLASSIFIERS
        }

    @model_validator(mode="after")
    def thresholds_ordered(self) -> Self:
        if self.log_threshold > self.act_threshold:
            raise ValueError("记录阈值不能高于处置阈值")
        return self

    @classmethod
    def defaults(cls, daily_limit: int) -> AntispamConfigModel:
        return cls(builtin={}, daily_limit=daily_limit)

    @classmethod
    def from_record(cls, record: AntispamRecord) -> AntispamConfigModel:
        try:
            stored = json.loads(record.classifiers or "{}")
            return cls(
                builtin=stored.get("builtin", {}),
                custom=stored.get("custom", []),
                action=AntispamAction(record.action),
                act_threshold=record.act_threshold,
                log_threshold=record.log_threshold,
                daily_limit=record.daily_limit,
                rules=record.rules,
                report_votes=record.report_votes,
            )
        except ValueError, ValidationError, AttributeError:
            logger.exception("invalid stored antispam config, using defaults", extra={"chat_id": record.chat_id})
            return cls.defaults(record.daily_limit)

    def to_rules(self) -> AntispamRules:
        classifiers = {
            "builtin": {key: value.model_dump() for key, value in self.builtin.items()},
            "custom": [value.model_dump() for value in self.custom],
        }
        return AntispamRules(
            classifiers=json.dumps(classifiers, ensure_ascii=False),
            action=self.action.value,
            act_threshold=self.act_threshold,
            log_threshold=self.log_threshold,
            daily_limit=self.daily_limit,
            rules=self.rules.strip(),
            report_votes=self.report_votes,
        )


@dataclass(frozen=True, slots=True)
class ActiveClassifier:
    key: str
    name: str
    yes: str
    no: str
    threshold: int


def active_classifiers(config: AntispamConfigModel) -> list[ActiveClassifier]:
    result = [
        ActiveClassifier(
            classifier.id,
            classifier.name,
            classifier.yes,
            classifier.no,
            setting.threshold or config.act_threshold,
        )
        for classifier in BUILTIN_CLASSIFIERS
        if (setting := config.builtin[classifier.id]).enabled
    ]
    result.extend(
        ActiveClassifier(f"custom_{index}", item.name, item.yes, item.no, item.threshold or config.act_threshold)
        for index, item in enumerate(config.custom)
        if item.enabled
    )
    return result


@dataclass(frozen=True, slots=True)
class SpamInput:
    text: str
    sender_name: str
    username: str | None = None
    bio: str | None = None
    forwarded_from: str | None = None
    buttons: tuple[str, ...] = ()
    avatar: Image | None = None
    images: tuple[Image, ...] = field(default_factory=tuple)


def new_member_context(group_title: str) -> str:
    return f"Telegram 群组「{group_title}」中一位刚通过入群验证的新成员发出的第一条消息"


def report_context(group_title: str, votes: int) -> str:
    return f"Telegram 群组「{group_title}」中被 {votes} 位成员举报为垃圾信息的一条消息，举报不一定正确"


def build_request(
    spam: SpamInput,
    config: AntispamConfigModel,
    group_title: str,
    *,
    with_images: bool,
    context: str | None = None,
) -> tuple[dict[str, object], list[Question], dict[str, Image]]:
    assets: dict[str, Image] = {}
    message: dict[str, object] = {"text": spam.text[:MAX_TEXT_LENGTH]}
    if spam.forwarded_from:
        message["forwarded_from"] = spam.forwarded_from
    if spam.buttons:
        message["buttons"] = list(spam.buttons)
    sender: dict[str, object] = {"name": spam.sender_name}
    if spam.username:
        sender["username"] = f"@{spam.username}"
    if spam.bio:
        sender["bio"] = spam.bio
    if with_images:
        if spam.avatar is not None:
            assets["sender_avatar"] = spam.avatar
            sender["avatar"] = "sender_avatar"
        names = []
        for index, image in enumerate(spam.images[:MAX_MESSAGE_IMAGES], start=1):
            name = f"message_image_{index}"
            assets[name] = image
            names.append(name)
        if names:
            message["images"] = names
    state: dict[str, object] = {
        "context": context or new_member_context(group_title),
        "sender": sender,
        "message": message,
    }
    rules = f"本群补充规则：{config.rules}" if config.rules else ""
    questions = [
        Question(
            classifier.key,
            f"这条消息(结合发送者的资料)是否属于「{classifier.name}」？{rules}",
            classifier.yes,
            classifier.no,
        )
        for classifier in active_classifiers(config)
    ]
    return state, questions, assets


@dataclass(frozen=True, slots=True)
class Score:
    classifier: ActiveClassifier
    percent: int

    @property
    def label(self) -> str:
        return f"{self.classifier.name} {self.percent}%"


@dataclass(frozen=True, slots=True)
class Verdict:
    scores: tuple[Score, ...]
    hits: tuple[Score, ...]
    suspect: bool
    input_tokens: int
    images_sent: bool

    @property
    def top(self) -> Score | None:
        return max(self.scores, key=lambda score: score.percent, default=None)

    @property
    def outcome(self) -> str:
        if self.hits:
            return "act"
        return "log" if self.suspect else "pass"


def judge(config: AntispamConfigModel, result: JevResult, *, images_sent: bool) -> Verdict:
    scores = tuple(
        Score(classifier, round(result.answers.get(classifier.key, 0.0) * 100))
        for classifier in active_classifiers(config)
    )
    hits = tuple(score for score in scores if score.percent >= score.classifier.threshold)
    suspect = not hits and any(score.percent >= config.log_threshold for score in scores) and config.log_threshold > 0
    return Verdict(scores, hits, suspect, result.input_tokens, images_sent)


@dataclass(slots=True)
class ReportVote:
    chat_id: int
    message_id: int
    target_user_id: int
    poll_message_id: int
    voters: set[int]
    judging: bool = False


class KeyCipher:
    def __init__(self, secret: str) -> None:
        digest = hashlib.sha256(f"captcha-bot antispam:{secret}".encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, api_key: str) -> str:
        return self._fernet.encrypt(api_key.encode()).decode()

    def decrypt(self, token: str) -> str | None:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return None


def key_last4(api_key: str) -> str:
    return api_key[-4:] if len(api_key) > 8 else ""


class AntispamService:
    def __init__(self, config: ConfigStore, repository: Repository, jev: JevClient) -> None:
        self.config = config
        self.repository = repository
        self.jev = jev
        self._test_calls: dict[int, list[datetime]] = {}
        # 进行中的举报投票，键为 (群 ID, 被举报消息 ID)；重启后丢失，不影响已处置的结果
        self.reports: dict[tuple[int, int], ReportVote] = {}

    @property
    def settings(self) -> AntispamSettings:
        # 每次读取，跟随配置重载
        return self.config.settings.antispam

    @property
    def available(self) -> bool:
        return self.settings.available

    def cipher(self) -> KeyCipher:
        secret = self.settings.secret_key
        if secret is None:
            raise RuntimeError("antispam.secret_key is not configured")
        return KeyCipher(secret.get_secret_value())

    def group_config(self, record: AntispamRecord | None) -> AntispamConfigModel:
        if record is None:
            return AntispamConfigModel.defaults(self.settings.default_daily_limit)
        return AntispamConfigModel.from_record(record)

    def api_key(self, record: AntispamRecord) -> str | None:
        if not self.available or not record.api_key_encrypted:
            return None
        return self.cipher().decrypt(record.api_key_encrypted)

    async def mark_new_member(self, chat_id: int, user_id: int) -> None:
        """通过验证时调用：只为开启了反垃圾的群记录，等他发第一条消息。"""
        if not self.available:
            return
        try:
            record = await self.repository.get_antispam(chat_id)
            if record is not None and record.enabled and record.api_key_encrypted:
                await self.repository.add_antispam_pending(chat_id, user_id, datetime.now())
        except Exception:
            logger.exception("failed to mark new member for antispam", extra={"chat_id": chat_id})

    async def verify_key(self, api_key: str) -> None:
        """保存或开启前用最小请求验证 token；失败时抛出 JevError。"""
        await self.jev.evaluate(api_key, "ping", [Question("ok", "这是一条测试消息吗？", "是", "不是")])

    async def evaluate(
        self,
        api_key: str,
        config: AntispamConfigModel,
        spam: SpamInput,
        group_title: str,
        *,
        context: str | None = None,
    ) -> Verdict:
        with_images = self.settings.send_images and (spam.avatar is not None or bool(spam.images))
        state, questions, assets = build_request(spam, config, group_title, with_images=with_images, context=context)
        if not questions:
            return Verdict((), (), False, 0, False)
        try:
            result = await self.jev.evaluate(api_key, state, questions, assets)
        except JevError as exc:
            if not (exc.kind == ErrorKind.BAD_REQUEST and assets):
                raise
            # 图片输入是实验功能，被拒时退回纯文字再试一次
            logger.warning("jev rejected image request, retrying text only: %s", exc.describe())
            state, questions, _ = build_request(spam, config, group_title, with_images=False, context=context)
            result = await self.jev.evaluate(api_key, state, questions)
            with_images = False
        return judge(config, result, images_sent=with_images)

    def allow_test(self, chat_id: int, now: datetime) -> bool:
        window = [when for when in self._test_calls.get(chat_id, []) if now - when < timedelta(hours=1)]
        if len(window) >= self.settings.test_hourly_limit:
            self._test_calls[chat_id] = window
            return False
        window.append(now)
        self._test_calls[chat_id] = window
        return True

    async def over_daily_limit(self, record: AntispamRecord, today: date) -> bool:
        return await self.repository.antispam_calls(record.chat_id, today) >= record.daily_limit


def should_disable(error: JevError, failure_count: int, first_failure_at: datetime, now: datetime) -> bool:
    if error.kind == ErrorKind.KEY:
        return True
    if error.kind != ErrorKind.FAILURE:
        return False
    return failure_count >= FAILURE_LIMIT or now - first_failure_at >= FAILURE_WINDOW
