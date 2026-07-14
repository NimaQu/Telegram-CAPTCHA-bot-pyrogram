from __future__ import annotations

import asyncio
import json
import os
import string
import tomllib
from configparser import ConfigParser
from enum import StrEnum
from ipaddress import ip_network
from pathlib import Path
from typing import Any, Self

import tomli_w
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class ChallengeType(StrEnum):
    MATH = "math"
    RECAPTCHA = "recaptcha"


class FailedAction(StrEnum):
    BAN = "ban"
    KICK = "kick"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BotSettings(StrictModel):
    username: str = Field(min_length=1)
    token: SecretStr
    api_id: int = Field(gt=0, strict=True)
    api_hash: SecretStr
    admin_ids: tuple[int, ...] = Field(min_length=1)
    log_channel_id: int = Field(strict=True)

    @field_validator("admin_ids", mode="before")
    @classmethod
    def validate_admin_ids(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)) or any(type(item) is not int or item <= 0 for item in value):
            raise ValueError("admin_ids must contain positive integers")
        return value

    @field_validator("log_channel_id")
    @classmethod
    def validate_log_channel_id(cls, value: int) -> int:
        if value == 0:
            raise ValueError("log_channel_id must not be zero")
        return value


class DatabaseSettings(StrictModel):
    url: SecretStr
    pool_size: int = Field(default=5, gt=0, le=50, strict=True)
    max_overflow: int = Field(default=10, ge=0, le=100, strict=True)

    @field_validator("url")
    @classmethod
    def validate_postgresql(cls, value: SecretStr) -> SecretStr:
        url = value.get_secret_value()
        try:
            parsed = make_url(url)
        except ArgumentError as exc:
            raise ValueError("invalid PostgreSQL URL") from exc
        if parsed.drivername not in {"postgresql", "postgresql+psycopg"} or not parsed.database:
            raise ValueError("only PostgreSQL URLs are supported")
        return value


class WebSettings(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=5000, ge=1, le=65535, strict=True)
    debug: bool = Field(default=False, strict=True)
    trusted_proxy_cidrs: tuple[str, ...] = ("127.0.0.1/32", "::1/128")

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            ip_network(value, strict=False)
        return values


class ProxySettings(StrictModel):
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535, strict=True)

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if (self.host is None) != (self.port is None):
            raise ValueError("proxy host and port must be set together")
        return self


class TurnstileSettings(StrictModel):
    site_key: str = Field(min_length=1)
    secret_key: SecretStr
    base_url: str
    verify_url: str = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    timeout_seconds: float = Field(default=10.0, gt=0, le=60, strict=True)

    @field_validator("base_url", "verify_url")
    @classmethod
    def validate_http_url(cls, value: str) -> str:
        return str(TypeAdapter(AnyHttpUrl).validate_python(value)).rstrip("/")


class DefaultPolicy(StrictModel):
    challenge_timeout: int = Field(default=60, gt=0, le=3600, strict=True)
    challenge_timeout_action: FailedAction = FailedAction.KICK
    challenge_failed_action: FailedAction = FailedAction.KICK
    challenge_type: ChallengeType = ChallengeType.MATH
    delete_passed_challenge: bool = Field(default=True, strict=True)
    delete_passed_challenge_interval: int = Field(default=15, ge=0, le=3600, strict=True)
    delete_failed_challenge: bool = Field(default=True, strict=True)
    delete_failed_challenge_interval: int = Field(default=15, ge=0, le=3600, strict=True)
    enable_global_blacklist: bool = Field(default=True, strict=True)
    global_timeout_user_blacklist_remove: int = Field(default=600, gt=0, strict=True)


class Messages(StrictModel):
    start_message: str
    passed_answer: str
    passed_admin: str
    failed_answer: str
    failed_timeout: str
    failed_admin: str
    failed_auto_kick: str
    message_deleted: str
    into_group: str
    leave_group: str
    leave_message: str
    self_introduction: str
    challenge_not_for_you: str
    challenge_math: str
    challenge_math_private: str
    challenge_recaptcha: str
    challenge_passed: str
    challenge_failed: str
    approve_manually: str
    refuse_manually: str
    permission_denied: str
    bot_no_permission: str
    approved: str
    refused: str

    @model_validator(mode="after")
    def validate_placeholders(self) -> Self:
        allowed = {
            "targetuserid",
            "targetusername",
            "targetfirstname",
            "targetlastname",
            "groupid",
            "grouptitle",
            "messageid",
            "lastattempt",
            "sincelastattempt",
            "trycount",
            "target_id",
            "timeout",
            "challenge",
            "user",
        }
        formatter = string.Formatter()
        for name, value in self:
            try:
                fields = {field for _, field, _, _ in formatter.parse(value) if field}
            except ValueError as exc:
                raise ValueError(f"messages.{name} has invalid format syntax") from exc
            unknown = fields - allowed
            if unknown:
                raise ValueError(f"messages.{name} has unknown placeholders: {sorted(unknown)}")
        return self


class Settings(StrictModel):
    bot: BotSettings
    database: DatabaseSettings
    web: WebSettings = WebSettings()
    proxy: ProxySettings = ProxySettings()
    turnstile: TurnstileSettings
    defaults: DefaultPolicy = DefaultPolicy()
    messages: Messages

    def startup_fingerprint(self) -> tuple[object, ...]:
        return (self.bot, self.database, self.web, self.proxy, self.turnstile)


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path)
    with config_path.open("rb") as file:
        raw = tomllib.load(file)
    return Settings.model_validate(raw)


class ConfigStore:
    def __init__(self, path: str | Path, settings: Settings) -> None:
        self.path = Path(path)
        self._settings = settings
        self._lock = asyncio.Lock()

    @property
    def settings(self) -> Settings:
        return self._settings

    async def reload(self) -> Settings:
        candidate = load_settings(self.path)
        async with self._lock:
            if candidate.startup_fingerprint() != self._settings.startup_fingerprint():
                raise ValueError("启动级配置已变化，请重启服务；当前配置未修改")
            self._settings = candidate
            return candidate


def _read_legacy(ini_path: Path, json_path: Path) -> tuple[ConfigParser, dict[str, Any]]:
    ini = ConfigParser()
    if not ini.read(ini_path, encoding="utf-8"):
        raise FileNotFoundError(ini_path)
    with json_path.open(encoding="utf-8") as file:
        legacy_json: dict[str, Any] = json.load(file)
    return ini, legacy_json


def _legacy_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def migrate_legacy_config(ini_path: str | Path, json_path: str | Path, output_path: str | Path) -> list[str]:
    ini_file, json_file, output_file = Path(ini_path), Path(json_path), Path(output_path)
    if output_file.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {output_file}")
    ini, legacy = _read_legacy(ini_file, json_file)
    defaults = legacy["*"]
    ignored = ["msg_passed_mercy", "enable_third_party_blacklist", "flask_secret_key"]

    def legacy_action(name: str) -> str:
        action = str(defaults[name]).lower()
        if action == "mute":
            ignored.append(f"{name}=mute (mapped to kick)")
            return "kick"
        return action

    admin_ids = tuple(int(value.strip()) for value in ini.get("bot", "admin").split(","))
    proxy_host = str(legacy.get("proxy_addr", "")).strip() or None
    proxy_port_raw = str(legacy.get("proxy_port", "")).strip()
    data: dict[str, Any] = {
        "bot": {
            "username": ini.get("bot", "username"),
            "token": ini.get("bot", "token"),
            "api_id": ini.getint("bot", "api_id"),
            "api_hash": ini.get("bot", "api_hash"),
            "admin_ids": list(admin_ids),
            "log_channel_id": ini.getint("bot", "channel"),
        },
        "database": {"url": ini.get("db", "conn_str")},
        "web": {
            "host": ini.get("web", "flask_host", fallback="127.0.0.1"),
            "port": ini.getint("web", "flask_port", fallback=5000),
            "debug": ini.getboolean("web", "development", fallback=False),
            "trusted_proxy_cidrs": ["127.0.0.1/32", "::1/128"],
        },
        "proxy": ({"host": proxy_host, "port": int(proxy_port_raw)} if proxy_host and proxy_port_raw else {}),
        "turnstile": {
            "site_key": ini.get("reCAPTCHA", "site_key"),
            "secret_key": ini.get("reCAPTCHA", "secret_key"),
            "base_url": ini.get("reCAPTCHA", "base_url").rstrip("/"),
        },
        "defaults": {
            "challenge_timeout": int(defaults["challenge_timeout"]),
            "challenge_timeout_action": legacy_action("challenge_timeout_action"),
            "challenge_failed_action": legacy_action("challenge_failed_action"),
            "challenge_type": str(defaults["challenge_type"]).lower(),
            "delete_passed_challenge": _legacy_bool(defaults["delete_passed_challenge"]),
            "delete_passed_challenge_interval": int(defaults["delete_passed_challenge_interval"]),
            "delete_failed_challenge": _legacy_bool(defaults["delete_failed_challenge"]),
            "delete_failed_challenge_interval": int(defaults["delete_failed_challenge_interval"]),
            "enable_global_blacklist": _legacy_bool(defaults["enable_global_blacklist"]),
            "global_timeout_user_blacklist_remove": int(defaults["global_timeout_user_blacklist_remove"]),
        },
        "messages": {
            "start_message": legacy["msg_start_message"],
            "passed_answer": legacy["msg_passed_answer"],
            "passed_admin": legacy["msg_passed_admin"],
            "failed_answer": legacy["msg_failed_answer"],
            "failed_timeout": legacy["msg_failed_timeout"],
            "failed_admin": legacy["msg_failed_admin"],
            "failed_auto_kick": legacy["msg_failed_auto_kick"],
            "message_deleted": legacy["msg_message_deleted"],
            "into_group": legacy["msg_into_group"],
            "leave_group": legacy["msg_leave_group"],
            "leave_message": legacy["msg_leave_msg"],
            "self_introduction": defaults["msg_self_introduction"],
            "challenge_not_for_you": defaults["msg_challenge_not_for_you"],
            "challenge_math": defaults["msg_challenge_math"],
            "challenge_math_private": defaults["msg_challenge_math_private"],
            "challenge_recaptcha": defaults["msg_challenge_recaptcha"],
            "challenge_passed": defaults["msg_challenge_passed"],
            "challenge_failed": defaults["msg_challenge_failed"],
            "approve_manually": defaults["msg_approve_manually"],
            "refuse_manually": defaults["msg_refuse_manually"],
            "permission_denied": defaults["msg_permission_denied"],
            "bot_no_permission": defaults["msg_bot_no_permission"],
            "approved": defaults["msg_approved"],
            "refused": defaults["msg_refused"],
        },
    }
    Settings.model_validate(data)
    output_file.write_bytes(tomli_w.dumps(data).encode("utf-8"))
    if os.name == "posix":
        output_file.chmod(0o600)
    return ignored


__all__ = [
    "ChallengeType",
    "ConfigStore",
    "DefaultPolicy",
    "FailedAction",
    "Messages",
    "Settings",
    "ValidationError",
    "load_settings",
    "migrate_legacy_config",
]
