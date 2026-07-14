from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from captcha_bot.config import ConfigStore, Settings, load_settings, migrate_legacy_config


def test_example_config_is_valid(settings: Settings) -> None:
    assert settings.bot.api_id == 123456
    assert settings.database.url.get_secret_value().startswith("postgresql+psycopg://")
    assert "123456:replace-me" not in repr(settings)


def test_rejects_non_postgresql_and_unknown_placeholders(settings: Settings) -> None:
    raw = settings.model_dump(mode="python")
    raw["database"]["url"] = "sqlite:///data.sqlite"
    with pytest.raises(ValidationError, match="PostgreSQL"):
        Settings.model_validate(raw)
    raw = settings.model_dump(mode="python")
    raw["messages"]["start_message"] = "bad {unknown}"
    with pytest.raises(ValidationError, match="unknown placeholders"):
        Settings.model_validate(raw)
    raw = settings.model_dump(mode="python")
    raw["bot"]["api_id"] = "123"
    with pytest.raises(ValidationError):
        Settings.model_validate(raw)


def legacy_json() -> dict[str, object]:
    defaults = {
        "msg_self_introduction": "intro",
        "msg_challenge_not_for_you": "not you",
        "msg_challenge_math": "{target_id} {timeout} {challenge}",
        "msg_challenge_math_private": "{timeout} {challenge}",
        "msg_challenge_recaptcha": "{target_id} {timeout}",
        "msg_challenge_passed": "passed",
        "msg_challenge_failed": "failed",
        "msg_approve_manually": "approve",
        "msg_refuse_manually": "refuse",
        "msg_permission_denied": "denied",
        "msg_bot_no_permission": "no permission",
        "msg_approved": "{user}",
        "msg_refused": "{user}",
        "challenge_timeout": 60,
        "challenge_timeout_action": "kick",
        "challenge_failed_action": "ban",
        "challenge_type": "recaptcha",
        "delete_passed_challenge": True,
        "delete_passed_challenge_interval": 1,
        "delete_failed_challenge": True,
        "delete_failed_challenge_interval": 2,
        "enable_global_blacklist": True,
        "global_timeout_user_blacklist_remove": 600,
        "enable_third_party_blacklist": False,
    }
    return {
        "proxy_addr": "",
        "proxy_port": "",
        "msg_start_message": "start",
        "msg_passed_answer": "{targetuserid} {groupid} {grouptitle}",
        "msg_passed_mercy": "unused",
        "msg_passed_admin": "{targetuserid} {groupid} {grouptitle}",
        "msg_failed_answer": "{targetuserid} {groupid} {grouptitle}",
        "msg_failed_timeout": (
            "{targetuserid} {targetusername} {targetfirstname} {targetlastname} {groupid} {grouptitle}"
        ),
        "msg_failed_admin": "{targetuserid} {groupid} {grouptitle}",
        "msg_failed_auto_kick": (
            "{targetuserid} {targetusername} {targetfirstname} {targetlastname} {groupid} {grouptitle} "
            "{lastattempt} {sincelastattempt} {trycount}"
        ),
        "msg_message_deleted": "{targetuserid} {messageid} {groupid} {grouptitle}",
        "msg_into_group": "{groupid} {grouptitle}",
        "msg_leave_group": "{groupid}",
        "msg_leave_msg": "leaving",
        "*": defaults,
    }


def write_legacy(tmp_path: Path) -> tuple[Path, Path]:
    ini = tmp_path / "config.ini"
    ini.write_text(
        """[db]
conn_str = postgresql://user:pass@localhost/db
[bot]
username = bot
token = token
api_id = 123
api_hash = hash
admin = 1, 2
channel = -1001
[reCAPTCHA]
site_key = site
secret_key = secret
base_url = https://example.com
[web]
flask_secret_key = old
flask_port = 5000
flask_host = 127.0.0.1
development = false
""",
        encoding="utf-8",
    )
    json_path = tmp_path / "config.json"
    json_path.write_text(json.dumps(legacy_json()), encoding="utf-8")
    return ini, json_path


def test_migrates_legacy_config_without_overwrite(tmp_path: Path) -> None:
    ini, json_path = write_legacy(tmp_path)
    output = tmp_path / "config.toml"
    ignored = migrate_legacy_config(ini, json_path, output)
    migrated = load_settings(output)
    assert migrated.bot.admin_ids == (1, 2)
    assert migrated.defaults.challenge_failed_action == "ban"
    assert ignored == ["msg_passed_mercy", "enable_third_party_blacklist", "flask_secret_key"]
    with pytest.raises(FileExistsError):
        migrate_legacy_config(ini, json_path, output)


def test_migration_maps_removed_mute_action(tmp_path: Path) -> None:
    ini, json_path = write_legacy(tmp_path)
    data = legacy_json()
    defaults = cast(dict[str, object], data["*"])
    defaults["challenge_failed_action"] = "mute"
    json_path.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "config.toml"
    ignored = migrate_legacy_config(ini, json_path, output)
    assert load_settings(output).defaults.challenge_failed_action == "kick"
    assert "challenge_failed_action=mute (mapped to kick)" in ignored


@pytest.mark.asyncio
async def test_config_store_reload_is_atomic(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = await asyncio.to_thread(Path("config.example.toml").read_text, encoding="utf-8")
    await asyncio.to_thread(path.write_text, original, encoding="utf-8")
    store = ConfigStore(path, load_settings(path))
    await asyncio.to_thread(
        path.write_text,
        original.replace('start_message = "喵？"', 'start_message = "new"'),
        encoding="utf-8",
    )
    assert (await store.reload()).messages.start_message == "new"
    await asyncio.to_thread(path.write_text, original.replace("port = 5000", "port = 5001"), encoding="utf-8")
    with pytest.raises(ValueError, match="重启"):
        await store.reload()
    assert store.settings.messages.start_message == "new"
