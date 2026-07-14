from __future__ import annotations

import asyncio
import os
import sys
import tomllib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest
import tomli_w
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from captcha_bot.config import load_settings
from captcha_bot.db.models import RecaptchaLogAction
from captcha_bot.db.repository import Database, Repository

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def database_config(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, Path, Config]]:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("TEST_DATABASE_URL is not set")
    with Path("config.example.toml").open("rb") as source:
        data = tomllib.load(source)
    data["database"]["url"] = database_url
    path = tmp_path_factory.mktemp("postgres") / "config.toml"
    path.write_text(tomli_w.dumps(data), encoding="utf-8")
    previous = os.environ.get("CAPTCHA_BOT_CONFIG")
    os.environ["CAPTCHA_BOT_CONFIG"] = str(path)
    alembic_config = Config("alembic.ini")
    command.downgrade(alembic_config, "base")
    command.upgrade(alembic_config, "head")
    try:
        yield database_url, path, alembic_config
    finally:
        command.upgrade(alembic_config, "head")
        if previous is None:
            os.environ.pop("CAPTCHA_BOT_CONFIG", None)
        else:
            os.environ["CAPTCHA_BOT_CONFIG"] = previous


def test_empty_upgrade_revision_cycle_and_data_preservation(database_config: tuple[str, Path, Config]) -> None:
    database_url, _, alembic_config = database_config
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO blacklist_user (user_id, last_attempt, attempt_count) "
                    "SELECT value, CURRENT_TIMESTAMP, 1 FROM generate_series(1, 18392) AS value"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO group_config "
                    "(chat_id, timeout, challenge_type, failed_action, timeout_action, global_blacklist) "
                    "VALUES (-1001, 60, 'math', 'kick', 'ban', true)"
                )
            )
        command.downgrade(alembic_config, "-1")
        command.upgrade(alembic_config, "head")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM blacklist_user")) == 18_392
            assert connection.scalar(text("SELECT timeout FROM group_config WHERE chat_id = -1001")) == 60
        metadata = inspect(engine)
        group_columns = {column["name"] for column in metadata.get_columns("group_config")}
        assert "third_party_blacklist" not in group_columns
        checks = {constraint["name"] for constraint in metadata.get_check_constraints("group_config")}
        assert {
            "ck_group_config_timeout_positive",
            "ck_group_config_challenge_type",
            "ck_group_config_failed_action",
            "ck_group_config_timeout_action",
        } <= checks
        indexes = {index["name"] for index in metadata.get_indexes("recaptcha_log")}
        assert {
            "ix_recaptcha_log_challenge_created",
            "ix_recaptcha_log_user_created",
            "ix_recaptcha_log_ip_action_group_user_created",
        } <= indexes
        unique = {constraint["name"] for constraint in metadata.get_unique_constraints("recaptcha_log")}
        assert unique == {"uq_recaptcha_log_event"}
        command.check(alembic_config)
    finally:
        engine.dispose()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="psycopg async requires a selector event loop on Windows")
async def test_repository_concurrent_upserts_and_log_deduplication(
    database_config: tuple[str, Path, Config],
) -> None:
    _, config_path, _ = database_config
    settings = load_settings(config_path)
    database = Database(settings)
    repository = Repository(database.sessions)
    try:
        await asyncio.gather(
            repository.set_group_config(-2002, "challenge_timeout", "75", settings.defaults),
            repository.set_group_config(-2002, "challenge_type", "recaptcha", settings.defaults),
        )
        overrides = await repository.get_group_overrides(-2002)
        assert overrides is not None
        assert overrides.challenge_timeout == 75
        assert overrides.challenge_type == "recaptcha"

        await asyncio.gather(*(repository.record_blacklist_timeout(settings_time(), 99_999) for _ in range(20)))
        blacklisted = await repository.get_blacklist_user(99_999)
        assert blacklisted is not None
        assert blacklisted.attempt_count == 20

        await asyncio.gather(
            *(
                repository.log_recaptcha(
                    "same-event",
                    42,
                    -2002,
                    "127.0.0.1",
                    "pytest",
                    RecaptchaLogAction.PASSED,
                )
                for _ in range(10)
            )
        )
        logs = await repository.logs_by_challenge("same-event")
        assert len(logs) == 1
    finally:
        await database.close()


def settings_time() -> datetime:
    return datetime.now()
