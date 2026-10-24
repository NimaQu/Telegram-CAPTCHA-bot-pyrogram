from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import tomli_w
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from captcha_bot import cli
from captcha_bot.db import legacy
from captcha_bot.db.legacy import _source_url, migrate_database


@pytest.fixture
def migration_files(tmp_path: Path) -> tuple[Path, Path, str, str]:
    source_path = tmp_path / "master.sqlite"
    target_path = tmp_path / "current.sqlite"
    source_url = f"sqlite:///{source_path.as_posix()}"
    target_url = f"sqlite:///{target_path.as_posix()}"
    ini = tmp_path / "config.ini"
    ini.write_text(f"[db]\nconn_str = {source_url}\n", encoding="utf-8")
    config = tmp_path / "config.toml"
    with Path("config.example.toml").open("rb") as file:
        data = tomllib.load(file)
    data["database"]["url"] = f"sqlite+aiosqlite:///{target_path.as_posix()}"
    config.write_text(tomli_w.dumps(data), encoding="utf-8")
    cli._initialize_database(config)
    engine = create_engine(source_url)
    with engine.begin() as connection:
        # Deliberately mirror master:model.py, not the current ORM metadata.
        connection.execute(
            text(
                "CREATE TABLE blacklist_user (user_id BIGINT PRIMARY KEY, last_attempt DATETIME NOT NULL, "
                "attempt_count INTEGER NOT NULL, created_at DATETIME, updated_at DATETIME)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE group_config (chat_id BIGINT PRIMARY KEY, timeout INTEGER NOT NULL, "
                "challenge_type VARCHAR(10) NOT NULL, failed_action VARCHAR(10) NOT NULL, "
                "timeout_action VARCHAR(10) NOT NULL, third_party_blacklist BOOLEAN NOT NULL, "
                "global_blacklist BOOLEAN NOT NULL)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE recaptcha_log (id INTEGER PRIMARY KEY, group_id BIGINT NOT NULL, "
                "user_id BIGINT NOT NULL, challenge_id VARCHAR(64) NOT NULL, ip_addr VARCHAR(64) NOT NULL, "
                "user_agent TEXT NOT NULL, action VARCHAR(20) NOT NULL, created_at DATETIME, updated_at DATETIME)"
            )
        )
    engine.dispose()
    return ini, config, source_url, target_url


def test_master_transfer_large_blacklist_logs_timestamps_and_repeat(migration_files, monkeypatch, capsys) -> None:
    ini, config, source_url, target_url = migration_files
    source = create_engine(source_url)
    target = create_engine(target_url)
    timestamp = "2024-05-04 02:03:32.123456"
    try:
        with source.begin() as connection:
            connection.execute(
                text("INSERT INTO blacklist_user VALUES (:id, :stamp, 7, :stamp, NULL)"),
                [{"id": value, "stamp": timestamp} for value in range(1, 18_393)],
            )
            connection.execute(text("INSERT INTO group_config VALUES (-1001, 0, 'bad', 'mute', 'ban', 1, 1)"))
            connection.execute(text("INSERT INTO group_config VALUES (-1002, 120, 'recaptcha', 'kick', 'ban', 0, 0)"))
            connection.execute(
                text(
                    "INSERT INTO recaptcha_log VALUES "
                    "(:id, -1001, 1, 'challenge', '::1', 'old UA', 'Passed', :stamp, NULL)"
                ),
                [{"id": 10, "stamp": timestamp}, {"id": 11, "stamp": timestamp}],
            )
        with target.begin() as connection:
            connection.execute(text("INSERT INTO blacklist_user VALUES (1, CURRENT_TIMESTAMP, 99, NULL, NULL)"))
            connection.execute(
                text(
                    "INSERT INTO recaptcha_log (id, group_id, user_id, challenge_id, ip_addr, user_agent, action) "
                    "VALUES (10, -9, 9, 'existing', '::1', 'new UA', 'Passed')"
                )
            )
        report = migrate_database(ini, config, batch_size=127)
        assert report["blacklist_user"].read == 18_392
        assert report["blacklist_user"].inserted == 18_391
        assert report["blacklist_user"].skipped == 1
        assert report["group_config"].normalized == 1
        assert report["recaptcha_log"].inserted == 1
        assert report["recaptcha_log"].skipped == 1
        with target.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM blacklist_user")) == 18_392
            assert connection.scalar(text("SELECT attempt_count FROM blacklist_user WHERE user_id = 1")) == 99
            assert connection.execute(
                text("SELECT last_attempt, attempt_count, created_at, updated_at FROM blacklist_user WHERE user_id = 2")
            ).one() == (timestamp, 7, timestamp, None)
            assert connection.execute(
                text(
                    "SELECT timeout, challenge_type, failed_action, timeout_action "
                    "FROM group_config WHERE chat_id = -1001"
                )
            ).one() == (300, "math", "kick", "ban")
            log = connection.execute(
                text(
                    "SELECT id, user_agent, created_at, updated_at FROM recaptcha_log WHERE challenge_id = 'challenge'"
                )
            ).one()
            assert log[0] != 10
            assert log[1:] == ("old UA", timestamp, None)
        monkeypatch.setattr(sys, "argv", ["captcha-bot", "migrate-db", "--ini", str(ini), "--config", str(config)])
        cli.main()
        assert "新增 0" in capsys.readouterr().out
        with source.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM recaptcha_log")) == 2
            assert connection.scalar(text("SELECT failed_action FROM group_config WHERE chat_id = -1001")) == "mute"
    finally:
        source.dispose()
        target.dispose()


def test_invalid_log_rolls_back_all_tables_and_redacts_errors(migration_files) -> None:
    ini, config, source_url, target_url = migration_files
    source = create_engine(source_url)
    target = create_engine(target_url)
    try:
        with source.begin() as connection:
            connection.execute(text("INSERT INTO blacklist_user VALUES (1, CURRENT_TIMESTAMP, 3, NULL, NULL)"))
            connection.execute(text("PRAGMA ignore_check_constraints=ON"))
            connection.execute(text("DROP TABLE recaptcha_log"))
            connection.execute(
                text(
                    "CREATE TABLE recaptcha_log (id INTEGER PRIMARY KEY, group_id BIGINT, user_id BIGINT, "
                    "challenge_id TEXT, ip_addr TEXT, user_agent TEXT, action TEXT, "
                    "created_at DATETIME, updated_at DATETIME)"
                )
            )
            connection.execute(
                text("INSERT INTO recaptcha_log VALUES (1, -1, 1, NULL, '::1', 'SECRET', 'Passed', NULL, NULL)")
            )
        with pytest.raises(RuntimeError, match="目标数据已回滚") as error:
            migrate_database(ini, config)
        assert "SECRET" not in str(error.value)
        with target.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM blacklist_user")) == 0
    finally:
        source.dispose()
        target.dispose()


def test_source_config_schema_and_same_file_safety(migration_files, tmp_path: Path) -> None:
    ini, config, source_url, target_url = migration_files
    ini.write_text("[db]\nconn_str = postgresql://user:p%25ss@localhost/old\n", encoding="utf-8")
    assert _source_url(ini).drivername == "postgresql+psycopg"
    assert _source_url(ini).password == "p%ss"
    ini.write_text("[db]\nconn_str = invalid-secret-url\n", encoding="utf-8")
    with pytest.raises(ValueError, match="连接信息已隐藏") as error:
        migrate_database(ini, config)
    assert "invalid-secret-url" not in str(error.value)
    ini.write_text(f"[db]\nconn_str = {target_url}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="同一个文件"):
        migrate_database(ini, config)
    ini.write_text(f"[db]\nconn_str = sqlite:///{(tmp_path / 'absent.sqlite').as_posix()}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="不存在"):
        migrate_database(ini, config)
    ini.write_text(f"[db]\nconn_str = {source_url}\n", encoding="utf-8")
    source = create_engine(source_url)
    try:
        with source.begin() as connection:
            connection.execute(text("DROP TABLE group_config"))
        with pytest.raises(ValueError, match="master 结构"):
            migrate_database(ini, config)
    finally:
        source.dispose()


def test_sqlite_source_is_read_only_and_missing_columns_are_rejected(migration_files) -> None:
    ini, config, source_url, _ = migration_files
    readonly = create_engine(_source_url(ini))
    try:
        with readonly.connect() as connection, pytest.raises(OperationalError, match="readonly"):
            connection.execute(text("DELETE FROM blacklist_user"))
    finally:
        readonly.dispose()
    source = create_engine(source_url)
    try:
        with source.begin() as connection:
            connection.execute(text("ALTER TABLE group_config DROP COLUMN third_party_blacklist"))
        with pytest.raises(ValueError, match="缺少字段 third_party_blacklist"):
            migrate_database(ini, config)
    finally:
        source.dispose()


def test_postgresql_connection_is_read_only_snapshot_and_secrets_hidden(migration_files, monkeypatch) -> None:
    ini, config, _, _ = migration_files
    ini.write_text("[db]\nconn_str = postgresql://user:TOPSECRET@localhost/old\n", encoding="utf-8")
    engine = MagicMock()
    source = engine.connect.return_value.__enter__.return_value
    source.dialect.name = "postgresql"
    source.execution_options.return_value = source
    target_engine = MagicMock()
    monkeypatch.setattr(legacy, "create_engine", MagicMock(side_effect=[engine, target_engine]))
    transfer = MagicMock(return_value={})
    monkeypatch.setattr(legacy, "_transfer", transfer)
    assert migrate_database(ini, config) == {}
    source.execution_options.assert_called_once_with(isolation_level="REPEATABLE READ")
    assert str(source.execute.call_args.args[0]) == "SET TRANSACTION READ ONLY"
    transfer.assert_called_once()
    engine.dispose.assert_called_once()
    target_engine.dispose.assert_called_once()

    monkeypatch.setattr(legacy, "create_engine", MagicMock(side_effect=ImportError("TOPSECRET")))
    with pytest.raises(RuntimeError, match="--extra migration") as error:
        migrate_database(ini, config)
    assert "TOPSECRET" not in str(error.value)
    engine.connect.side_effect = OperationalError("password=TOPSECRET", {}, Exception("TOPSECRET"))
    monkeypatch.setattr(legacy, "create_engine", MagicMock(side_effect=[engine, target_engine]))
    with pytest.raises(RuntimeError, match="连接信息已隐藏") as error:
        migrate_database(ini, config)
    assert "TOPSECRET" not in str(error.value)


def test_target_requires_current_schema(migration_files) -> None:
    ini, config, _, target_url = migration_files
    target = create_engine(target_url)
    try:
        with target.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num = 'b841fd90a794'"))
        with pytest.raises(ValueError, match="不是最新版本"):
            migrate_database(ini, config)
        with target.begin() as connection:
            connection.execute(text("DROP TABLE alembic_version"))
        with pytest.raises(ValueError, match="未初始化"):
            migrate_database(ini, config)
        with pytest.raises(ValueError, match="batch_size"):
            migrate_database(ini, config, batch_size=0)
    finally:
        target.dispose()
