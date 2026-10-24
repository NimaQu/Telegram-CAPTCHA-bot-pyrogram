"""Read-only transfer from the master-branch schema into the current SQLite schema."""

from __future__ import annotations

from configparser import ConfigParser
from configparser import Error as ConfigError
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.engine import URL, Connection, make_url
from sqlalchemy.exc import SQLAlchemyError

from captcha_bot.config import load_settings
from captcha_bot.db.models import BlacklistUser, GroupConfig, RecaptchaLog

TABLES = tuple(cast(Table, model.__table__) for model in (BlacklistUser, GroupConfig, RecaptchaLog))
LOG_KEY = ("challenge_id", "user_id", "group_id", "ip_addr", "action")


@dataclass(frozen=True, slots=True)
class TransferCount:
    read: int
    inserted: int
    skipped: int
    normalized: int


def _source_url(ini_path: Path) -> URL:
    parser = ConfigParser(interpolation=None)
    try:
        with ini_path.open(encoding="utf-8-sig") as source:
            parser.read_file(source)
        url = make_url(parser.get("db", "conn_str").strip())
    except ConfigError, SQLAlchemyError, ValueError:
        raise ValueError("旧配置无效：需要 [db] conn_str，且必须是有效数据库 URL (连接信息已隐藏)") from None
    if url.drivername in {"postgres", "postgresql", "postgresql+psycopg2", "postgresql+psycopg"}:
        return url.set(drivername="postgresql+psycopg")
    if url.drivername == "sqlite" and url.database and url.database != ":memory:":
        path = Path(url.database).resolve()
        if not path.is_file():
            raise ValueError("旧 SQLite 文件不存在；不会自动创建旧数据库")
        return make_url(f"sqlite:///{path.as_posix()}?mode=ro&uri=true").set(database=f"file:{path.as_posix()}")
    raise ValueError("迁移源仅支持 PostgreSQL 或采用 master 表结构的本地 SQLite 文件")


def _check_target(connection: Connection) -> None:
    expected = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    if not inspect(connection).has_table("alembic_version"):
        raise ValueError("目标数据库未初始化，请先运行 captcha-bot init-db --config config.toml")
    if connection.scalar(text("SELECT version_num FROM alembic_version")) != expected:
        raise ValueError("目标数据库不是最新版本，请先运行 captcha-bot init-db --config config.toml")


def _source_tables(connection: Connection) -> dict[str, Table]:
    metadata = MetaData()
    inspector = inspect(connection)
    for target in TABLES:
        if not inspector.has_table(target.name):
            raise ValueError(f"旧数据库不符合 master 结构：缺少表 {target.name}")
        columns = {column["name"] for column in inspector.get_columns(target.name)}
        required = set(target.columns.keys())
        if target.name == "group_config":
            required.add("third_party_blacklist")
        if not required <= columns:
            missing = ", ".join(sorted(required - columns))
            raise ValueError(f"旧数据库不符合 master 结构：{target.name} 缺少字段 {missing}")
        Table(target.name, metadata, autoload_with=connection, resolve_fks=False)
    return metadata.tables


def _normalize_group(row: dict[str, Any]) -> bool:
    original = row.copy()
    if row["timeout"] <= 0:
        row["timeout"] = 300
    if row["challenge_type"] not in {"math", "recaptcha"}:
        row["challenge_type"] = "math"
    for field in ("failed_action", "timeout_action"):
        if row[field] not in {"ban", "kick"}:
            row[field] = "kick"
    return row != original


def _transfer(source: Connection, target: Connection, batch_size: int) -> dict[str, TransferCount]:
    source_tables = _source_tables(source)
    _check_target(target)
    counts: dict[str, TransferCount] = {}
    for table in TABLES:
        legacy = source_tables[table.name]
        fields = [name for name in table.columns.keys() if table.name != "recaptcha_log" or name != "id"]
        statement = select(*(legacy.c[name] for name in fields)).order_by(*legacy.primary_key.columns)
        key = LOG_KEY if table.name == "recaptcha_log" else tuple(column.name for column in table.primary_key)
        upsert = insert(table).on_conflict_do_nothing(index_elements=list(key))
        read = inserted = normalized = 0
        with source.execution_options(stream_results=True).execute(statement) as result:
            for batch in result.mappings().partitions(batch_size):
                rows = [dict(row) for row in batch]
                if table.name == "group_config":
                    normalized += sum(_normalize_group(row) for row in rows)
                read += len(rows)
                inserted += target.execute(upsert, rows).rowcount
        counts[table.name] = TransferCount(read, inserted, read - inserted, normalized)
    return counts


def migrate_database(ini_path: Path, config_path: Path, *, batch_size: int = 500) -> dict[str, TransferCount]:
    """Copy all three tables in one target transaction; never modify the source."""
    if batch_size <= 0:
        raise ValueError("batch_size 必须为正整数")
    settings = load_settings(config_path)
    source_url = _source_url(ini_path)
    target_url = make_url(settings.database.url).set(drivername="sqlite")
    if source_url.get_backend_name() == "sqlite":
        source_path = Path(str(source_url.database).removeprefix("file:")).resolve()
        target_path = Path(str(target_url.database)).resolve()
        if source_path == target_path or (target_path.exists() and source_path.samefile(target_path)):
            raise ValueError("源数据库和目标数据库不能是同一个文件")
    try:
        source_engine = create_engine(source_url, hide_parameters=True)
    except ImportError:
        raise RuntimeError(
            "读取旧 PostgreSQL 需要可选驱动，请使用 uv run --extra migration captcha-bot migrate-db"
        ) from None
    target_engine = create_engine(
        target_url, hide_parameters=True, connect_args={"timeout": settings.database.busy_timeout_ms / 1000}
    )
    try:
        with source_engine.connect() as source:
            if source.dialect.name == "postgresql":
                source = source.execution_options(isolation_level="REPEATABLE READ")
            with source.begin():
                if source.dialect.name == "postgresql":
                    source.execute(text("SET TRANSACTION READ ONLY"))
                else:
                    source.exec_driver_sql("BEGIN")
                with target_engine.begin() as target:
                    return _transfer(source, target, batch_size)
    except SQLAlchemyError:
        raise RuntimeError(
            "数据库迁移失败，目标数据已回滚。请检查旧库连接、读取权限、目标文件权限和数据完整性；连接信息已隐藏。"
        ) from None
    finally:
        source_engine.dispose()
        target_engine.dispose()
