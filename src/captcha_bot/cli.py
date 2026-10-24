from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import uvicorn
from alembic.config import Config
from alembic.util.exc import CommandError
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from alembic import command
from captcha_bot.config import load_settings, migrate_legacy_config
from captcha_bot.db.importer import import_csv
from captcha_bot.db.legacy import migrate_database
from captcha_bot.db.repository import Database, Repository


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(prog="captcha-bot")
    subcommands = command_parser.add_subparsers(dest="command")

    run = subcommands.add_parser("run", help="run the Telegram bot and web service")
    run.add_argument("--config", default="config.toml", type=Path)

    initialize = subcommands.add_parser("init-db", help="initialize or upgrade the database without starting the bot")
    initialize.add_argument("--config", default="config.toml", type=Path)

    transfer = subcommands.add_parser("migrate-db", help="copy the master database from config.ini into SQLite")
    transfer.add_argument("--ini", default="config.ini", type=Path)
    transfer.add_argument("--config", default="config.toml", type=Path)

    migrate = subcommands.add_parser("migrate-config", help="convert config.ini and config.json to TOML")
    migrate.add_argument("--ini", default="config.ini", type=Path)
    migrate.add_argument("--json", default="config.json", type=Path)
    migrate.add_argument("--output", default="config.toml", type=Path)

    importer = subcommands.add_parser("import-csv", help="import legacy database CSV data")
    importer.add_argument("file", type=Path)
    importer.add_argument("--table", required=True, choices=("group-config", "blacklist-user"))
    importer.add_argument("--config", default="config.toml", type=Path)
    return command_parser


def _initialize_database(config_path: Path) -> None:
    settings = load_settings(config_path)
    migration_config = Config("alembic.ini")
    migration_config.attributes["captcha_bot_settings"] = settings
    command.upgrade(migration_config, "head")


async def _import_command(config_path: Path, file_path: Path, table: str) -> int:
    settings = load_settings(config_path)
    database = Database(settings)
    try:
        await database.ensure_schema_current()
        return await import_csv(Repository(database.sessions), file_path, table)
    finally:
        await database.close()


def _run_async[T](coroutine: Coroutine[Any, Any, T]) -> T:
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    return asyncio.run(coroutine, loop_factory=loop_factory)


def _serve_application(application: Any, host: str, port: int, debug: bool) -> None:
    config = uvicorn.Config(
        application,
        host=host,
        port=port,
        log_level="debug" if debug else "info",
        proxy_headers=False,
    )
    try:
        _run_async(uvicorn.Server(config).serve())
    except KeyboardInterrupt:
        # Uvicorn handles shutdown before asyncio.run re-raises SIGINT here.
        logging.getLogger(__name__).info("server stopped by interrupt")


def main(default_command: str | None = None) -> None:
    arguments = sys.argv[1:]
    if not arguments and default_command:
        arguments = [default_command]
    args = parser().parse_args(arguments)
    try:
        if args.command == "migrate-db":
            counts = migrate_database(args.ini, args.config)
            for table, count in counts.items():
                print(
                    f"{table}: 读取 {count.read}，新增 {count.inserted}，"
                    f"重复/冲突跳过 {count.skipped}，策略转换 {count.normalized}"
                )
            print("迁移已提交；旧库未修改。third_party_blacklist 已忽略，日志内部 ID 已重新生成。")
            return
        if args.command == "init-db":
            _initialize_database(args.config)
            print("数据库已初始化/升级至最新版本；可以启动机器人了。")
            return
        if args.command == "migrate-config":
            ignored = migrate_legacy_config(args.ini, args.json, args.output)
            print(f"已写入 {args.output}；忽略的遗留字段: {', '.join(ignored)}")
            return
        if args.command == "import-csv":
            os.environ["CAPTCHA_BOT_CONFIG"] = str(args.config.resolve())
            count = _run_async(_import_command(args.config, args.file, args.table))
            print(f"已导入 {count} 条记录")
            return
        if args.command == "run":
            from captcha_bot.app import create_app

            settings = load_settings(args.config)
            os.environ["CAPTCHA_BOT_CONFIG"] = str(args.config.resolve())
            logging.basicConfig(
                level=logging.DEBUG if settings.web.debug else logging.INFO,
                format="%(asctime)s %(levelname)s %(name)s %(message)s",
            )
            _serve_application(
                create_app(args.config),
                settings.web.host,
                settings.web.port,
                settings.web.debug,
            )
            return
        parser().print_help()
    except (OSError, ValueError, ValidationError, RuntimeError, CommandError, SQLAlchemyError) as exc:
        raise SystemExit(f"error: {exc}") from exc
