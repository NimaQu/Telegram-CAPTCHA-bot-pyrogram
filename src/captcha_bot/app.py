from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pyrogram import Client

from captcha_bot.challenges import ChallengeRegistry
from captcha_bot.config import ConfigStore, load_settings
from captcha_bot.context import AppContext
from captcha_bot.db.repository import Database, Repository
from captcha_bot.handlers import register_admin_handlers, register_challenge_handlers
from captcha_bot.services import PolicyService, TurnstileService
from captcha_bot.web import register_web_routes

logger = logging.getLogger(__name__)


def create_app(config_path: str | Path = "config.toml") -> FastAPI:
    path = Path(config_path).resolve()
    initial_settings = load_settings(path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        config = ConfigStore(path, initial_settings)
        database = Database(initial_settings)
        registry = ChallengeRegistry()
        http: httpx.AsyncClient | None = None
        client: Client | None = None
        try:
            await database.ensure_schema_current()
            repository = Repository(database.sessions)
            http = httpx.AsyncClient()
            proxy = None
            if initial_settings.proxy.host and initial_settings.proxy.port:
                proxy = {
                    "scheme": "socks5",
                    "hostname": initial_settings.proxy.host,
                    "port": initial_settings.proxy.port,
                }
            client = Client(
                "bot",
                bot_token=initial_settings.bot.token.get_secret_value(),
                api_id=initial_settings.bot.api_id,
                api_hash=initial_settings.bot.api_hash.get_secret_value(),
                proxy=proxy,
            )
            policies = PolicyService(config, repository)
            context = AppContext(
                config=config,
                database=database,
                repository=repository,
                registry=registry,
                http=http,
                policies=policies,
                turnstile=TurnstileService(http, config),
                client=client,
            )
            register_admin_handlers(client, context)
            register_challenge_handlers(client, context)
            app.state.context = context
            await client.start()
            logger.info("Telegram client and web service started")
            yield
        finally:
            await registry.shutdown()
            if client is not None and client.is_connected:
                await client.stop()
            if http is not None:
                await http.aclose()
            await database.close()
            logger.info("application shutdown complete")

    app = FastAPI(title="Telegram CAPTCHA Bot", debug=initial_settings.web.debug, lifespan=lifespan)
    workspace_root = Path(__file__).resolve().parents[2]
    asset_root = workspace_root if (workspace_root / "templates").is_dir() else Path(__file__).resolve().parent
    app.mount("/static", StaticFiles(directory=asset_root / "static"), name="static")
    register_web_routes(app, Jinja2Templates(directory=asset_root / "templates"))
    return app
