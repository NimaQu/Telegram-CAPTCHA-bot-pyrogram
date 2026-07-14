from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from captcha_bot import app as app_module
from captcha_bot import cli


def test_cli_parser_and_migrate(tmp_path: Path, monkeypatch, capsys) -> None:
    assert cli.parser().prog == "captcha-bot"
    ini = tmp_path / "missing.ini"
    monkeypatch.setattr(
        sys,
        "argv",
        ["captcha-bot", "migrate-config", "--ini", str(ini), "--json", "missing.json", "--output", "out.toml"],
    )
    try:
        cli.main()
    except SystemExit as exc:
        assert "missing.ini" in str(exc)
    assert capsys.readouterr().out == ""


def test_cli_run_calls_uvicorn(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_run(app, host, port, debug):  # type: ignore[no-untyped-def]
        called["app"] = app
        called.update(host=host, port=port, debug=debug)

    monkeypatch.setattr(cli, "_serve_application", fake_run)
    monkeypatch.setattr(sys, "argv", ["captcha-bot", "run", "--config", "config.example.toml"])
    cli.main()
    assert called["host"] == "127.0.0.1"
    assert called["port"] == 5000


class FakeDatabase:
    def __init__(self, _settings) -> None:  # type: ignore[no-untyped-def]
        self.sessions = object()
        self.closed = False

    async def ensure_schema_current(self) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, *_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
        self.is_connected = False
        self.handlers: list[object] = []

    def add_handler(self, handler, group: int = 0) -> None:  # type: ignore[no-untyped-def]
        self.handlers.append((handler, group))

    async def start(self) -> None:
        self.is_connected = True

    async def stop(self) -> None:
        self.is_connected = False


@pytest.mark.asyncio
async def test_application_lifespan_owns_resources(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "Database", FakeDatabase)
    monkeypatch.setattr(app_module, "Client", FakeClient)
    monkeypatch.setattr(app_module, "Repository", lambda sessions: SimpleNamespace(sessions=sessions))
    monkeypatch.setattr(app_module, "PolicyService", lambda config, repository: SimpleNamespace())
    monkeypatch.setattr(app_module, "TurnstileService", lambda http, config: SimpleNamespace())
    application = app_module.create_app("config.example.toml")
    async with application.router.lifespan_context(application):
        assert application.state.context.client.is_connected
        assert application.state.context.client.handlers
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client:
            assert (await client.get("/")).status_code == 200
    assert not application.state.context.client.is_connected
