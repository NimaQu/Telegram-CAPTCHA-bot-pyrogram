from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from captcha_bot.db.importer import import_csv
from captcha_bot.db.repository import Repository


class Transaction:
    def __init__(self) -> None:
        self.execute = AsyncMock()

    async def __aenter__(self) -> Transaction:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_imports_group_and_blacklist_csv(tmp_path: Path) -> None:
    transaction = Transaction()
    repository = cast(Repository, SimpleNamespace(sessions=SimpleNamespace(begin=lambda: transaction)))
    groups = tmp_path / "groups.csv"
    groups.write_text("-1,ban,kick,60,math,1\n-2,,,180,recaptcha,0\n", encoding="utf-8")
    assert await import_csv(repository, groups, "group-config") == 2

    blacklist = tmp_path / "blacklist.csv"
    blacklist.write_text("1,1700000000,1,3\n2,1700000001,0,1\n", encoding="utf-8")
    assert await import_csv(repository, blacklist, "blacklist-user") == 1
    assert transaction.execute.await_count == 2


@pytest.mark.asyncio
async def test_import_rejects_unknown_table_and_skips_empty_rows(tmp_path: Path) -> None:
    transaction = Transaction()
    repository = cast(Repository, SimpleNamespace(sessions=SimpleNamespace(begin=lambda: transaction)))
    empty = tmp_path / "empty.csv"
    empty.write_text("2,1700000001,0,1\n", encoding="utf-8")
    assert await import_csv(repository, empty, "blacklist-user") == 0
    with pytest.raises(ValueError, match="table must"):
        await import_csv(repository, empty, "unknown")
