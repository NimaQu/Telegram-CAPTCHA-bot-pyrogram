from __future__ import annotations

import asyncio
import csv
from datetime import datetime
from pathlib import Path

from sqlalchemy.dialects.postgresql import insert

from captcha_bot.db.models import BlacklistUser, GroupConfig
from captcha_bot.db.repository import Repository


def _read_rows(file_path: str | Path) -> list[list[str]]:
    with Path(file_path).open(newline="", encoding="utf-8") as file:
        return list(csv.reader(file))


async def import_csv(repository: Repository, file_path: str | Path, table: str) -> int:
    rows = await asyncio.to_thread(_read_rows, file_path)
    objects: list[dict[str, object]] = []
    if table == "group-config":
        for row in rows:
            objects.append(
                {
                    "chat_id": int(row[0]),
                    "failed_action": (row[1] or "kick").lower(),
                    "timeout_action": (row[2] or "kick").lower(),
                    "timeout": int(row[3] or 180),
                    "challenge_type": (row[4] or "recaptcha").lower(),
                    "global_blacklist": row[5] != "0",
                }
            )
        statement = insert(GroupConfig).values(objects).on_conflict_do_nothing(index_elements=[GroupConfig.chat_id])
    elif table == "blacklist-user":
        for row in rows:
            if row[2] == "0":
                continue
            objects.append(
                {
                    "user_id": int(row[0]),
                    "last_attempt": datetime.fromtimestamp(int(row[1])),
                    "attempt_count": int(row[3] or 1),
                }
            )
        statement = insert(BlacklistUser).values(objects).on_conflict_do_nothing(index_elements=[BlacklistUser.user_id])
    else:
        raise ValueError("table must be group-config or blacklist-user")
    if not objects:
        return 0
    async with repository.sessions.begin() as session:
        await session.execute(statement)
    return len(objects)
