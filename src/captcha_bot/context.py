from __future__ import annotations

from dataclasses import dataclass

import httpx
from pyrogram import Client

from captcha_bot.challenges import ChallengeRegistry
from captcha_bot.config import ConfigStore
from captcha_bot.db.repository import Database, Repository
from captcha_bot.services import PolicyService, TurnstileService


@dataclass(slots=True)
class AppContext:
    config: ConfigStore
    database: Database
    repository: Repository
    registry: ChallengeRegistry
    http: httpx.AsyncClient
    policies: PolicyService
    turnstile: TurnstileService
    client: Client
