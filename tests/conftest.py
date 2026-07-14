from __future__ import annotations

from pathlib import Path

import pytest

from captcha_bot.config import Settings, load_settings


@pytest.fixture
def settings() -> Settings:
    return load_settings(Path("config.example.toml"))
