from captcha_bot.handlers.admin import register_admin_handlers
from captcha_bot.handlers.antispam import register_antispam_handlers
from captcha_bot.handlers.challenge import register_challenge_handlers
from captcha_bot.handlers.config import register_config_handlers

__all__ = [
    "register_admin_handlers",
    "register_antispam_handlers",
    "register_challenge_handlers",
    "register_config_handlers",
]
