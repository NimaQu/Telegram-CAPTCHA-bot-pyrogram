"""Backward-compatible executable entry point."""

from captcha_bot.cli import main

if __name__ == "__main__":
    main(default_command="run")
