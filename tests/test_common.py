from __future__ import annotations

from captcha_bot.handlers.common import extract_message_ids, split_long_message, valid_ip


def test_message_utilities() -> None:
    assert extract_message_ids("https://t.me/c/123/456") == (-100123, 456)
    assert extract_message_ids("https://t.me/channel/456") == ("channel", 456)
    assert valid_ip("2001:db8::1")
    assert not valid_ip("not-an-ip")
    assert split_long_message("123456", max_length=3) == ["123", "456"]
    assert split_long_message("a\nb\n", max_length=3) == ["a\n", "b\n"]
