from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from captcha_bot.asn import AsnInfo
from captcha_bot.db.repository import IpBlockRecord
from captcha_bot.ipblock import IpBlocklist, ParsedRule, RuleError, describe, parse_rule


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("108.187.4.79/24", ParsedRule("cidr", "108.187.4.0/24")),
        (" 1.2.3.4 ", ParsedRule("cidr", "1.2.3.4/32")),
        ("2001:db8::1/48", ParsedRule("cidr", "2001:db8::/48")),
        ("AS138995", ParsedRule("asn", "138995")),
        ("as13335", ParsedRule("asn", "13335")),
        ("138995", ParsedRule("asn", "138995")),
    ],
)
def test_parse_rule_normalizes(text: str, expected: ParsedRule) -> None:
    assert parse_rule(text) == expected


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "请提供"),
        ("10.0.0.0/8", "范围过大"),
        ("2001:db8::/16", "/32"),
        ("AS0", "ASN 超出范围"),
        ("AS99999999999", "无法识别"),
        ("example.com", "无法识别"),
    ],
)
def test_parse_rule_rejects(text: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rule(text)


class FakeRepository:
    def __init__(self) -> None:
        self.rows: dict[int, IpBlockRecord] = {}
        self.next_id = 1
        self.hits: list[int] = []
        self.loads = 0

    async def ip_block_rules(self) -> list[IpBlockRecord]:
        self.loads += 1
        return list(self.rows.values())

    async def add_ip_block_rule(self, kind: str, value: str, note: str, created_by: int | None) -> IpBlockRecord | None:
        if any(row.kind == kind and row.value == value for row in self.rows.values()):
            return None
        record = IpBlockRecord(self.next_id, kind, value, note, created_by, datetime(2026, 11, 4), 0, None)
        self.rows[record.id] = record
        self.next_id += 1
        return record

    async def ip_block_rule_page(
        self, offset: int, limit: int, search: str | None = None
    ) -> tuple[list[IpBlockRecord], int]:
        rows = [row for row in reversed(self.rows.values()) if not search or search in row.value + row.note]
        return rows[offset : offset + limit], len(rows)

    async def find_ip_block_rule(self, kind: str, value: str) -> IpBlockRecord | None:
        return next((row for row in self.rows.values() if row.kind == kind and row.value == value), None)

    async def delete_ip_block_rule(self, rule_id: int) -> IpBlockRecord | None:
        return self.rows.pop(rule_id, None)

    async def record_ip_block_hit(self, rule_id: int, when: datetime) -> None:
        self.hits.append(rule_id)


class FakeAsn:
    def __init__(self, table: dict[str, AsnInfo]) -> None:
        self.table = table

    async def lookup(self, ip: str) -> AsnInfo | None:
        return self.table.get(ip)


def blocklist() -> tuple[IpBlocklist, FakeRepository]:
    repository = FakeRepository()
    asn: Any = FakeAsn({"9.9.9.9": AsnInfo(138995, "Spam Hosting"), "8.8.8.8": AsnInfo(15169, None)})
    return IpBlocklist(repository, asn), repository


@pytest.mark.asyncio
async def test_blocklist_matches_cidr_and_asn() -> None:
    service, repository = blocklist()
    assert (await service.check("108.187.4.79")).rule is None
    cidr = await service.add("108.187.4.79/24", "  打码农场  ", 1)
    assert cidr.value == "108.187.4.0/24" and cidr.note == "打码农场"
    v6 = await service.add("2001:db8::/48", "", None)
    asn = await service.add("AS138995", "", 1)
    assert describe(asn) == "AS138995" and describe(cidr) == "108.187.4.0/24"

    hit = await service.check("108.187.4.200")
    assert hit.rule == cidr
    assert (await service.check("2001:db8::5")).rule == v6
    by_asn = await service.check("9.9.9.9")
    assert by_asn.rule == asn and str(by_asn.asn) == "AS138995 Spam Hosting"
    clean = await service.check("8.8.8.8")
    assert clean.rule is None and str(clean.asn) == "AS15169"
    assert (await service.check("::1")).rule is None

    await service.record_hit(cidr)
    assert repository.hits == [cidr.id]
    assert (await service.page()).total == 3


@pytest.mark.asyncio
async def test_blocklist_rejects_duplicates_and_long_notes() -> None:
    service, _ = blocklist()
    await service.add("AS138995", "", 1)
    with pytest.raises(RuleError, match="已存在"):
        await service.add("as138995", "", 1)
    await service.add("1.2.3.0/24", "", 1)
    with pytest.raises(RuleError, match="已存在"):
        await service.add("1.2.3.4/24", "", 1)
    with pytest.raises(RuleError, match="备注"):
        await service.add("5.6.7.0/24", "x" * 201, 1)


@pytest.mark.asyncio
async def test_blocklist_remove_by_id_cidr_and_asn() -> None:
    service, _ = blocklist()
    first = await service.add("108.187.4.0/24", "", 1)
    second = await service.add("AS138995", "", 1)
    third = await service.add("1.2.3.0/24", "", 1)
    assert (await service.check("9.9.9.9")).rule == second

    assert await service.remove(f"#{first.id}") == first
    assert await service.remove("AS138995") == second
    assert (await service.check("9.9.9.9")).rule is None
    assert await service.remove("1.2.3.9/24") == third
    assert await service.remove("42") is None
    assert await service.remove("AS1") is None
    with pytest.raises(RuleError):
        await service.remove("nonsense")
    assert (await service.page()).rules == []


@pytest.mark.asyncio
async def test_blocklist_loads_rules_once() -> None:
    service, repository = blocklist()
    await repository.add_ip_block_rule("cidr", "10.1.0.0/16", "", None)
    assert (await service.check("10.1.2.3")).rule is not None
    await service.check("10.2.0.1")
    assert repository.loads == 1


@pytest.mark.asyncio
async def test_blocklist_pages_and_clamps() -> None:
    service, _ = blocklist()
    for index in range(5):
        await service.add(f"10.{index}.0.0/16", "farm" if index % 2 else "", 1)
    first = await service.page(1, page_size=2)
    assert [rule.value for rule in first.rules] == ["10.4.0.0/16", "10.3.0.0/16"]
    assert first.total == 5 and first.pages == 3
    last = await service.page(99, page_size=2)
    assert last.page == 3 and [rule.value for rule in last.rules] == ["10.0.0.0/16"]
    assert (await service.page(0, page_size=2)).page == 1
    found = await service.page(1, "farm", page_size=2)
    assert found.total == 2 and found.pages == 1
    empty = await service.page(5, "nothing")
    assert empty.page == 1 and empty.pages == 1 and empty.rules == []
