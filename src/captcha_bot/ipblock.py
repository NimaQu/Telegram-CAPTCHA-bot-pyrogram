"""全局 IP 封锁：按 CIDR 或 ASN 拒绝网页验证，针对人工打码的 spam 账号。"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Protocol

from captcha_bot.asn import AsnInfo, AsnService
from captcha_bot.db.repository import IpBlockRecord

KIND_CIDR = "cidr"
KIND_ASN = "asn"
# 更大的范围应该用 ASN 规则表达，避免误封整片地址
MIN_PREFIX = {4: 16, 6: 32}
MAX_NOTE_LENGTH = 200
PAGE_SIZE = 20
ASN_PATTERN = re.compile(r"(?i)^(?:as)?(\d{1,10})$")


class RuleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedRule:
    kind: str
    value: str


def parse_rule(text: str) -> ParsedRule:
    """接受 `108.187.4.79/24`、`2001:db8::/48`、单个 IP、`AS138995`；CIDR 会规范化为网络地址。"""
    raw = text.strip()
    if not raw:
        raise RuleError("请提供 CIDR 或 ASN，例如 108.187.4.0/24 或 AS138995")
    asn = ASN_PATTERN.match(raw)
    if asn and (raw.lower().startswith("as") or "." not in raw):
        number = int(asn.group(1))
        if not 0 < number < 2**32:
            raise RuleError("ASN 超出范围")
        return ParsedRule(KIND_ASN, str(number))
    try:
        network = ip_network(raw, strict=False)
    except ValueError as exc:
        raise RuleError(f"无法识别 `{raw}`：需要 CIDR(如 108.187.4.0/24)、IP 或 ASN(如 AS138995)") from exc
    minimum = MIN_PREFIX[network.version]
    if network.prefixlen < minimum:
        raise RuleError(f"范围过大：IPv{network.version} 前缀不能短于 /{minimum}，更大的范围请用 ASN 规则")
    return ParsedRule(KIND_CIDR, str(network))


def describe(rule: IpBlockRecord) -> str:
    return f"AS{rule.value}" if rule.kind == KIND_ASN else rule.value


class RuleRepository(Protocol):
    async def ip_block_rules(self) -> list[IpBlockRecord]: ...

    async def ip_block_rule_page(
        self, offset: int, limit: int, search: str | None = None
    ) -> tuple[list[IpBlockRecord], int]: ...

    async def find_ip_block_rule(self, kind: str, value: str) -> IpBlockRecord | None: ...

    async def add_ip_block_rule(
        self, kind: str, value: str, note: str, created_by: int | None
    ) -> IpBlockRecord | None: ...

    async def delete_ip_block_rule(self, rule_id: int) -> IpBlockRecord | None: ...

    async def record_ip_block_hit(self, rule_id: int, when: datetime) -> None: ...


@dataclass(frozen=True, slots=True)
class RulePage:
    rules: list[IpBlockRecord]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))


@dataclass(frozen=True, slots=True)
class IpCheck:
    ip: str
    asn: AsnInfo | None
    rule: IpBlockRecord | None


class IpBlocklist:
    """规则缓存在内存中，增删规则时刷新；规则只有 Bot 管理员维护，数量不大，线性匹配即可。"""

    def __init__(self, repository: RuleRepository, asn: AsnService) -> None:
        self.repository = repository
        self.asn = asn
        self._networks: list[tuple[IPv4Network | IPv6Network, IpBlockRecord]] | None = None
        self._asns: dict[int, IpBlockRecord] = {}
        self._lock = asyncio.Lock()

    async def _load(self) -> None:
        rules = await self.repository.ip_block_rules()
        networks: list[tuple[IPv4Network | IPv6Network, IpBlockRecord]] = []
        asns: dict[int, IpBlockRecord] = {}
        for rule in rules:
            if rule.kind == KIND_ASN:
                asns[int(rule.value)] = rule
            else:
                networks.append((ip_network(rule.value), rule))
        self._networks, self._asns = networks, asns

    async def _ensure_loaded(self) -> list[tuple[IPv4Network | IPv6Network, IpBlockRecord]]:
        if self._networks is None:
            async with self._lock:
                if self._networks is None:
                    await self._load()
        assert self._networks is not None
        return self._networks

    async def page(self, page: int = 1, search: str | None = None, page_size: int = PAGE_SIZE) -> RulePage:
        """page 从 1 开始；超出范围时返回最后一页。"""
        page = max(1, page)
        rules, total = await self.repository.ip_block_rule_page((page - 1) * page_size, page_size, search)
        last = max(1, -(-total // page_size))
        if page > last:
            page = last
            rules, total = await self.repository.ip_block_rule_page((page - 1) * page_size, page_size, search)
        return RulePage(rules, total, page, page_size)

    async def add(self, text: str, note: str, created_by: int | None) -> IpBlockRecord:
        parsed = parse_rule(text)
        note = note.strip()
        if len(note) > MAX_NOTE_LENGTH:
            raise RuleError(f"备注不能超过 {MAX_NOTE_LENGTH} 字")
        record = await self.repository.add_ip_block_rule(parsed.kind, parsed.value, note, created_by)
        if record is None:
            label = f"AS{parsed.value}" if parsed.kind == KIND_ASN else parsed.value
            raise RuleError(f"规则 {label} 已存在")
        async with self._lock:
            await self._load()
        return record

    async def remove(self, text: str) -> IpBlockRecord | None:
        """可以按规则 ID(`#3` 或 `3`)、CIDR 或 ASN 删除。"""
        raw = text.strip().removeprefix("#")
        rule_id: int | None = None
        if raw.isdigit() and not raw.lower().startswith("as"):
            rule_id = int(raw)
        else:
            parsed = parse_rule(raw)
            found = await self.repository.find_ip_block_rule(parsed.kind, parsed.value)
            rule_id = found.id if found else None
        if rule_id is None:
            return None
        record = await self.repository.delete_ip_block_rule(rule_id)
        if record is not None:
            async with self._lock:
                await self._load()
        return record

    async def check(self, ip: str) -> IpCheck:
        address = ip_address(ip)
        networks = await self._ensure_loaded()
        asn = await self.asn.lookup(ip)
        for network, rule in networks:
            if address.version == network.version and address in network:
                return IpCheck(ip, asn, rule)
        rule = self._asns.get(asn.number) if asn else None
        return IpCheck(ip, asn, rule)

    async def record_hit(self, rule: IpBlockRecord) -> None:
        await self.repository.record_ip_block_hit(rule.id, datetime.now())
