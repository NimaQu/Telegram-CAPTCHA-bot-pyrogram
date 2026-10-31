from __future__ import annotations

import os
import struct
from ipaddress import IPv4Address
from pathlib import Path

import httpx
import pytest

from captcha_bot.geoip import GeoIpService, QQWry, QQWryError, download_qqwry


def gbk(text: str) -> bytes:
    return text.encode("gb18030") + b"\0"


def build_qqwry() -> bytes:
    """构造一个覆盖各种重定向方式的小型 qqwry.dat。"""
    body = bytearray(b"\0" * 8)
    strings: dict[str, int] = {}

    def string(text: str) -> int:
        if text not in strings:
            strings[text] = len(body)
            body.extend(gbk(text))
        return strings[text]

    def offset3(value: int) -> bytes:
        return value.to_bytes(3, "little")

    country = string("中国-北京")
    area = string("电信")
    shared = len(body)
    body.extend(b"\x02" + offset3(country) + b"\x02" + offset3(area))
    entries: list[tuple[str, str, bytes]] = [
        ("0.0.0.0", "0.255.255.255", gbk("IANA") + gbk(" CZ88.NET")),
        ("1.0.0.0", "1.0.0.255", b"\x01" + offset3(shared)),
        ("1.0.1.0", "1.0.1.255", b"\x02" + offset3(country) + gbk("联通")),
        ("1.0.3.0", "1.0.3.255", gbk("美国") + b"\x01" + offset3(0)),
        ("255.255.255.0", "255.255.255.255", gbk("纯真网络") + gbk("测试数据")),
    ]
    records: list[tuple[int, int]] = []
    for start, end, location in entries:
        records.append((int(IPv4Address(start)), len(body)))
        body.extend(struct.pack("<I", int(IPv4Address(end))) + location)
    first = len(body)
    for start, offset in records:
        body.extend(struct.pack("<I", start) + offset3(offset))
    struct.pack_into("<II", body, 0, first, len(body) - 7)
    return bytes(body)


def test_qqwry_lookup_handles_redirects() -> None:
    database = QQWry(build_qqwry())
    assert database.version == "纯真网络 测试数据"
    assert database.lookup("0.1.2.3") == "IANA"
    assert database.lookup("1.0.0.8") == "中国-北京 电信"
    assert database.lookup("1.0.1.1") == "中国-北京 联通"
    assert database.lookup("1.0.3.1") == "美国"
    assert database.lookup("1.0.2.1") is None
    assert database.lookup("255.255.255.255") is None
    assert database.lookup("2001:db8::1") is None
    assert database.lookup("not-an-ip") is None


@pytest.mark.parametrize("data", [b"", struct.pack("<II", 100, 50), struct.pack("<II", 8, 10) + b"\0" * 10])
def test_qqwry_rejects_broken_files(data: bytes) -> None:
    with pytest.raises(QQWryError):
        QQWry(data)


@pytest.mark.asyncio
async def test_geoip_service_reloads_changed_file(tmp_path: Path) -> None:
    path = tmp_path / "qqwry.dat"
    service = GeoIpService(lambda: str(path))
    assert await service.format("1.0.0.1") == "`1.0.0.1`"
    path.write_bytes(build_qqwry())
    assert await service.format("1.0.0.1") == "`1.0.0.1` (中国-北京 电信)"
    assert await service.format("1.0.2.1") == "`1.0.2.1`"

    path.write_bytes(b"broken")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert await service.lookup("1.0.0.1") is None
    assert await GeoIpService(lambda: None).lookup("1.0.0.1") is None


@pytest.mark.asyncio
async def test_download_qqwry_validates_before_replacing(tmp_path: Path) -> None:
    target = tmp_path / "qqwry.dat"
    target.write_bytes(b"old")
    payload = build_qqwry()
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=payload))
    assert await download_qqwry("https://example.com/qqwry.dat", target, transport=transport) == "纯真网络 测试数据"
    assert target.read_bytes() == payload

    broken = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"broken"))
    with pytest.raises(QQWryError):
        await download_qqwry("https://example.com/qqwry.dat", target, transport=broken)
    assert target.read_bytes() == payload
    assert not (tmp_path / ".qqwry.dat.download").exists()
