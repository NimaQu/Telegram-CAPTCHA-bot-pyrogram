from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from captcha_bot import asn as asn_module
from captcha_bot.asn import AsnInfo, AsnService, download_geolite2_asn, lookup
from captcha_bot.geoip import GeoIpService

RECORDS: dict[str, Any] = {
    "9.9.9.9": {"autonomous_system_number": 138995, "autonomous_system_organization": "Spam Hosting"},
    "8.8.8.8": {"autonomous_system_number": 15169},
    "7.7.7.7": {"autonomous_system_organization": "no number"},
    "6.6.6.6": "broken",
}


class FakeReader:
    def __init__(self, build_epoch: int = 1_762_214_400) -> None:
        self.closed = False
        self.build_epoch = build_epoch

    def get(self, ip_address: str) -> Any:
        if ip_address == "5.5.5.5":
            raise ValueError("bad")
        return RECORDS.get(ip_address)

    def metadata(self) -> Any:
        return SimpleNamespace(build_epoch=self.build_epoch, database_type="GeoLite2-ASN")

    def close(self) -> None:
        self.closed = True


def test_lookup_reads_records() -> None:
    reader = FakeReader()
    assert lookup(reader, "9.9.9.9") == AsnInfo(138995, "Spam Hosting")
    assert str(lookup(reader, "9.9.9.9")) == "AS138995 Spam Hosting"
    assert str(lookup(reader, "8.8.8.8")) == "AS15169"
    for value in ("7.7.7.7", "6.6.6.6", "5.5.5.5", "1.1.1.1", "not-an-ip"):
        assert lookup(reader, value) is None
    assert asn_module.build_date(reader) == "2025-11-04"


@pytest.mark.asyncio
async def test_service_reloads_on_change_and_handles_missing(tmp_path: Path) -> None:
    path = tmp_path / "GeoLite2-ASN.mmdb"
    readers: list[FakeReader] = []

    def opener(_path: str) -> FakeReader:
        if Path(_path).read_bytes() == b"broken":
            raise ValueError("not an mmdb")
        readers.append(FakeReader())
        return readers[-1]

    configured: list[str | None] = [str(path)]
    service = AsnService(lambda: configured[0], opener)
    assert await service.lookup("9.9.9.9") is None
    assert not await service.available()

    path.write_bytes(b"v1")
    assert (await service.lookup("9.9.9.9")) == AsnInfo(138995, "Spam Hosting")
    assert await service.available()
    assert len(readers) == 1

    path.write_bytes(b"v2")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    await service.lookup("8.8.8.8")
    assert len(readers) == 2 and readers[0].closed

    path.write_bytes(b"broken")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000))
    assert await service.lookup("9.9.9.9") is None
    assert readers[1].closed

    path.unlink()
    assert await service.lookup("9.9.9.9") is None
    configured[0] = None
    assert await service.lookup("9.9.9.9") is None


def test_real_opener_rejects_invalid_files(tmp_path: Path) -> None:
    path = tmp_path / "bad.mmdb"
    path.write_bytes(b"not a database")
    with pytest.raises(Exception, match=r"(?i)metadata|database|mmdb"):
        asn_module._open_reader(str(path))


def archive(name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_download_with_account_id_uses_basic_auth(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=archive("GeoLite2-ASN_20261103/GeoLite2-ASN.mmdb", b"mmdb"))

    target = tmp_path / "GeoLite2-ASN.mmdb"
    version = await download_geolite2_asn(
        "secret", target, account_id=42, transport=httpx.MockTransport(handler), opener=lambda _p: FakeReader()
    )
    assert version == "2025-11-04"
    assert target.read_bytes() == b"mmdb"
    assert requests[0].url.path == "/geoip/databases/GeoLite2-ASN/download"
    assert requests[0].headers["authorization"].startswith("Basic ")
    assert not (tmp_path / ".GeoLite2-ASN.mmdb.download").exists()


@pytest.mark.asyncio
async def test_download_legacy_url_and_failures(tmp_path: Path) -> None:
    target = tmp_path / "GeoLite2-ASN.mmdb"
    target.write_bytes(b"old")
    seen: list[httpx.Request] = []

    def legacy(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=archive("x/GeoLite2-ASN.mmdb", b"new"))

    await download_geolite2_asn("secret", target, transport=httpx.MockTransport(legacy), opener=lambda _p: FakeReader())
    assert seen[0].url.params["license_key"] == "secret"
    assert seen[0].url.params["edition_id"] == "GeoLite2-ASN"
    assert target.read_bytes() == b"new"

    denied = httpx.MockTransport(lambda _r: httpx.Response(401))
    with pytest.raises(ValueError, match="license_key"):
        await download_geolite2_asn("bad", target, transport=denied)

    empty = httpx.MockTransport(lambda _r: httpx.Response(200, content=archive("x/README.txt", b"hi")))
    with pytest.raises(ValueError, match=r"\.mmdb"):
        await download_geolite2_asn("secret", target, transport=empty)

    def broken_opener(_path: str) -> FakeReader:
        raise ValueError("corrupt")

    with pytest.raises(ValueError, match="corrupt"):
        await download_geolite2_asn("secret", target, transport=httpx.MockTransport(legacy), opener=broken_opener)
    assert target.read_bytes() == b"new"
    assert not (tmp_path / ".GeoLite2-ASN.mmdb.download").exists()


@pytest.mark.asyncio
async def test_geoip_format_includes_asn(tmp_path: Path) -> None:
    path = tmp_path / "GeoLite2-ASN.mmdb"
    path.write_bytes(b"v1")
    service = AsnService(lambda: str(path), lambda _p: FakeReader())
    geoip = GeoIpService(lambda: None, service)
    assert await geoip.format("9.9.9.9") == "`9.9.9.9` (AS138995 Spam Hosting)"
    assert await geoip.format("1.1.1.1") == "`1.1.1.1`"
