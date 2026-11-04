"""MaxMind GeoLite2-ASN 查询，用于 IP 封锁的 ASN 规则和日志中显示 IP 所属网络。"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

import httpx
import maxminddb

logger = logging.getLogger(__name__)

LEGACY_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download"
EDITION = "GeoLite2-ASN"


@dataclass(frozen=True, slots=True)
class AsnInfo:
    number: int
    organization: str | None

    def __str__(self) -> str:
        return f"AS{self.number} {self.organization}" if self.organization else f"AS{self.number}"


class AsnReader(Protocol):
    def get(self, ip_address: str) -> Any: ...

    def metadata(self) -> Any: ...

    def close(self) -> None: ...


def _open_reader(path: str) -> AsnReader:
    # 整个文件读入内存(约 10MB)，不占用文件句柄，Windows 下也能原子替换文件
    reader = maxminddb.open_database(path, maxminddb.MODE_MEMORY)
    database_type = str(reader.metadata().database_type)
    if "ASN" not in database_type:
        reader.close()
        raise ValueError(f"{path} 不是 ASN 数据库({database_type})")
    return reader


def build_date(reader: AsnReader) -> str:
    epoch = int(reader.metadata().build_epoch)
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d")


def lookup(reader: AsnReader, value: str) -> AsnInfo | None:
    try:
        address = str(ip_address(value))
    except ValueError:
        return None
    try:
        record = reader.get(address)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    number = record.get("autonomous_system_number")
    if not isinstance(number, int):
        return None
    organization = record.get("autonomous_system_organization")
    return AsnInfo(number, str(organization) if organization else None)


class AsnService:
    """按需打开 mmdb 文件，文件被替换后自动重新加载，无需重启。"""

    def __init__(self, path: Callable[[], str | None], opener: Callable[[str], AsnReader] = _open_reader) -> None:
        self._path = path
        self._opener = opener
        self._loaded: tuple[str, int] | None = None
        self._reader: AsnReader | None = None
        self._lock = asyncio.Lock()

    def _replace(self, reader: AsnReader | None) -> None:
        old, self._reader = self._reader, reader
        if old is not None:
            old.close()

    async def _current(self) -> AsnReader | None:
        path = self._path()
        if not path:
            self._replace(None)
            self._loaded = None
            return None
        try:
            stamp = (path, os.stat(path).st_mtime_ns)
        except OSError:
            if self._loaded is None or self._loaded[0] != path:
                logger.warning("ASN database not found; ASN rules are disabled", extra={"path": path})
                self._loaded = (path, 0)
            self._replace(None)
            return None
        if stamp == self._loaded:
            return self._reader
        async with self._lock:
            if stamp != self._loaded:
                try:
                    reader = await asyncio.to_thread(self._opener, path)
                    logger.info("loaded ASN database", extra={"path": path, "build_date": build_date(reader)})
                except OSError, ValueError, maxminddb.InvalidDatabaseError:
                    logger.exception("failed to load ASN database")
                    reader = None
                self._replace(reader)
                self._loaded = stamp
        return self._reader

    async def available(self) -> bool:
        return await self._current() is not None

    async def lookup(self, ip: str) -> AsnInfo | None:
        reader = await self._current()
        return lookup(reader, ip) if reader else None


def _extract_mmdb(archive: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(".mmdb"):
                extracted = tar.extractfile(member)
                if extracted is not None:
                    return extracted.read()
    raise ValueError("下载的压缩包中没有 .mmdb 文件")


async def download_geolite2_asn(
    license_key: str,
    path: str | Path,
    *,
    account_id: int | None = None,
    request_timeout: float = 120.0,
    transport: httpx.AsyncBaseTransport | None = None,
    opener: Callable[[str], AsnReader] = _open_reader,
) -> str:
    """下载 GeoLite2-ASN，校验后原子替换目标文件，返回数据库构建日期。"""
    if account_id is not None:
        url, params, auth = DOWNLOAD_URL, {"suffix": "tar.gz"}, httpx.BasicAuth(str(account_id), license_key)
    else:
        url, params, auth = (
            LEGACY_DOWNLOAD_URL,
            {"edition_id": EDITION, "license_key": license_key, "suffix": "tar.gz"},
            None,
        )
    async with httpx.AsyncClient(follow_redirects=True, timeout=request_timeout, transport=transport) as client:
        response = await client.get(url, params=params, auth=auth or httpx.USE_CLIENT_DEFAULT)
        if response.status_code in (401, 403):
            raise ValueError(f"MaxMind 拒绝了下载请求(HTTP {response.status_code})，请检查 account_id 和 license_key")
        response.raise_for_status()
    target = Path(path)
    temporary = target.with_name(f".{target.name}.download")
    temporary.write_bytes(_extract_mmdb(response.content))
    try:
        reader = opener(str(temporary))
        try:
            version = build_date(reader)
        finally:
            reader.close()
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, target)
    return version
