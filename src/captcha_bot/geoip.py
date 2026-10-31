"""纯真 IP 库 qqwry.dat 查询，数据来自 https://github.com/metowolf/qqwry.dat 。"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
from collections.abc import Callable
from ipaddress import IPv4Address, ip_address
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

INDEX_SIZE = 7
REDIRECT_FULL = 1
REDIRECT_COUNTRY = 2
# 纯真库用这个占位符表示没有更详细的地区信息
PLACEHOLDER = "CZ88.NET"


class QQWryError(ValueError):
    pass


class QQWry:
    def __init__(self, data: bytes) -> None:
        if len(data) < 8:
            raise QQWryError("qqwry.dat 文件过小")
        self._data = data
        self._first, self._last = struct.unpack_from("<II", data, 0)
        if self._first > self._last or self._last + INDEX_SIZE > len(data) or (self._last - self._first) % INDEX_SIZE:
            raise QQWryError("qqwry.dat 索引损坏")
        self.version = self._record(self._last)

    @classmethod
    def from_file(cls, path: str | Path) -> QQWry:
        return cls(Path(path).read_bytes())

    def _int3(self, offset: int) -> int:
        return int.from_bytes(self._data[offset : offset + 3], "little")

    def _string(self, offset: int) -> tuple[str, int]:
        end = self._data.index(b"\0", offset)
        return self._data[offset:end].decode("gb18030", errors="replace"), end + 1

    def _area(self, offset: int) -> str:
        if self._data[offset] in (REDIRECT_FULL, REDIRECT_COUNTRY):
            target = self._int3(offset + 1)
            return self._string(target)[0] if target else ""
        return self._string(offset)[0]

    def _record(self, index_offset: int) -> str:
        offset = self._int3(index_offset + 4) + 4
        if self._data[offset] == REDIRECT_FULL:
            offset = self._int3(offset + 1)
        if self._data[offset] == REDIRECT_COUNTRY:
            country = self._string(self._int3(offset + 1))[0]
            area_offset = offset + 4
        else:
            country, area_offset = self._string(offset)
        parts = (country.strip(), self._area(area_offset).strip())
        return " ".join(part for part in parts if part and part != PLACEHOLDER)

    def lookup(self, value: str) -> str | None:
        try:
            address = ip_address(value)
        except ValueError:
            return None
        if not isinstance(address, IPv4Address):
            return None
        target = int(address)
        low, high = 0, (self._last - self._first) // INDEX_SIZE
        while low < high:
            middle = (low + high + 1) // 2
            if struct.unpack_from("<I", self._data, self._first + middle * INDEX_SIZE)[0] <= target:
                low = middle
            else:
                high = middle - 1
        index_offset = self._first + low * INDEX_SIZE
        if index_offset == self._last:
            # 最后一条记录存放的是数据库版本信息
            return None
        record_offset = self._int3(index_offset + 4)
        if struct.unpack_from("<I", self._data, record_offset)[0] < target:
            return None
        try:
            return self._record(index_offset) or None
        except IndexError, ValueError:
            logger.warning("broken qqwry record", extra={"ip": value})
            return None


class GeoIpService:
    """按需加载 qqwry.dat，文件被替换后自动重新加载，无需重启。"""

    def __init__(self, path: Callable[[], str | None]) -> None:
        self._path = path
        self._loaded: tuple[str, int] | None = None
        self._database: QQWry | None = None
        self._lock = asyncio.Lock()

    async def _current(self) -> QQWry | None:
        path = self._path()
        if not path:
            return None
        try:
            stamp = (path, os.stat(path).st_mtime_ns)
        except OSError:
            if self._loaded is None or self._loaded[0] != path:
                logger.warning("qqwry.dat not found; IP locations are disabled", extra={"path": path})
                self._loaded = (path, 0)
            self._database = None
            return None
        if stamp == self._loaded:
            return self._database
        async with self._lock:
            if stamp != self._loaded:
                try:
                    # 解析约 30MB 的文件，放到线程里避免阻塞事件循环
                    self._database = await asyncio.to_thread(QQWry.from_file, path)
                    logger.info("loaded qqwry.dat", extra={"path": path, "qqwry_version": self._database.version})
                except OSError, QQWryError:
                    logger.exception("failed to load qqwry.dat")
                    self._database = None
                self._loaded = stamp
        return self._database

    async def lookup(self, ip: str) -> str | None:
        database = await self._current()
        return database.lookup(ip) if database else None

    async def format(self, ip: str) -> str:
        """Telegram 中点击 inline code 即可复制 IP。"""
        location = await self.lookup(ip)
        return f"`{ip}` ({location})" if location else f"`{ip}`"


async def download_qqwry(
    url: str, path: str | Path, *, request_timeout: float = 120.0, transport: httpx.AsyncBaseTransport | None = None
) -> str:
    """下载并校验 qqwry.dat，原子替换目标文件，返回数据库版本。"""
    target = Path(path)
    temporary = target.with_name(f".{target.name}.download")
    async with httpx.AsyncClient(follow_redirects=True, timeout=request_timeout, transport=transport) as client:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            with temporary.open("wb") as file:
                async for chunk in response.aiter_bytes():
                    file.write(chunk)
    try:
        version = QQWry.from_file(temporary).version
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, target)
    return version
