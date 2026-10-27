"""Mini App 中的 Bot 管理员接口，对应 /reload、/leave、/clean、/getlog、/getuserbyip、/banuserbyip 及转发查询。"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from pyrogram.errors import ChatAdminRequired, RPCError

from captcha_bot import admin_ops
from captcha_bot.context import AppContext
from captcha_bot.db.repository import LogRecord
from captcha_bot.handlers.common import is_bot_admin, schedule, valid_ip
from captcha_bot.miniapp import WebAppUser, authenticate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/miniapp/api/admin")

AuthHeader = Annotated[str | None, Header()]


class LeavePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chat_id: int = Field(lt=0, strict=True)


class BanPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: int = Field(lt=0, strict=True)


def _context(request: Request) -> AppContext:
    return request.app.state.context


def require_bot_admin(request: Request, authorization: str | None) -> WebAppUser:
    user = authenticate(request, authorization).user
    if not is_bot_admin(_context(request), user.id):
        raise HTTPException(403, "仅 Bot 管理员可用")
    return user


def _checked_ip(ip_addr: str) -> str:
    if not valid_ip(ip_addr):
        raise HTTPException(400, "IP 地址格式错误")
    return ip_addr


def _log_json(record: LogRecord) -> dict[str, object]:
    return {
        "group_id": record.group_id,
        "user_id": record.user_id,
        "challenge_id": record.challenge_id,
        "ip_addr": record.ip_addr,
        "user_agent": record.user_agent,
        "action": record.action,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


@router.post("/reload")
async def reload_config(request: Request, authorization: AuthHeader = None) -> dict[str, object]:
    require_bot_admin(request, authorization)
    try:
        await _context(request).config.reload()
    except (OSError, ValueError) as exc:
        raise HTTPException(400, f"配置重载失败：{exc}") from exc
    return {"message": "配置已成功重载。"}


@router.post("/leave")
async def leave_group(request: Request, payload: LeavePayload, authorization: AuthHeader = None) -> dict[str, object]:
    user = require_bot_admin(request, authorization)
    try:
        await admin_ops.leave_group(_context(request), payload.chat_id)
    except RPCError as exc:
        raise HTTPException(400, "操作失败，可能是 Bot 不在该群里。") from exc
    logger.info("bot left group via Mini App", extra={"chat_id": payload.chat_id, "admin_id": user.id})
    return {"message": f"已离开群组 {payload.chat_id}"}


async def _clean_and_report(context: AppContext, admin_id: int) -> None:
    try:
        result = await admin_ops.clean_deleted_users(context)
    except Exception:
        logger.exception("database cleanup failed")
        await context.client.send_message(admin_id, "数据库整理失败，请查看日志。")
        return
    await context.client.send_message(
        admin_id, f"已成功清除{len(result.deleted)}个已经删号的用户，共有{result.failures}个用户信息获取失败。"
    )


@router.post("/clean")
async def clean_database(request: Request, authorization: AuthHeader = None) -> dict[str, object]:
    user = require_bot_admin(request, authorization)
    context = _context(request)
    count = len(await context.repository.all_blacklist_user_ids())
    # 每个用户都要查询 Telegram，耗时可能超过 HTTP 超时，因此放到后台执行并私聊通知结果
    schedule(_clean_and_report(context, user.id), name=f"miniapp-clean:{user.id}")
    return {"message": f"开始整理 {count} 个黑名单用户，完成后会私聊通知您。"}


@router.get("/logs")
async def get_logs(
    request: Request,
    challenge_id: str | None = None,
    user_id: int | None = None,
    authorization: AuthHeader = None,
) -> dict[str, object]:
    require_bot_admin(request, authorization)
    repository = _context(request).repository
    if challenge_id:
        logs = await repository.logs_by_challenge(challenge_id)
    elif user_id is not None:
        logs = await repository.logs_by_user(user_id)
    else:
        raise HTTPException(400, "请提供验证 ID 或用户 ID")
    return {"logs": [_log_json(record) for record in logs]}


@router.get("/ip/{ip_addr}")
async def users_by_ip(request: Request, ip_addr: str, authorization: AuthHeader = None) -> dict[str, object]:
    require_bot_admin(request, authorization)
    groups = await admin_ops.passed_users_by_ip(_context(request), _checked_ip(ip_addr))
    return {
        "groups": [
            {
                "group_id": group.group_id,
                "title": group.title,
                "users": [
                    {"user_id": user_id, "last_passed_at": passed_at.isoformat() if passed_at else None}
                    for user_id, passed_at in group.users
                ],
            }
            for group in groups
        ]
    }


@router.post("/ip/{ip_addr}/ban")
async def ban_by_ip(
    request: Request, ip_addr: str, payload: BanPayload, authorization: AuthHeader = None
) -> dict[str, object]:
    user = require_bot_admin(request, authorization)
    context = _context(request)
    try:
        result = await admin_ops.ban_users_by_ip(context, _checked_ip(ip_addr), payload.group_id)
    except ChatAdminRequired as exc:
        raise HTTPException(409, "封禁失败: Bot 在该群没有封禁用户权限") from exc
    if result is None:
        raise HTTPException(404, "没有找到在该群通过这个 IP 验证的用户")
    logger.info(
        "banned users by IP via Mini App",
        extra={"admin_id": user.id, "group_id": payload.group_id, "banned": result.success},
    )
    return {
        "success": result.success,
        "failures": [{"user_id": user_id, "error": error} for user_id, error in result.failures],
    }
