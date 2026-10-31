"""新成员第一条消息的反垃圾检测、处置、误判恢复，以及 token 失效时的自动关闭。"""

from __future__ import annotations

import html
import logging
from datetime import date, datetime, timedelta
from functools import partial
from io import BytesIO

from pyrogram import Client, filters
from pyrogram.enums import ParseMode
from pyrogram.errors import ChatAdminRequired, MessageDeleteForbidden, RPCError
from pyrogram.handlers import CallbackQueryHandler, MessageHandler
from pyrogram.types import (
    CallbackQuery,
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    User,
)

from captcha_bot.antispam import (
    ACTION_LABELS,
    MAX_MESSAGE_IMAGES,
    PENDING_MAX_AGE,
    AntispamAction,
    SpamInput,
    Verdict,
    should_disable,
)
from captcha_bot.context import AppContext
from captcha_bot.db.repository import AntispamRecord
from captcha_bot.handlers.common import (
    ChatUnavailable,
    fetch_member_rights,
    full_chat_permissions,
    schedule,
    send_log,
)
from captcha_bot.handlers.config import miniapp_keyboard
from captcha_bot.jev import ErrorKind, Image, JevError

logger = logging.getLogger(__name__)

UNDO_PREFIX = "as:undo:"
NOTICE_DELETE_SECONDS = 120
MAX_IMAGE_BYTES = 5 * 1024 * 1024
LOG_TEXT_LIMIT = 500


def display_name(user: User) -> str:
    return " ".join(part for part in (user.first_name, user.last_name) if part) or str(user.id)


async def _download(client: Client, file_id: str | None, size: int | None = None) -> Image | None:
    if not file_id or (size is not None and size > MAX_IMAGE_BYTES):
        return None
    try:
        data = await client.download_media(file_id, in_memory=True)
    except RPCError, OSError, ValueError:
        logger.warning("failed to download media for antispam", exc_info=True)
        return None
    if not isinstance(data, BytesIO):
        return None
    content = data.getvalue()
    return Image.detect(content) if len(content) <= MAX_IMAGE_BYTES else None


def _message_image_source(message: Message) -> tuple[str | None, int | None]:
    if message.photo:
        return message.photo.file_id, message.photo.file_size
    document = message.document
    if document and document.mime_type in {"image/jpeg", "image/png"}:
        return document.file_id, document.file_size
    # 视频、GIF、圆视频等取缩略图；贴纸的缩略图是 webp，会在 Image.detect 里被丢掉
    for media in (message.video, message.animation, message.video_note, document, message.sticker):
        thumbs = getattr(media, "thumbs", None) if media else None
        if thumbs:
            thumb = thumbs[-1]
            return thumb.file_id, thumb.file_size
    return None, None


def _message_text(message: Message) -> str:
    text = message.text or message.caption or ""
    # 文字链接的真实地址不在正文里
    links = [entity.url for entity in (message.entities or message.caption_entities or []) if entity.url]
    if links:
        text += "\n链接: " + " ".join(links)
    return str(text)


def _forwarded_from(message: Message) -> str | None:
    origin = message.forward_origin
    if origin is None:
        return None
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat is not None:
        username = f" (@{chat.username})" if chat.username else ""
        return f"{chat.title or chat.id}{username}"
    user = getattr(origin, "sender_user", None)
    if user is not None:
        return display_name(user)
    return getattr(origin, "sender_user_name", None) or "未知来源"


def _buttons(message: Message) -> tuple[str, ...]:
    markup = message.reply_markup
    if not isinstance(markup, InlineKeyboardMarkup):
        return ()
    return tuple(
        f"{button.text} {button.url}".strip() if button.url else button.text
        for row in markup.inline_keyboard
        for button in row
    )


async def collect_input(client: Client, messages: list[Message], user: User, *, with_images: bool) -> SpamInput:
    first = messages[0]
    bio: str | None = None
    try:
        bio = (await client.get_chat(user.id)).bio
    except RPCError:
        logger.info("failed to read user bio", extra={"user_id": user.id})
    avatar: Image | None = None
    images: list[Image] = []
    if with_images:
        if user.photo is not None:
            avatar = await _download(client, user.photo.big_file_id)
        for message in messages:
            if len(images) >= MAX_MESSAGE_IMAGES:
                break
            image = await _download(client, *_message_image_source(message))
            if image is not None:
                images.append(image)
    text = "\n".join(part for part in (_message_text(message) for message in messages) if part)
    return SpamInput(
        text=text,
        sender_name=display_name(user),
        username=user.username,
        bio=bio,
        forwarded_from=_forwarded_from(first),
        buttons=_buttons(first),
        avatar=avatar,
        images=tuple(images),
    )


async def notify_setter(context: AppContext, record: AntispamRecord, text: str) -> None:
    """私聊设置 token 的管理员；私聊失败(比如屏蔽了 Bot)时在群里提醒他。"""
    client = context.client
    if record.key_set_by is None:
        return
    try:
        await client.send_message(
            record.key_set_by,
            text,
            parse_mode=ParseMode.DISABLED,
            reply_markup=miniapp_keyboard(context, record.chat_id),
        )
        return
    except RPCError:
        logger.info("failed to DM antispam key owner", extra={"chat_id": record.chat_id})
    mention = f'<a href="tg://user?id={record.key_set_by}">{html.escape(record.key_set_by_name or "设置者")}</a>'
    try:
        await client.send_message(
            record.chat_id,
            f"{mention} {html.escape(text)}\n\n(无法私聊你，请先私聊本 Bot 并在群里发送 /config 处理。)",
            parse_mode=ParseMode.HTML,
        )
    except RPCError:
        logger.exception("failed to notify antispam key owner", extra={"chat_id": record.chat_id})


async def handle_failure(context: AppContext, record: AntispamRecord, error: JevError, chat_title: str) -> None:
    now = datetime.now()
    logger.warning("jev request failed: %s", error.describe(), extra={"chat_id": record.chat_id})
    if error.kind in {ErrorKind.BAD_REQUEST, ErrorKind.RATE_LIMITED}:
        return
    count, first_failure_at = (1, now)
    if error.kind == ErrorKind.FAILURE:
        count, first_failure_at = await context.repository.record_antispam_failure(record.chat_id, now)
    if not should_disable(error, count, first_failure_at, now):
        return
    reason = "token 无效、无权限或余额不足" if error.kind == ErrorKind.KEY else "连续无法访问 jev"
    detail = f"{reason}: {error.describe()}"
    if not await context.repository.disable_antispam(record.chat_id, detail, now):
        return
    await notify_setter(
        context,
        record,
        f"群「{chat_title}」的 AI 反垃圾已自动关闭。\n"
        f"原因：{reason}\n"
        f"状态码：{error.status if error.status is not None else '无'}\n"
        f"报错：{error.message}\n\n"
        "处理好之后请在配置面板中手动重新开启。",
    )


def undo_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("误判，恢复", callback_data=f"{UNDO_PREFIX}{user_id}")]])


async def apply_action(client: Client, chat_id: int, user_id: int, action: AntispamAction) -> None:
    if action == AntispamAction.MUTE:
        await client.restrict_chat_member(chat_id, user_id, permissions=ChatPermissions(can_send_messages=False))
    elif action == AntispamAction.KICK:
        await client.ban_chat_member(chat_id, user_id, until_date=datetime.now() + timedelta(seconds=31))
    elif action == AntispamAction.BAN:
        await client.ban_chat_member(chat_id, user_id)


def log_text(verdict: Verdict, chat_title: str, chat_id: int, user: User, text: str, action: str) -> str:
    scores = "、".join(score.label for score in sorted(verdict.scores, key=lambda s: -s.percent)[:3]) or "无"
    tag = "#ANTISPAM" if verdict.hits else "#ANTISPAM_SUSPECT"
    content = text if len(text) <= LOG_TEXT_LIMIT else f"{text[:LOG_TEXT_LIMIT]}…"
    username = f" @{user.username}" if user.username else ""
    return (
        f"{tag}\n群组: {chat_title} ({chat_id})\n用户: {display_name(user)}{username} ({user.id})\n"
        f"命中: {scores}\n处置: {action}\n图片: {'已送检' if verdict.images_sent else '无'}\n"
        f"内容: {content or '(无文字)'}"
    )


async def check_first_message(context: AppContext, client: Client, message: Message) -> None:
    antispam = context.antispam
    user = message.from_user
    if not antispam.available or user is None or user.is_bot or message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    if not await context.repository.pop_antispam_pending(chat_id, user.id, PENDING_MAX_AGE):
        return
    record = await context.repository.get_antispam(chat_id)
    if record is None or not record.enabled:
        return
    api_key = antispam.api_key(record)
    chat_title = message.chat.title or str(chat_id)
    if api_key is None:
        await handle_failure(
            context, record, JevError(ErrorKind.KEY, "无法解密已保存的 token，可能更换了加密密钥"), chat_title
        )
        return
    today = date.today()
    if await antispam.over_daily_limit(record, today):
        if await context.repository.mark_antispam_limit_notified(chat_id, today):
            await notify_setter(
                context,
                record,
                f"群「{chat_title}」今天的 AI 反垃圾调用已达上限 {record.daily_limit} 次，"
                "今天剩下的新成员不再检测，明天自动恢复。可以在配置面板中调高上限。",
            )
        return

    messages = [message]
    if message.media_group_id:
        try:
            messages = await client.get_media_group(chat_id, message.id)
        except RPCError:
            logger.info("failed to load media group", extra={"chat_id": chat_id})
    spam = await collect_input(client, messages, user, with_images=antispam.settings.send_images)
    config = antispam.group_config(record)
    try:
        verdict = await antispam.evaluate(api_key, config, spam, chat_title)
    except JevError as exc:
        await handle_failure(context, record, exc, chat_title)
        return
    await context.repository.add_antispam_usage(chat_id, today, verdict.input_tokens)
    await context.repository.reset_antispam_failures(chat_id)

    if verdict.outcome == "pass":
        return
    if verdict.outcome == "log":
        await send_log(context, log_text(verdict, chat_title, chat_id, user, spam.text, "未处置(可疑)"), plain=True)
        return

    action = config.action
    label = ACTION_LABELS[action]
    try:
        await client.delete_messages(chat_id, [item.id for item in messages])
    except MessageDeleteForbidden, ChatAdminRequired:
        label = "Bot 无权删除消息"
    try:
        await apply_action(client, chat_id, user.id, action)
    except ChatAdminRequired:
        label += "，Bot 无权限制成员"
    except RPCError:
        logger.exception("failed to apply antispam action", extra={"chat_id": chat_id})
        label += "，处置失败"
    await send_log(context, log_text(verdict, chat_title, chat_id, user, spam.text, label), plain=True)
    top = verdict.top
    reason = top.classifier.name if top else "垃圾信息"
    try:
        notice = await client.send_message(
            chat_id,
            f"已移除 {display_name(user)} 的疑似垃圾消息(原因：{reason})。",
            parse_mode=ParseMode.DISABLED,
            reply_markup=undo_keyboard(user.id) if action != AntispamAction.DELETE else None,
        )
        schedule(notice.delete(), delay=NOTICE_DELETE_SECONDS, name=f"delete-antispam-notice:{notice.id}")
    except RPCError:
        logger.exception("failed to send antispam notice", extra={"chat_id": chat_id})


async def undo_callback(_context: AppContext, client: Client, query: CallbackQuery) -> None:
    message = query.message
    if message is None or message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    try:
        user_id = int(str(query.data).removeprefix(UNDO_PREFIX))
    except ValueError:
        return
    try:
        rights = await fetch_member_rights(client, chat_id, query.from_user.id)
    except ChatUnavailable, RPCError:
        rights = None
    if rights is None or not rights.can_restrict_members:
        await client.answer_callback_query(query.id, "只有能限制成员的管理员可以恢复")
        return
    try:
        await client.unban_chat_member(chat_id, user_id)
        await client.restrict_chat_member(chat_id, user_id, permissions=full_chat_permissions())
    except ChatAdminRequired:
        await client.answer_callback_query(query.id, "Bot 没有限制成员的权限")
        return
    except RPCError:
        # 用户已被移出群组时无法恢复发言权限，解封即可
        logger.info("antispam undo partially applied", extra={"chat_id": chat_id, "user_id": user_id})
    try:
        await client.edit_message_text(
            chat_id,
            message.id,
            f"已由 {display_name(query.from_user)} 标记为误判并恢复。被删除的消息无法找回。",
            parse_mode=ParseMode.DISABLED,
        )
    except RPCError:
        logger.info("failed to edit antispam notice", extra={"chat_id": chat_id})
    await client.answer_callback_query(query.id, "已恢复")


def register_antispam_handlers(client: Client, context: AppContext) -> None:
    client.add_handler(MessageHandler(partial(check_first_message, context), filters.group & ~filters.service), group=2)
    # 放在 -1 组，先于验证题的回调路由处理
    client.add_handler(
        CallbackQueryHandler(partial(undo_callback, context), filters.regex(f"^{UNDO_PREFIX}")), group=-1
    )
