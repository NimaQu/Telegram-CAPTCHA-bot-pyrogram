"""/report：群成员回复一条消息发起举报投票，票数够了交给 jev 判断，是垃圾信息就按群配置处置。"""

from __future__ import annotations

import logging
from functools import partial
from typing import Any

from pyrogram import Client, filters
from pyrogram.enums import ParseMode
from pyrogram.errors import MessageDeleteForbidden, RPCError
from pyrogram.handlers import CallbackQueryHandler, MessageHandler
from pyrogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from captcha_bot.antispam import AntispamAction, ReportVote, report_context
from captcha_bot.context import AppContext
from captcha_bot.handlers.antispam import (
    NOTICE_DELETE_SECONDS,
    display_name,
    enforce,
    judge_messages,
    log_text,
    media_group,
    prepare,
    reason_text,
    report_debug,
    undo_keyboard,
)
from captcha_bot.handlers.common import ChatUnavailable, fetch_member_rights, schedule, send_log

logger = logging.getLogger(__name__)

VOTE_PREFIX = "as:vote:"
HINT_DELETE_SECONDS = 15
# 投票一直凑不够人时，多久后撤掉
VOTE_TTL_SECONDS = 3600


def vote_keyboard(message_id: int, votes: int, needed: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(f"同意交给 AI 判断 ({votes}/{needed})", callback_data=f"{VOTE_PREFIX}{message_id}")]]
    )


async def _is_admin(client: Client, chat_id: int, user_id: int) -> bool:
    try:
        return (await fetch_member_rights(client, chat_id, user_id)).is_admin
    except ChatUnavailable, RPCError:
        return False


async def _hint(message: Message, text: str) -> None:
    try:
        reply = await message.reply(text, quote=False)
        schedule(reply.delete(), delay=HINT_DELETE_SECONDS, name=f"delete-report-hint:{reply.id}")
    except RPCError:
        logger.info("failed to send report hint")


async def _edit_poll(client: Client, vote: ReportVote, text: str, markup: InlineKeyboardMarkup | None = None) -> None:
    kwargs: dict[str, Any] = {"reply_markup": markup} if markup else {}
    try:
        await client.edit_message_text(
            vote.chat_id, vote.poll_message_id, text, parse_mode=ParseMode.DISABLED, **kwargs
        )
    except RPCError:
        logger.info("failed to edit report poll", extra={"chat_id": vote.chat_id})


def _finish(context: AppContext, client: Client, vote: ReportVote) -> None:
    context.antispam.reports.pop((vote.chat_id, vote.message_id), None)
    schedule(
        client.delete_messages(vote.chat_id, vote.poll_message_id),
        delay=NOTICE_DELETE_SECONDS,
        name=f"delete-report-poll:{vote.poll_message_id}",
    )


async def _expire(context: AppContext, client: Client, vote: ReportVote) -> None:
    if context.antispam.reports.get((vote.chat_id, vote.message_id)) is not vote or vote.judging:
        return
    context.antispam.reports.pop((vote.chat_id, vote.message_id), None)
    await client.delete_messages(vote.chat_id, vote.poll_message_id)


async def judge_report(context: AppContext, client: Client, vote: ReportVote, chat_title: str) -> None:
    vote.judging = True
    await _edit_poll(client, vote, f"已有 {len(vote.voters)} 人同意，正在交给 AI 判断…")
    try:
        await _judge(context, client, vote, chat_title)
    finally:
        _finish(context, client, vote)


async def _judge(context: AppContext, client: Client, vote: ReportVote, chat_title: str) -> None:
    prepared = await prepare(context, vote.chat_id, chat_title)
    if prepared is None:
        await _edit_poll(client, vote, "AI 反垃圾暂时不可用，请等待管理员处理。")
        return
    record, api_key = prepared
    try:
        target = await client.get_messages(vote.chat_id, vote.message_id)
    except RPCError:
        target = None
    if target is None or isinstance(target, list) or target.empty or target.from_user is None:
        await _edit_poll(client, vote, "被举报的消息已经不存在了。")
        return
    user = target.from_user
    messages = await media_group(client, target)
    source = f"举报({len(vote.voters)} 人)"
    judged = await judge_messages(
        context,
        client,
        record,
        api_key,
        messages,
        user,
        chat_title,
        source=source,
        jev_context=report_context(chat_title, len(vote.voters)),
    )
    if judged is None:
        await _edit_poll(client, vote, "AI 暂时无法判断，请等待管理员处理。")
        return
    verdict, spam = judged.verdict, judged.spam
    if verdict.outcome == "pass":
        await _edit_poll(client, vote, "AI 认为这条消息不是垃圾信息，未做处理。")
        await report_debug(context, client, judged, record, user, chat_title, source, "放行", undo=False)
        return
    if verdict.outcome == "log":
        text = log_text(verdict, chat_title, vote.chat_id, user, spam.text, "未处置(可疑)", source)
        await send_log(context, text, plain=True)
        await _edit_poll(client, vote, "AI 不能确定这条消息是否为垃圾信息，已记录给管理员查看。")
        await report_debug(context, client, judged, record, user, chat_title, source, "可疑，仅记录", undo=False)
        return
    label = await enforce(context, client, record, messages, user, verdict, spam, chat_title, source)
    action = context.antispam.group_config(record).action
    undo = action != AntispamAction.DELETE
    await _edit_poll(
        client,
        vote,
        f"AI 判定 {display_name(user)} 的消息为垃圾信息({reason_text(verdict)})，已{label}。",
        undo_keyboard(user.id) if undo else None,
    )
    await report_debug(context, client, judged, record, user, chat_title, source, label, undo=undo)


async def report_command(context: AppContext, client: Client, message: Message) -> None:
    if message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    try:
        await message.delete()
    except MessageDeleteForbidden, RPCError:
        logger.info("failed to delete /report command", extra={"chat_id": chat_id})
    reporter = message.from_user
    if reporter is None:
        return
    antispam = context.antispam
    record = await context.repository.get_antispam(chat_id) if antispam.available else None
    needed = antispam.group_config(record).report_votes if record else 0
    if record is None or not record.enabled or needed == 0:
        await _hint(message, "本群没有开启举报功能。")
        return
    target = message.reply_to_message
    if target is None or target.empty:
        await _hint(message, "请回复要举报的消息再发送 /report。")
        return
    author = target.from_user
    if author is None or author.is_bot or await _is_admin(client, chat_id, author.id):
        await _hint(message, "这条消息不能被举报。")
        return
    if author.id == reporter.id:
        await _hint(message, "不能举报自己的消息。")
        return
    key = (chat_id, target.id)
    vote = antispam.reports.get(key)
    if vote is None:
        poll = await client.send_message(
            chat_id,
            f"{display_name(reporter)} 举报了这条消息。如果你也认为它是垃圾信息，请点击下方按钮，"
            f"满 {needed} 人后交给 AI 判断。",
            reply_to_message_id=target.id,
            parse_mode=ParseMode.DISABLED,
            reply_markup=vote_keyboard(target.id, 1, needed),
        )
        vote = ReportVote(chat_id, target.id, author.id, poll.id, {reporter.id})
        antispam.reports[key] = vote
        schedule(_expire(context, client, vote), delay=VOTE_TTL_SECONDS, name=f"expire-report:{poll.id}")
    elif not vote.judging:
        vote.voters.add(reporter.id)
    await _count(context, client, vote, needed, message.chat.title or str(chat_id), reporter.id)


async def _count(
    context: AppContext, client: Client, vote: ReportVote, needed: int, chat_title: str, voter_id: int
) -> None:
    if vote.judging:
        return
    # 管理员同意直接送检
    if len(vote.voters) >= needed or await _is_admin(client, vote.chat_id, voter_id):
        await judge_report(context, client, vote, chat_title)
        return
    try:
        await client.edit_message_reply_markup(
            vote.chat_id,
            vote.poll_message_id,
            reply_markup=vote_keyboard(vote.message_id, len(vote.voters), needed),
        )
    except RPCError:
        logger.info("failed to update report poll", extra={"chat_id": vote.chat_id})


async def vote_callback(context: AppContext, client: Client, query: CallbackQuery) -> None:
    message = query.message
    if message is None or message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    try:
        message_id = int(str(query.data).removeprefix(VOTE_PREFIX))
    except ValueError:
        return
    vote = context.antispam.reports.get((chat_id, message_id))
    if vote is None or vote.judging:
        await client.answer_callback_query(query.id, "这次举报已经结束了")
        return
    voter = query.from_user.id
    if voter == vote.target_user_id:
        await client.answer_callback_query(query.id, "不能给针对自己的举报投票")
        return
    if voter in vote.voters:
        await client.answer_callback_query(query.id, "你已经投过票了")
        return
    vote.voters.add(voter)
    await client.answer_callback_query(query.id, "已记录你的投票")
    record = await context.repository.get_antispam(chat_id)
    needed = context.antispam.group_config(record).report_votes if record else 0
    await _count(context, client, vote, max(needed, 1), message.chat.title or str(chat_id), voter)


def register_report_handlers(client: Client, context: AppContext) -> None:
    client.add_handler(MessageHandler(partial(report_command, context), filters.command("report") & filters.group))
    client.add_handler(
        CallbackQueryHandler(partial(vote_callback, context), filters.regex(f"^{VOTE_PREFIX}")), group=-1
    )
