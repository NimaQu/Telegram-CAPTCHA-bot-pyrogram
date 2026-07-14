from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from functools import partial

from pyrogram import Client, filters
from pyrogram.enums import ChatMemberStatus
from pyrogram.enums.chat_type import ChatType
from pyrogram.enums.message_service_type import MessageServiceType
from pyrogram.errors import (
    ChannelPrivate,
    ChatAdminRequired,
    MessageDeleteForbidden,
    MessageNotModified,
    RPCError,
    UserIsBlocked,
)
from pyrogram.handlers import CallbackQueryHandler, ChatJoinRequestHandler, ChatMemberUpdatedHandler, MessageHandler
from pyrogram.types import CallbackQuery, ChatJoinRequest, ChatMemberUpdated, ChatPermissions, Message

from captcha_bot.challenges import (
    ChallengeKind,
    ChallengeSession,
    MathChallenge,
    new_turnstile_id,
    turnstile_auth_keyboard,
    turnstile_auth_url,
    turnstile_group_keyboard,
)
from captcha_bot.config import ChallengeType
from captcha_bot.context import AppContext
from captcha_bot.handlers.common import (
    apply_failed_action,
    can_restrict_members,
    full_chat_permissions,
    schedule,
    send_log,
)

logger = logging.getLogger(__name__)


async def start_command(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not message.command or len(message.command) != 2:
        await message.reply(context.config.settings.messages.start_message)
        return
    try:
        chat_id = int(message.command[1])
    except ValueError:
        await message.reply(context.config.settings.messages.start_message)
        return
    if chat_id >= 0:
        await message.reply(context.config.settings.messages.start_message)
        return
    session = await context.registry.find(message.from_user.id, chat_id)
    if session is None or session.kind != ChallengeKind.TURNSTILE or not session.turnstile_id:
        await message.reply("这不是你的验证数据，请确认是否点击了正确的按钮")
        return
    url = turnstile_auth_url(context.config.settings.turnstile.base_url, session.turnstile_id)
    await message.reply(
        "点击下方按钮完成验证，您需要使用浏览器来完成，如果您在访问页面时出现问题，请尝试关闭匿名代理\n\n",
        reply_markup=turnstile_auth_keyboard(url),
    )


async def _register_session(context: AppContext, session: ChallengeSession, delay_seconds: int) -> bool:
    return await context.registry.register(session, delay_seconds, partial(challenge_timeout, context))


async def on_chat_join_request(context: AppContext, client: Client, request: ChatJoinRequest) -> None:
    user_id, chat_id = request.from_user.id, request.chat.id
    if chat_id is None:
        return
    if await context.registry.contains_user(user_id, chat_id):
        return
    policy = await context.policies.get(chat_id)
    message_id: int | None = None
    answer: int | None = None
    turnstile_id: str | None = None
    kind: ChallengeKind
    if policy.challenge_type == ChallengeType.RECAPTCHA:
        kind = ChallengeKind.TURNSTILE
        turnstile_id = new_turnstile_id()
        url = turnstile_auth_url(context.config.settings.turnstile.base_url, turnstile_id)
        try:
            sent = await client.send_message(
                user_id,
                f"请在{policy.challenge_timeout}秒内点击下方按钮完成验证，您需要使用浏览器来完成。\n\n",
                reply_markup=turnstile_auth_keyboard(url),
            )
            message_id = sent.id
        except UserIsBlocked:
            await send_log(context, f"用户 `{user_id}` 屏蔽了机器人，无法发送验证消息")
    else:
        kind = ChallengeKind.MATH
        challenge = MathChallenge()
        answer = challenge.answer
        try:
            sent = await client.send_message(
                user_id,
                context.config.settings.messages.challenge_math_private.format(
                    challenge=challenge.question, timeout=policy.challenge_timeout
                ),
                reply_markup=challenge.join_request_keyboard(chat_id),
            )
            message_id = sent.id
        except UserIsBlocked:
            logger.info("join request user blocked bot", extra={"user_id": user_id, "chat_id": chat_id})
    session = ChallengeSession(
        key=f"{chat_id}|{user_id}",
        kind=kind,
        chat_id=chat_id,
        user_id=user_id,
        chat_title=request.chat.title or str(chat_id),
        message_id=message_id,
        answer=answer,
        turnstile_id=turnstile_id,
        join_request=True,
    )
    await _register_session(context, session, policy.challenge_timeout)


async def on_chat_member_updated(context: AppContext, client: Client, update: ChatMemberUpdated) -> None:
    if update.via_join_request or update.new_chat_member is None or update.chat.type == ChatType.CHANNEL:
        return
    member = update.new_chat_member
    target = member.user
    chat_id = update.chat.id
    if chat_id is None:
        return
    if update.old_chat_member is not None or member.status != ChatMemberStatus.MEMBER:
        return
    if target.is_self:
        try:
            await client.send_message(chat_id, context.config.settings.messages.self_introduction)
            await send_log(
                context,
                context.config.settings.messages.into_group.format(
                    groupid=chat_id, grouptitle=update.chat.title or str(chat_id)
                ),
            )
        except ChannelPrivate:
            pass
        return
    if update.from_user is None or update.from_user.id != target.id:
        return
    user_id = target.id
    policy = await context.policies.get(chat_id)

    if policy.enable_global_blacklist:
        blacklisted = await context.repository.get_blacklist_user(user_id)
        if blacklisted is not None:
            now = datetime.now()
            since_last_attempt = (now - blacklisted.last_attempt).total_seconds()
            if since_last_attempt > policy.global_timeout_user_blacklist_remove:
                cache = ChallengeSession(
                    key=f"{chat_id}|auto:{user_id}",
                    kind=ChallengeKind.AUTO_KICK,
                    chat_id=chat_id,
                    user_id=user_id,
                    chat_title=update.chat.title or str(chat_id),
                )
                await _register_session(context, cache, 5)
                await client.ban_chat_member(chat_id, user_id, until_date=now + timedelta(seconds=31))
                attempts = await context.repository.record_auto_kick(user_id, now)
                await send_log(
                    context,
                    context.config.settings.messages.failed_auto_kick.format(
                        targetuserid=user_id,
                        targetusername=target.username,
                        targetfirstname=target.first_name,
                        targetlastname=target.last_name,
                        groupid=chat_id,
                        grouptitle=update.chat.title,
                        lastattempt=blacklisted.last_attempt.strftime("%Y-%m-%d %H:%M:%S"),
                        sincelastattempt=timedelta(seconds=since_last_attempt),
                        trycount=attempts,
                    ),
                )
                return
            await context.repository.remove_blacklist_users(user_id)

    if await context.registry.contains_user(user_id, chat_id):
        logger.warning("duplicate challenge ignored", extra={"user_id": user_id, "chat_id": chat_id})
        return
    try:
        await client.restrict_chat_member(chat_id, user_id, permissions=ChatPermissions(can_send_messages=False))
    except ChatAdminRequired:
        return
    except RPCError:
        await client.send_message(chat_id, "当前群组不是超级群组，Bot 无法工作，可能是成员过少。")
        return

    turnstile_id: str | None = None
    answer: int | None = None
    if policy.challenge_type == ChallengeType.RECAPTCHA:
        kind = ChallengeKind.TURNSTILE
        turnstile_id = new_turnstile_id()
        reply = await client.send_message(
            chat_id,
            context.config.settings.messages.challenge_recaptcha.format(
                target_id=user_id, timeout=policy.challenge_timeout
            ),
            reply_markup=turnstile_group_keyboard(
                context.config.settings.bot.username,
                chat_id,
                context.config.settings.messages.approve_manually,
                context.config.settings.messages.refuse_manually,
            ),
        )
    else:
        kind = ChallengeKind.MATH
        challenge = MathChallenge()
        answer = challenge.answer
        reply = await client.send_message(
            chat_id,
            context.config.settings.messages.challenge_math.format(
                target_id=user_id, timeout=policy.challenge_timeout, challenge=challenge.question
            ),
            reply_markup=challenge.group_keyboard(
                context.config.settings.messages.approve_manually,
                context.config.settings.messages.refuse_manually,
            ),
        )
    session = ChallengeSession(
        key=f"{chat_id}|{reply.id}",
        kind=kind,
        chat_id=chat_id,
        user_id=user_id,
        chat_title=update.chat.title or str(chat_id),
        message_id=reply.id,
        answer=answer,
        turnstile_id=turnstile_id,
    )
    await _register_session(context, session, policy.challenge_timeout)


async def delete_pending_messages(context: AppContext, _client: Client, message: Message) -> None:
    if message.chat is None:
        return
    chat_id = message.chat.id
    if chat_id is None:
        return
    if message.service:
        if message.service in {MessageServiceType.NEW_CHAT_MEMBERS, MessageServiceType.LEFT_CHAT_MEMBER}:
            try:
                await message.delete()
            except MessageDeleteForbidden:
                pass
        return
    if message.from_user is None:
        return
    await asyncio.sleep(1)
    if not await context.registry.contains_user(message.from_user.id, chat_id):
        return
    try:
        await message.delete()
    except MessageDeleteForbidden:
        return
    await send_log(
        context,
        context.config.settings.messages.message_deleted.format(
            targetuserid=message.from_user.id,
            messageid=message.id,
            groupid=chat_id,
            grouptitle=message.chat.title,
        ),
    )


async def callback_router(context: AppContext, client: Client, query: CallbackQuery) -> None:
    data = str(query.data or "")
    if "|" in data:
        await private_math_callback(context, client, query, data)
    elif data in {"+", "-"}:
        await admin_callback(context, client, query, data)
    else:
        await math_callback(context, client, query, data)


async def private_math_callback(context: AppContext, client: Client, query: CallbackQuery, data: str) -> None:
    if query.message is None:
        return
    try:
        answer_text, chat_text = data.split("|", maxsplit=1)
        chat_id = int(chat_text)
    except ValueError:
        return
    key = f"{chat_id}|{query.from_user.id}"
    current = await context.registry.get(key)
    if current is None or current.user_id != query.from_user.id:
        return
    session = await context.registry.claim(key)
    if session is None:
        return
    correct = str(session.answer) == answer_text
    if correct:
        await client.approve_chat_join_request(chat_id, session.user_id)
        await client.edit_message_text(
            session.user_id, query.message.id, context.config.settings.messages.challenge_passed
        )
        await send_log(
            context,
            context.config.settings.messages.passed_answer.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
    else:
        await client.edit_message_text(
            session.user_id, query.message.id, context.config.settings.messages.challenge_failed
        )
        await client.decline_chat_join_request(chat_id, session.user_id)
        await send_log(
            context,
            context.config.settings.messages.failed_answer.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
    await client.answer_callback_query(query.id)


async def admin_callback(context: AppContext, client: Client, query: CallbackQuery, action: str) -> None:
    if query.message is None or query.message.chat is None:
        return
    chat_id, message_id = query.message.chat.id, query.message.id
    if chat_id is None:
        return
    key = f"{chat_id}|{message_id}"
    current = await context.registry.get(key)
    if current is None:
        return
    policy = await context.policies.get(chat_id)
    if not await can_restrict_members(client, chat_id, query.from_user.id):
        await client.answer_callback_query(query.id, context.config.settings.messages.permission_denied)
        return
    session = await context.registry.claim(key)
    if session is None:
        return
    if action == "+":
        try:
            await client.restrict_chat_member(chat_id, session.user_id, permissions=full_chat_permissions())
        except ChatAdminRequired:
            await client.answer_callback_query(query.id, context.config.settings.messages.bot_no_permission)
            return
        await client.edit_message_text(
            chat_id,
            message_id,
            context.config.settings.messages.approved.format(user=query.from_user.first_name),
        )
        await send_log(
            context,
            context.config.settings.messages.passed_admin.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
    else:
        try:
            await client.ban_chat_member(chat_id, session.user_id)
        except ChatAdminRequired:
            await client.answer_callback_query(query.id, context.config.settings.messages.bot_no_permission)
            return
        await client.edit_message_text(
            chat_id,
            message_id,
            context.config.settings.messages.refused.format(user=query.from_user.first_name),
        )
        if policy.delete_failed_challenge:
            schedule(
                client.delete_messages(chat_id, message_id),
                delay=policy.delete_failed_challenge_interval,
                name=f"delete-failed:{key}",
            )
        await send_log(
            context,
            context.config.settings.messages.failed_admin.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
    await client.answer_callback_query(query.id)


async def math_callback(context: AppContext, client: Client, query: CallbackQuery, answer: str) -> None:
    if query.message is None or query.message.chat is None:
        return
    chat_id, message_id = query.message.chat.id, query.message.id
    if chat_id is None:
        return
    key = f"{chat_id}|{message_id}"
    current = await context.registry.get(key)
    if current is None or current.kind != ChallengeKind.MATH:
        return
    if query.from_user.id != current.user_id:
        await client.answer_callback_query(query.id, context.config.settings.messages.challenge_not_for_you)
        return
    session = await context.registry.claim(key)
    if session is None:
        return
    policy = await context.policies.get(chat_id)
    try:
        await client.restrict_chat_member(chat_id, session.user_id, permissions=full_chat_permissions())
    except ChatAdminRequired:
        pass
    correct = str(session.answer) == answer
    if correct:
        try:
            await client.edit_message_text(chat_id, message_id, context.config.settings.messages.challenge_passed)
        except MessageNotModified:
            logger.info("challenge result message already updated", extra={"challenge_key": key})
        await send_log(
            context,
            context.config.settings.messages.passed_answer.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
    else:
        await client.edit_message_text(chat_id, message_id, context.config.settings.messages.challenge_failed)
        await send_log(
            context,
            context.config.settings.messages.failed_answer.format(
                targetuserid=session.user_id, groupid=chat_id, grouptitle=session.chat_title
            ),
        )
        await apply_failed_action(client, chat_id, session.user_id, policy.challenge_failed_action)
        if policy.delete_failed_challenge:
            schedule(
                client.delete_messages(chat_id, message_id),
                delay=policy.delete_failed_challenge_interval,
                name=f"delete-failed:{key}",
            )
    if correct and policy.delete_passed_challenge:
        schedule(
            client.delete_messages(chat_id, message_id),
            delay=policy.delete_passed_challenge_interval,
            name=f"delete-passed:{key}",
        )
    await client.answer_callback_query(query.id)


async def challenge_timeout(context: AppContext, session: ChallengeSession) -> None:
    if session.kind == ChallengeKind.AUTO_KICK:
        return
    policy = await context.policies.get(session.chat_id)
    messages = context.config.settings.messages
    if session.join_request:
        try:
            await context.client.decline_chat_join_request(session.chat_id, session.user_id)
            if session.message_id is not None:
                await context.client.edit_message_text(
                    session.user_id, session.message_id, "验证已超时，请重新加群尝试"
                )
        except RPCError:
            logger.exception("failed to expire join request", extra={"challenge_key": session.key})
    else:
        if session.message_id is not None:
            try:
                await context.client.edit_message_text(session.chat_id, session.message_id, messages.challenge_failed)
            except RPCError:
                logger.exception("failed to edit timed out challenge", extra={"challenge_key": session.key})
        await apply_failed_action(context.client, session.chat_id, session.user_id, policy.challenge_timeout_action)
        if policy.delete_failed_challenge and session.message_id is not None:
            schedule(
                context.client.delete_messages(session.chat_id, session.message_id),
                delay=policy.delete_failed_challenge_interval,
                name=f"delete-timeout:{session.key}",
            )
        if policy.enable_global_blacklist:
            await context.repository.record_blacklist_timeout(datetime.now(), session.user_id)
    await send_log(
        context,
        messages.failed_timeout.format(
            targetuserid=session.user_id,
            targetusername="None",
            targetfirstname="None",
            targetlastname="None",
            groupid=session.chat_id,
            grouptitle=session.chat_title,
        ),
    )


def register_challenge_handlers(client: Client, context: AppContext) -> None:
    client.add_handler(MessageHandler(partial(start_command, context), filters.command("start") & filters.private))
    client.add_handler(MessageHandler(partial(delete_pending_messages, context), filters.group), group=1)
    client.add_handler(ChatJoinRequestHandler(partial(on_chat_join_request, context)))
    client.add_handler(ChatMemberUpdatedHandler(partial(on_chat_member_updated, context)))
    client.add_handler(CallbackQueryHandler(partial(callback_router, context)))
