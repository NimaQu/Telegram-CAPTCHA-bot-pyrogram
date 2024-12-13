# !/usr/bin/env python3
# -*- coding: UTF-8 -*-
import asyncio
import json
import logging
import threading
# import time
from datetime import datetime, timedelta
from configparser import ConfigParser

from pyrogram import Client, filters
from pyrogram.enums import ChatMemberStatus
from pyrogram.errors import ChatAdminRequired, ChannelPrivate, MessageNotModified, RPCError, BadRequest, \
    MessageDeleteForbidden, UserNotParticipant
from pyrogram.enums.chat_members_filter import ChatMembersFilter
from pyrogram.enums.message_service_type import MessageServiceType
from pyrogram.enums.chat_type import ChatType
from pyrogram.types import (InlineKeyboardMarkup, User, Message, ChatPermissions, CallbackQuery,
                            ChatMemberUpdated, ChatMember, Chat)
from Timer import Timer
from challenge.math import Math
from challenge.recaptcha import ReCAPTCHA
from challenge.autokickcache import AutoKickCache
import dbhelper as db
from challengedata import ChallengeData
from waitress import serve
from urllib.parse import urlparse
from model import ChallengeType, FailedAction
from ai import chk_message
import base64

# db = DBHelper()

_start_message = "YABE!"
# _challenge_scheduler = sched.scheduler(time, sleep)
_current_challenges = ChallengeData()
_cch_lock = threading.Lock()
_config = dict()
admin_operate_filter = filters.create(lambda _, __, query: query.data.split(" ")[0] in ["+", "-"])

'''
读 只 读 配 置
'''
cf = ConfigParser()  # 启用ConfigParser读取那些启动后即不会再被更改的数据，如BotToken等
cf.read("config.ini", encoding="utf-8")
_admin_user = cf.getint("bot", "admin")
_token = cf.get("bot", "token")
_api_id = cf.getint("bot", "api_id")
_api_hash = cf.get("bot", "api_hash")
_channel = cf.getint("bot", "channel")
logging.basicConfig(level=logging.INFO)


# 设置一下日志记录，能够在诸如 systemctl status captchabot 这样的地方获得详细输出。

def start_web(client: Client):
    import web
    port = cf.getint('web', 'flask_port')
    host = cf.get('web', 'flask_host')
    web.app.secret_key = cf.get('web', 'flask_secret_key')
    web.client = client
    web._current_challenges = _current_challenges
    web._config = _config
    web._channel = _channel
    if cf.getboolean('web', 'development'):
        web.app.env = 'development '
        web.app.run(host=host, port=port)
    else:
        serve(web.app, host=host, port=port)


def load_config():
    global _config
    with open("config.json", encoding="utf-8") as f:
        _config = json.load(f)


def save_config():
    with open("config.json", "w", encoding='utf8') as f:
        json.dump(_config, f, indent=4, ensure_ascii=False)


def get_group_config(chat_id):
    try:
        int(chat_id)
    except ValueError:
        return None
    file_config = _config.get(chat_id, _config["*"])
    db_config = db.get_group_config(chat_id, 'all')
    if db_config is None:
        return file_config
    else:
        final_config = {**file_config, **db_config}
        return final_config


def extract_ids(url: str) -> (int | str, int):
    # 解析 URL
    parsed = urlparse(url)
    # 提取路径部分
    path = parsed.path

    if '/c/' in path:
        # 私有群组链接
        path_parts = path.split('/')
        chat_id = int(path_parts[-2])
        message_id = int(path_parts[-1])
        # chat_id 需要加上 -100 前缀
        return str(-100) + str(chat_id), message_id
    else:
        # 公共群组链接，chat_id 为用户名，message_id 为最后一部分
        chat_id = path.split('/')[-2]
        message_id = int(path.split('/')[-1])
        return chat_id, message_id


def _update(app):
    @app.on_message(filters.command("reload") & filters.private)
    async def reload_cfg(client: Client, message: Message):
        _me: User = await client.get_me()
        logging.info(message.text)
        if message.from_user.id == _admin_user:
            save_config()
            load_config()
            await message.reply("配置已成功重载。")
        else:
            logging.info("Permission denied, admin user in config is:" + str(_admin_user))
            pass

    @app.on_message(filters.command("help") & filters.group)
    async def helping_cmd(client: Client, message: Message):
        _me: User = await client.get_me()
        logging.info(message.text)
        await message.reply(_config["msg_self_introduction"],
                            disable_web_page_preview=True)

    @app.on_message(filters.command("ping") & filters.private)
    async def ping_command(client: Client, message: Message):
        await message.reply("poi~")

    @app.on_message(filters.command("start") & filters.private)
    async def start_command(client: Client, message: Message):
        user_id = message.from_user.id
        if len(message.command) != 2:
            await message.reply(_start_message)
            return
        try:
            from_chat_id = int(message.command[1])
        except ValueError:
            await message.reply(_start_message)
            return

        if from_chat_id >= 0:
            await message.reply(_start_message)
            return
        ch_id, challenge_data = _current_challenges.get_by_user_and_chat_id(user_id, from_chat_id)

        if challenge_data is None or ch_id is None:
            await message.reply("这不是你的验证数据，请确认是否点击了正确的按钮")
            return
        else:
            challenge, target_id, timeout_event = challenge_data

        await message.reply("点击下方按钮完成验证，您需要使用浏览器来完成\n\n",
                            reply_markup=InlineKeyboardMarkup(challenge.generate_auth_button()))

    @app.on_message(filters.command("admin", prefixes="@") & filters.group)
    async def call_admin(client: Client, message: Message):
        administrators: list[ChatMember] = []
        me: User = await client.get_me()
        async for m in app.get_chat_members(message.chat.id, filter=ChatMembersFilter.ADMINISTRATORS):
            administrators.append(m)
        text = ""
        for admin in administrators:
            if admin.user.id == me.id:
                continue
            # 检查是否有删除消息的权限
            if not admin.privileges.can_restrict_members or not admin.privileges.can_delete_messages:
                continue
            if admin.user.is_bot:
                continue
            text += f"{admin.user.mention('admin')} "
        if text == "":
            await message.reply("没有找到可用的管理员")
            return
        msg = await message.reply(text)
        Timer(msg.delete(), 300)

    @app.on_message(filters.command("leave") & filters.private)
    async def leave_command(client: Client, message: Message):
        chat_id = message.text.split()[-1]
        if message.from_user.id == _admin_user:
            try:
                await client.send_message(int(chat_id),
                                          _config["msg_leave_msg"])
                await client.leave_chat(int(chat_id), True)
            except RPCError:
                await message.reply("指令出错了！可能是bot不在参数所在群里。")
            else:
                await message.reply("已离开群组: `" + chat_id + "`", )
                _me: User = await client.get_me()
                try:
                    await client.send_message(
                        int(_channel),
                        _config["msg_leave_group"].format(
                            groupid=chat_id,
                        ))
                except Exception as e:
                    logging.error(str(e))
        else:
            pass

    @app.on_message(filters.command("clean") & filters.private)
    async def clean_database(client: Client, message: Message):
        if message.from_user.id == _admin_user:
            failed_count = success_count = 0
            deleted_users = []
            user_id_list = db.get_all_user_ids()
            estimated_time = timedelta(seconds=int(len(user_id_list) / 4))
            await message.reply("开始整理数据库，请稍等...\n预计需要时间:{}".format(estimated_time))
            for x in user_id_list:
                try:
                    user = await client.get_users(x)
                except BadRequest:
                    deleted_users.append(x)
                    failed_count += 1
                    continue
                if user.is_deleted:
                    deleted_users.append(x)
                    # 因为 db 用的是 executemany ，得传一个 tuple 进去，所以必须得这么写，不知道有没有更好的方法
                    success_count += 1
            db.delete_users_by_id(deleted_users)
            await message.reply(
                "已成功清除{}个已经删号的用户，共有{}个用户信息获取失败。".format(success_count, failed_count))
        else:
            logging.info("Permission denied, admin user in config is:" + str(_admin_user))
            return

    @app.on_message(filters.command("faset") & filters.group)
    async def set_config(client: Client, message: Message):
        if message.from_user is None:
            await message.reply("请从个人账号发送指令。")
            return
        chat_id = message.chat.id
        group_config = get_group_config(chat_id)
        user_id = message.from_user.id
        admins = []
        async for m in client.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
            admins.append(m)
        help_message = "使用方法:\n" \
                       "/faset [配置项] [值]\n\n" \
                       "配置项:\n" \
                       "`challenge_failed_action`: 验证失败的动作，值为 `ban` 封禁或 `kick` 踢出\n" \
                       "`challenge_timeout_action`: 验证超时的动作，值为 `ban` 封禁或 `kick` 踢出\n" \
                       "`challenge_timeout`: 验证超时时间，单位为秒\n" \
                       "`challenge_type`: 验证方法，当前可用为数学题 `math` 或 `reCAPTCHA` 谷歌验证码\n" \
                       "`enable_global_blacklist`: 是否启用全局黑名单，值为 `1` 启用或 `0` 禁用\n" \
                       "例如: \n" \
                       "`/faset challenge_type reCAPTCHA`"
        if not any([
            admin.user.id == user_id and
            (admin.status == "creator" or admin.privileges.can_restrict_members)
            for admin in admins
        ]):
            msg = await message.reply(group_config["msg_permission_denied"])
            Timer(msg.delete(), 5)
            Timer(message.delete(), 5)
            return

        args = message.text.split(" ", maxsplit=3)
        if len(args) != 3:
            await message.reply(help_message)
            return
        key = args[1]
        value = args[2]
        try:
            db.set_group_config(chat_id, key, value)
            await message.reply("配置项设置成功")
        except ValueError as e:
            await message.reply(str(e))

    @app.on_message(filters.command("report") & filters.group)
    async def report_message(client: Client, message: Message):
        if message.reply_to_message is None:
            await message.reply("请回复一条消息")
            return
        reply_message = message.reply_to_message
        image_url = ""
        if reply_message.from_user is not None:
            reply_message.chat = await client.get_chat(reply_message.from_user.id)
        else:
            reply_message.chat = await client.get_chat(reply_message.sender_chat.id)
        if reply_message.photo:
            file = await client.download_media(reply_message.photo.file_id, in_memory=True)
            file_ext = file.name.split('.')[-1]
            file_bytes = bytes(file.getbuffer())
            image_url = f"data:image/{file_ext};base64,{base64.b64encode(file_bytes).decode('utf-8')}"
            print(image_url)
        result = await chk_message(api_key="sk-", message=reply_message, image_url=image_url, max_token=512)
        if result.possibility > 85:
            logging.info(f"AI 判断为垃圾消息，概率为 {result.possibility}%")
            await client.ban_chat_member(message.chat.id, reply_message.chat.id if reply_message.from_user is None else reply_message.from_user.id)

    @app.on_message(filters.private & filters.command("sender"))
    async def get_message_info(client: Client, message: Message):
        # 从参数给出的链接中获取对应的消息例如：https://t.me/SSUnion/1918564
        if len(message.command) != 2:
            await message.reply("使用方法: /msginfo [message link]")
            return
        link = message.command[1]
        if not link.startswith("https://t.me/"):
            await message.reply("链接格式错误")
            return
        try:
            chat_id, message_id = extract_ids(link)
            msg = await client.get_messages(chat_id, message_id)
        except BadRequest as e:
            await message.reply("Bot 不在该群组中")
            return
        except IndexError:
            await message.reply("链接格式错误")
            return
        except RPCError as e:
            logging.exception(e)
            await message.reply("获取消息失败: " + str(e))
            return
        if msg.from_user is None:
            await message.reply("未找到消息发送者")
            return
        else:
            fuser = msg.from_user
            await message.reply(f"{fuser.mention(str(fuser.id))}\n")

    @app.on_message(filters.private & filters.command("getlog"))
    async def get_log(client: Client, message: Message):
        if len(message.command) != 2:
            await message.reply("使用方法: /getlog [challenge_id]")
            return
        if message.from_user.id != _admin_user:
            return
        logs = db.get_logs_by_challenge_id(message.command[1])
        if len(logs) == 0:
            await message.reply("没有找到相关记录")
            return
        text = ""
        for log in logs:
            text += str(log)
            text += "\n"
        await message.reply(text)

    @app.on_message(filters.private & filters.forwarded)
    async def get_user_record(client: Client, message: Message):
        if message.from_user.id != _admin_user:
            return
        if message.forward_from is None:
            await message.reply("该消息用户为频道或关闭了消息转发权限")
            return
        user_id = message.forward_from.id
        logs = db.get_logs_by_user_id(user_id)
        if len(logs) == 0:
            await message.reply("没有找到相关记录")
            return
        text = ""
        for log in logs:
            text += str(log)
            text += "\n"
        await message.reply(text)

    @app.on_message(filters.group | filters.service)
    # delete service message and message send from pending validation user
    async def delete_service_message(client: Client, message: Message):
        service_message_need_delete = [MessageServiceType.NEW_CHAT_MEMBERS, MessageServiceType.LEFT_CHAT_MEMBERS]
        if message.service:
            if message.service in service_message_need_delete:
                try:
                    await message.delete()
                except MessageDeleteForbidden:
                    pass
                return
            else:
                return
        if not message.from_user:
            # 频道发言不判断
            return
        await asyncio.sleep(1)  # 延迟2秒再判断
        if not _current_challenges.data:
            # 如果当前没有验证任务，就不用判断了
            return
        chat_id, user = message.chat.id, message.from_user
        if _current_challenges.is_duplicate(user.id, chat_id):
            await message.delete()
            await client.send_message(chat_id=_channel,
                                      text=_config["msg_message_deleted"].format(
                                          targetuserid=str(user.id),
                                          messageid=str(message.id),
                                          groupid=str(chat_id),
                                          grouptitle=str(message.chat.title),
                                      ))
            return

    @app.on_chat_member_updated()
    async def challenge_user(client: Client, message: ChatMemberUpdated):
        # 过滤掉非用户加群消息和频道新用户消息，同时确保 form_user 这个参数不是空的
        if not bool(message.new_chat_member) or bool(message.old_chat_member) or message.chat.type == ChatType.CHANNEL:
            return
        # 过滤掉管理员 ban 掉用户产生的加群消息 (Durov 这什么 jb api 赶紧分遗产了)
        if message.from_user.id != message.new_chat_member.user.id and not message.new_chat_member.status == ChatMemberStatus.MEMBER:
            return

        target = message.new_chat_member.user
        group_config = get_group_config(message.chat.id)
        chat_id = message.chat.id
        user_id = target.id

        # 黑名单部分----------------------------------------------------------------------------------------------------
        if group_config["enable_global_blacklist"]:
            db_user = db.get_user(user_id)
            if db_user:
                current_time = datetime.now()
                since_last_attempt = (current_time - db_user.last_attempt).total_seconds()
                if since_last_attempt > group_config[
                    "global_timeout_user_blacklist_remove"]:

                    # 存进 current_challenge 里面一小会，以供消息删除使用
                    challenge = AutoKickCache()
                    challenge_id = "{chat}|{msg}".format(chat=message.chat.id, msg=None)
                    timeout_event = Timer(
                        challenge_timeout(client, message, None),
                        timeout=5,
                    )
                    _current_challenges[challenge_id] = (challenge, message.from_user.id, timeout_event)

                    await client.ban_chat_member(chat_id, target.id)
                    logging.info(f"{target.id} banned")
                    await asyncio.sleep(1)
                    await client.unban_chat_member(chat_id, target.id)
                    logging.info(f"{target.id} unbanned")
                    asyncio.create_task(ensure_user_got_banned(client, message.chat, user_id))
                    db.update_last_try(current_time, target.id)
                    db.try_count_plus_one(target.id)
                    try_count = int(db.get_try_count(target.id))
                    try:
                        await client.send_message(_channel,
                                                  text=_config["msg_failed_auto_kick"].format(
                                                      targetuserid=str(target.id),
                                                      targetusername=str(target.username),
                                                      targetfirstname=str(target.first_name),
                                                      targetlastname=str(target.last_name),
                                                      groupid=str(chat_id),
                                                      grouptitle=str(message.chat.title),
                                                      lastattempt=str(
                                                          db_user.last_attempt.strftime("%Y-%m-%d %H:%M:%S")),
                                                      sincelastattempt=str(
                                                          timedelta(seconds=since_last_attempt)),
                                                      trycount=str(try_count)
                                                  ))
                    except Exception as e:
                        logging.error(str(e))
                    return
                else:
                    db.delete_users_by_id(target.id)

        # 入群验证部分--------------------------------------------------------------------------------------------------
        # 这里做一个判断让当出 bug 的时候不会重复弹出一车验证消息
        ch_id, ch_data = _current_challenges.get_by_user_and_chat_id(user_id, chat_id)
        if ch_data:
            challenge, target_id, timeout_event = ch_data
            # 如果某个 bug 导致了重复的验证，就直接返回, 除非这个验证是 AutoKickCache
            if not isinstance(challenge, AutoKickCache):
                logging.error(f"重复的验证，用户id：{user_id}，群组id：{chat_id}")
                return
        # 禁言用户 ----------------------------------------------------------------------------------------------------
        if message.from_user.id != target.id:
            if target.is_self:
                try:
                    await client.send_message(
                        message.chat.id, group_config["msg_self_introduction"])
                    _me: User = await client.get_me()
                    try:
                        await client.send_message(
                            int(_channel),
                            _config["msg_into_group"].format(
                                groupid=str(message.chat.id),
                                grouptitle=str(message.chat.title)
                            )
                        )
                    except Exception as e:
                        logging.error(str(e))
                except ChannelPrivate:
                    return
            return
        try:
            await client.restrict_chat_member(
                chat_id=message.chat.id,
                user_id=target.id,
                permissions=ChatPermissions(can_send_messages=False))
        except ChatAdminRequired:
            return
        except RPCError:
            await client.send_message(
                message.chat.id,
                "当前群组不是超级群组，Bot 无法工作，可能是成员过少。\n请尝试添加更多用户，或者禁言一个用户，让 Telegram 将该群转换为超级群组")
            return
        # reCAPTCHA 验证 ----------------------------------------------------------------------------------------------

        if group_config['challenge_type'] == ChallengeType.recaptcha:
            challenge = ReCAPTCHA()
            timeout = group_config["challenge_timeout"]
            reply_message = await client.send_message(
                message.chat.id,
                group_config["msg_challenge_recaptcha"].format(target_id=target.id,
                                                               timeout=timeout),
                reply_markup=InlineKeyboardMarkup(
                    challenge.generate_button(group_config, chat_id)),
            )
            challenge.message = reply_message
        else:  # 验证码验证 -------------------------------------------------------------------------------------------
            challenge = Math()
            timeout = group_config["challenge_timeout"]
            reply_message = await client.send_message(
                message.chat.id,
                group_config["msg_challenge_math"].format(target_id=target.id,
                                                          timeout=timeout,
                                                          challenge=challenge.qus()),
                reply_markup=InlineKeyboardMarkup(
                    challenge.generate_button(group_config)),
            )

        # 开始计时 -----------------------------------------------------------------------------------------------------
        challenge_id = "{chat}|{msg}".format(chat=message.chat.id, msg=reply_message.id)
        timeout_event = Timer(
            challenge_timeout(client, message, reply_message.id),
            timeout=group_config["challenge_timeout"],
        )
        _current_challenges[challenge_id] = (challenge, message.from_user.id, timeout_event)

    @app.on_callback_query(admin_operate_filter)
    async def admin_operate_callback(client: Client, callback_query: CallbackQuery):
        query_data = str(callback_query.data)
        query_id = callback_query.id
        chat_id = callback_query.message.chat.id
        user_id = callback_query.from_user.id
        msg_id = callback_query.message.id
        chat_title = callback_query.message.chat.title
        user_username = callback_query.from_user.username
        user_first_name = callback_query.from_user.first_name
        user_last_name = callback_query.from_user.last_name
        group_config = get_group_config(chat_id)

        # 获取验证信息-----------------------------------------------------------------------------------------------

        ch_id = "{chat}|{msg}".format(chat=chat_id, msg=msg_id)
        challenge_data = _current_challenges.get(ch_id)

        if challenge_data is None:
            logging.error("challenge not found, challenge_id: {}".format(ch_id))
            return
        else:
            challenge, target_id, timeout_event = challenge_data

        # 响应管理员操作------------------------------------------------------------------------------------------------

        if query_data in ["+", "-"]:
            admins = []
            async for m in client.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
                admins.append(m)
            if not any([
                admin.user.id == user_id and
                (admin.status == "creator" or admin.privileges.can_restrict_members)
                for admin in admins
            ]):
                await client.answer_callback_query(
                    query_id, group_config["msg_permission_denied"])
                return
            _current_challenges.delete(ch_id)
            timeout_event.stop()
            if query_data == "+":
                try:
                    await client.restrict_chat_member(
                        chat_id,
                        target_id,
                        permissions=ChatPermissions(
                            can_send_messages=True,
                            can_send_media_messages=True,
                            can_send_other_messages=True,
                            can_send_polls=True,
                            can_add_web_page_previews=True,
                            can_change_info=True,
                            can_invite_users=True,
                            can_pin_messages=True))
                except ChatAdminRequired:
                    await client.answer_callback_query(
                        query_id, group_config["msg_bot_no_permission"])
                    return

                await client.edit_message_text(
                    chat_id,
                    msg_id,
                    group_config["msg_approved"].format(user=user_first_name),
                    reply_markup=None,
                )
                _me: User = await client.get_me()
                try:
                    await client.send_message(
                        int(_channel),
                        _config["msg_passed_admin"].format(
                            targetuserid=str(target_id),
                            groupid=str(chat_id),
                            grouptitle=str(chat_title),
                        )
                    )
                except Exception as e:
                    logging.error(str(e))
            else:
                try:
                    await client.ban_chat_member(chat_id, target_id)
                except ChatAdminRequired:
                    await client.answer_callback_query(
                        query_id, group_config["msg_bot_no_permission"])
                    return
                await client.edit_message_text(
                    chat_id,
                    msg_id,
                    group_config["msg_refused"].format(user=user_first_name),
                    reply_markup=None,
                )
                Timer(
                    client.delete_messages(chat_id, msg_id),
                    group_config["delete_failed_challenge_interval"]
                )
                _me: User = await client.get_me()
                try:
                    await client.send_message(
                        int(_channel),
                        _config["msg_failed_admin"].format(
                            targetuserid=str(target_id),
                            groupid=str(chat_id),
                            grouptitle=str(chat_title),
                        )
                    )
                except Exception as e:
                    logging.error(str(e))
            await client.answer_callback_query(query_id)
            return

    @app.on_callback_query()
    async def challenge_answer_callback(client: Client, callback_query: CallbackQuery):
        query_data = str(callback_query.data)
        query_id = callback_query.id
        chat_id = callback_query.message.chat.id
        user_id = callback_query.from_user.id
        msg_id = callback_query.message.id
        chat_title = callback_query.message.chat.title
        user_username = callback_query.from_user.username
        user_first_name = callback_query.from_user.first_name
        user_last_name = callback_query.from_user.last_name
        group_config = get_group_config(chat_id)

        # 获取验证信息-----------------------------------------------------------------------------------------------

        ch_id = "{chat}|{msg}".format(chat=chat_id, msg=msg_id)

        challenge_data = _current_challenges.get(ch_id)

        if challenge_data is None:
            logging.error("challenge not found, challenge_id: {}".format(ch_id))
            return
        else:
            challenge, target_id, timeout_event = challenge_data

        # 让捣蛋的一边玩去 ---------------------------------------------------------------------------------

        if user_id != target_id:
            await client.answer_callback_query(
                query_id, group_config["msg_challenge_not_for_you"])
            return None
        timeout_event.stop()

        # 分析的没错的话这里应该是先给用户解开再根据回答对错处理 -----------------------------------------------------------

        try:
            await client.restrict_chat_member(
                chat_id,
                target_id,
                permissions=ChatPermissions(
                    can_send_messages=True,
                    can_send_media_messages=True,
                    can_send_other_messages=True,
                    can_send_polls=True,
                    can_add_web_page_previews=True,
                    can_change_info=True,
                    can_invite_users=True,
                    can_pin_messages=True))
        except ChatAdminRequired:
            pass

        _current_challenges.delete(ch_id)

        correct = str(challenge.ans()) == query_data
        if correct:
            try:
                await client.edit_message_text(
                    chat_id,
                    msg_id,
                    group_config["msg_challenge_passed"],
                    reply_markup=None)
            except MessageNotModified as e:
                await client.send_message(int(_channel),
                                          'Bot 运行时发生异常: `' + str(e) + "`")
            try:
                await client.send_message(
                    int(_channel),
                    _config["msg_passed_answer"].format(
                        targetuserid=str(target_id),
                        groupid=str(chat_id),
                        grouptitle=str(chat_title),
                    )
                )
            except Exception as e:
                logging.error(str(e))
        else:
            try:
                await client.edit_message_text(
                    chat_id,
                    msg_id,
                    group_config["msg_challenge_failed"],
                    reply_markup=None,
                )
                try:
                    await client.send_message(
                        int(_channel),
                        _config["msg_failed_answer"].format(
                            targetuserid=str(target_id),
                            groupid=str(chat_id),
                            grouptitle=str(chat_title),
                        )
                    )
                except Exception as e:
                    logging.error(str(e))
            except ChatAdminRequired:
                return

            if group_config["challenge_failed_action"] == FailedAction.ban:
                await client.ban_chat_member(chat_id, user_id)
            else:
                # kick
                await client.ban_chat_member(chat_id, user_id)
                logging.info(f"{user_id} banned")
                await asyncio.sleep(1)
                await client.unban_chat_member(chat_id, user_id)
                logging.info(f"{user_id} unbanned")

                asyncio.create_task(ensure_user_got_banned(client, callback_query.message.chat, user_id))

            if group_config["delete_failed_challenge"]:
                Timer(
                    client.delete_messages(chat_id, msg_id),
                    group_config["delete_failed_challenge_interval"],
                )
        if group_config["delete_passed_challenge"]:
            Timer(
                client.delete_messages(chat_id, msg_id),
                group_config["delete_passed_challenge_interval"],
            )

    async def challenge_timeout(client: Client, message, reply_id):
        chat_id = message.chat.id
        from_id = message.from_user.id
        chat_title = message.chat.title
        user_username = message.from_user.username
        user_first_name = message.from_user.first_name
        user_last_name = message.from_user.last_name
        group_config = get_group_config(chat_id)
        _current_challenges.delete("{chat}|{msg}".format(chat=chat_id,
                                                         msg=reply_id))
        if reply_id is None:
            # 删除黑名单缓存
            return

        # TODO try catch
        await client.edit_message_text(
            chat_id=chat_id,
            message_id=reply_id,
            text=group_config["msg_challenge_failed"],
            reply_markup=None,
        )

        await client.send_message(chat_id=_channel,
                                  text=_config["msg_failed_timeout"].format(
                                      targetuserid=str(from_id),
                                      targetusername=str(user_username),
                                      targetfirstname=str(user_first_name),
                                      targetlastname=str(user_last_name),
                                      groupid=str(chat_id),
                                      grouptitle=str(chat_title)
                                  ))

        if group_config["challenge_timeout_action"] == FailedAction.ban:
            await client.ban_chat_member(chat_id, from_id)
        elif group_config["challenge_timeout_action"] == FailedAction.kick:
            await client.ban_chat_member(chat_id, from_id)
            logging.info(f"{from_id} banned")
            await asyncio.sleep(1)
            await client.unban_chat_member(chat_id, from_id)
            logging.info(f"{from_id} unbanned")

            asyncio.create_task(ensure_user_got_banned(client, message.chat, user_id))
        else:
            pass

        if group_config["delete_failed_challenge"]:
            Timer(
                client.delete_messages(chat_id, reply_id),
                group_config["delete_failed_challenge_interval"],
            )

        if group_config["enable_global_blacklist"]:
            db.new_blacklist(datetime.now(), from_id)

    async def ensure_user_got_banned(client: Client, chat: Chat, user_id: int):
        # 当前有验证任务，就不用判断了
        ch_id, ch_data = _current_challenges.get_by_user_and_chat_id(user_id, chat.id)
        if ch_data:
            challenge, target_id, timeout_event = ch_data
            if not isinstance(challenge, AutoKickCache):
                return
        try:
            # 查询用户是否还在群组内
            member = await chat.get_member(user_id)
            if member.status == ChatMemberStatus.MEMBER:
                logging.error(f"{user_id} is still in the group {chat.id}, muted")
                await client.restrict_chat_member(chat.id, user_id, ChatPermissions(can_send_messages=False))
                await client.send_message(chat_id=_channel,
                                          text=f"#DIRTY_PATCH\n[用户](tg://user?id={user_id}) ID: `{user_id}` \n事件: 检测到踢出后仍然在群组中，已禁言待处理.\n群组 ID: `{chat.id}`\n群组标题: `{chat.title}`")
        except UserNotParticipant:
            logging.info(f"{user_id} is not in the group {chat.id}, no need to mute")
            return # 用户已经不在群组内


def _main():
    # db.setup()
    global _channel, _start_message, _config
    load_config()
    _start_message = _config["msg_start_message"]
    _proxy_ip = _config["proxy_addr"].strip()
    _proxy_port = _config["proxy_port"].strip()
    if _proxy_ip and _proxy_port:
        _app = Client("bot",
                      bot_token=_token,
                      api_id=_api_id,
                      api_hash=_api_hash,
                      proxy=dict(hostname=_proxy_ip, port=int(_proxy_port)))
    else:
        _app = Client("bot",
                      bot_token=_token,
                      api_id=_api_id,
                      api_hash=_api_hash)
    try:
        # start web
        tt = threading.Thread(
            target=start_web, name="WebThread", args=(_app,))
        tt.daemon = True
        logging.info('Starting webapi ....')
        tt.start()

        # start bot
        _update(_app)
        _app.run()
    except KeyboardInterrupt:
        quit()
    except Exception as e:
        logging.error(e)
        _main()


if __name__ == "__main__":
    _main()
