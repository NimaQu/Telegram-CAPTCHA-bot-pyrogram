from pyrogram.errors import ChatAdminRequired, MessageNotModified
from pyrogram.filters import private
from pyrogram.types import ChatPermissions
from pyrogram import Client
import logging
from flask import Flask, request, flash
from flask import render_template
from challengedata import ChallengeData
import dbhelper as db

app = Flask(__name__)
client: Client = None
_current_challenges = ChallengeData()
_config = dict()
_channel = 0


@app.after_request
def add_response_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-src https://challenges.cloudflare.com; "
        "connect-src 'self' https://challenges.cloudflare.com; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    response.headers.pop("Cache-Control", None)
    response.headers.pop("Pragma", None)
    return response


@app.route("/")
def root():
    return render_template('index.html')


@app.route("/recaptcha", methods=["GET", "POST"])
async def verify():
    # 测试模板用-----------------------------------------------------
    # return render_template('recaptcha.html', sitekey=114514)
    # 测试模板用-----------------------------------------------------

    if request.args.get('challenge') is None:
        flash("没有这条验证数据！", "error")
        return render_template('result.html')
    else:
        challenge_id = request.args.get('challenge')
    try:
        ch_id, challenge_data = _current_challenges.get_by_challenge_id(challenge_id)
    except TypeError:
        flash("没有这条验证数据！", "error")
        return render_template('result.html')

    if challenge_data is None or ch_id is None:
        flash("没有这条验证数据！", "error")
        return render_template('result.html')

    challenge, target_id, timeout_event = challenge_data
    join_request = False
    if challenge.message.chat.id == target_id:
        try:
            chat_id = int(ch_id.split("|")[0])
        except ValueError:
            logging.error(f"Invalid chat_id in challenge data: {ch_id}")
        chat = await client.get_chat(chat_id)
        chat_title = chat.title
        join_request = True
    else:
        chat_id = challenge.message.chat.id
        chat_title = challenge.message.chat.title
    msg_id = challenge.message.id
    user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
    ua = request.headers.get('User-Agent')

    group_config = _config.get(str(chat_id), _config["*"])

    if request.method == "POST":
        captcha_response = request.form['g-recaptcha-response']
        if not challenge.verify(captcha_response, user_ip):
            flash('验证状态异常，请再试一次！', 'error')
            return render_template('recaptcha.html', sitekey=challenge.site_key)
        else:
            timeout_event.stop()
            try:
                if not join_request:
                    await client.restrict_chat_member(
                        chat_id,
                        target_id,
                        permissions=ChatPermissions(
                            can_send_messages=True,
                            can_send_other_messages=True,
                            can_send_polls=True,
                            can_add_web_page_previews=True,
                            can_change_info=True,
                            can_invite_users=True,
                            can_pin_messages=True))
                else:
                    await client.approve_chat_join_request(chat_id, target_id)
            except ChatAdminRequired:
                pass

            _current_challenges.delete(ch_id)

            try:
                await client.send_message(
                    int(_channel),
                    _config["msg_passed_answer"].format(
                        targetuserid=str(target_id),
                        groupid=str(chat_id),
                        grouptitle=str(chat_title),
                    ) + f"\n验证ID: `{challenge_id}`")

                db.log_recaptcha(challenge_id=challenge_id,
                                 user_id=target_id,
                                 chat_id=chat_id,
                                 ip_addr=user_ip,
                                 user_agent=ua,
                                 action=db.RecaptchaLogAction.Passed)
            except Exception as e:
                logging.error(str(e))

            if group_config["delete_passed_challenge"] and not join_request:
                await client.delete_messages(chat_id, msg_id)
            else:
                try:
                    await client.edit_message_text(
                        chat_id=chat_id if not join_request else target_id,
                        message_id=msg_id,
                        text=group_config["msg_challenge_passed"],
                        reply_markup=None)
                except MessageNotModified as e:
                    await client.send_message(int(_channel),
                                              'Bot 运行时发生异常: `' + str(e) + "`")
            flash('您已通过验证，欢迎加入本群！如果仍然无法发言，请重启 Telegram 客户端。')
            return render_template('result.html')
    else:
        try:
            db.log_recaptcha(challenge_id=challenge_id,
                             user_id=target_id,
                             chat_id=chat_id,
                             ip_addr=user_ip,
                             user_agent=ua,
                             action=db.RecaptchaLogAction.PageVisit)
        except Exception as e:
            logging.error(e)
        return render_template('recaptcha.html', sitekey=challenge.site_key)


if __name__ == '__main__':
    app.debug = True
    app.env = 'debug'
    app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
    app.run(port=5000, host="127.0.0.1")
