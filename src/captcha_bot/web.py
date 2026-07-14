from __future__ import annotations

import logging
from ipaddress import ip_address, ip_network

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pyrogram.errors import ChatAdminRequired, MessageNotModified, RPCError

from captcha_bot.context import AppContext
from captcha_bot.db.models import RecaptchaLogAction
from captcha_bot.handlers.common import full_chat_permissions, send_log

logger = logging.getLogger(__name__)


def get_context(request: Request) -> AppContext:
    return request.app.state.context


def client_ip(request: Request, context: AppContext) -> str:
    peer = request.client.host if request.client else "127.0.0.1"
    try:
        peer_address = ip_address(peer)
    except ValueError:
        return "127.0.0.1"
    trusted = any(
        peer_address in ip_network(cidr, strict=False) for cidr in context.config.settings.web.trusted_proxy_cidrs
    )
    if trusted:
        forwarded = request.headers.get("CF-Connecting-IP")
        if forwarded:
            try:
                return str(ip_address(forwarded))
            except ValueError:
                logger.warning("ignored invalid CF-Connecting-IP", extra={"peer": peer})
    return str(peer_address)


def register_web_routes(app: FastAPI, templates: Jinja2Templates) -> None:
    @app.middleware("http")
    async def response_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "public, max-age=300" if request.url.path == "/" else "no-store"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request=request, name="index.html")

    @app.get("/healthz")
    async def health(request: Request) -> JSONResponse:
        context = get_context(request)
        database_ok = await context.database.healthcheck()
        telegram_ok = bool(context.client.is_connected)
        status = 200 if database_ok and telegram_ok else 503
        return JSONResponse({"status": "ok" if status == 200 else "degraded"}, status_code=status)

    @app.api_route("/recaptcha", methods=["GET", "POST"], response_class=HTMLResponse)
    async def verify(request: Request) -> HTMLResponse:
        context = get_context(request)
        challenge_id = request.query_params.get("challenge")
        if not challenge_id:
            return templates.TemplateResponse(
                request=request, name="result.html", context={"notice": "没有这条验证数据！", "category": "error"}
            )
        session = await context.registry.get_by_turnstile_id(challenge_id)
        if session is None:
            return templates.TemplateResponse(
                request=request, name="result.html", context={"notice": "没有这条验证数据！", "category": "error"}
            )
        remote_ip = client_ip(request, context)
        user_agent = request.headers.get("User-Agent", "")
        if request.method == "GET":
            await context.repository.log_recaptcha(
                challenge_id,
                session.user_id,
                session.chat_id,
                remote_ip,
                user_agent,
                RecaptchaLogAction.PAGE_VISIT,
            )
            return templates.TemplateResponse(
                request=request,
                name="recaptcha.html",
                context={"sitekey": context.config.settings.turnstile.site_key},
            )
        form = await request.form()
        response_token = str(form.get("g-recaptcha-response") or form.get("cf-turnstile-response") or "")
        result = await context.turnstile.verify(response_token, remote_ip)
        if not result.success:
            await context.repository.log_recaptcha(
                challenge_id,
                session.user_id,
                session.chat_id,
                remote_ip,
                user_agent,
                RecaptchaLogAction.FAILED,
            )
            return templates.TemplateResponse(
                request=request,
                name="recaptcha.html",
                context={"sitekey": context.config.settings.turnstile.site_key, "error": "验证状态异常，请再试一次！"},
            )
        session = await context.registry.claim_by_turnstile_id(challenge_id)
        if session is None:
            return templates.TemplateResponse(
                request=request, name="result.html", context={"notice": "验证已过期或已完成。", "category": "error"}
            )
        try:
            if session.join_request:
                await context.client.approve_chat_join_request(session.chat_id, session.user_id)
            else:
                await context.client.restrict_chat_member(
                    session.chat_id, session.user_id, permissions=full_chat_permissions()
                )
        except ChatAdminRequired:
            logger.warning("bot lacks permission to approve challenge", extra={"challenge_id": challenge_id})
        await context.repository.log_recaptcha(
            challenge_id,
            session.user_id,
            session.chat_id,
            remote_ip,
            user_agent,
            RecaptchaLogAction.PASSED,
        )
        await send_log(
            context,
            context.config.settings.messages.passed_answer.format(
                targetuserid=session.user_id,
                groupid=session.chat_id,
                grouptitle=session.chat_title,
            )
            + f"\n验证ID: `{challenge_id}`",
        )
        policy = await context.policies.get(session.chat_id)
        if session.message_id is not None:
            if policy.delete_passed_challenge and not session.join_request:
                try:
                    await context.client.delete_messages(session.chat_id, session.message_id)
                except RPCError:
                    logger.exception("failed to delete passed challenge")
            else:
                try:
                    await context.client.edit_message_text(
                        session.user_id if session.join_request else session.chat_id,
                        session.message_id,
                        context.config.settings.messages.challenge_passed,
                    )
                except MessageNotModified:
                    pass
        return templates.TemplateResponse(
            request=request,
            name="result.html",
            context={
                "notice": "您已通过验证，欢迎加入本群！如果仍然无法发言，请重启 Telegram 客户端。",
                "category": "success",
            },
        )
