"use strict";

(() => {
    const webApp = window.Telegram && window.Telegram.WebApp;
    const form = document.getElementById("config-form");
    const status = document.getElementById("status");
    const botWarning = document.getElementById("bot-warning");
    const saveButton = document.getElementById("save");

    function showStatus(text, kind) {
        status.textContent = text;
        status.className = `status ${kind || ""}`.trim();
        status.hidden = false;
    }

    function resolveChatId() {
        const fromQuery = new URLSearchParams(window.location.search).get("chat_id");
        const fromStart = webApp && webApp.initDataUnsafe ? webApp.initDataUnsafe.start_param : null;
        const raw = fromQuery || fromStart || "";
        return /^-\d+$/.test(raw) ? raw : null;
    }

    async function request(chatId, options) {
        const response = await fetch(`/miniapp/api/chats/${encodeURIComponent(chatId)}`, {
            ...options,
            headers: {
                Authorization: `tma ${webApp.initData}`,
                "Content-Type": "application/json",
            },
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            const detail = typeof body.detail === "string" ? body.detail : "请求失败，请检查输入";
            throw new Error(detail);
        }
        return body;
    }

    function render(state) {
        document.getElementById("chat-title").textContent = state.chat.title;
        document.getElementById("chat-id").textContent = `群组 ID: ${state.chat.id}`;
        const policy = state.policy;
        form.elements.challenge_type.value = policy.challenge_type;
        form.elements.challenge_timeout.value = policy.challenge_timeout;
        form.elements.challenge_failed_action.value = policy.challenge_failed_action;
        form.elements.challenge_timeout_action.value = policy.challenge_timeout_action;
        form.elements.enable_global_blacklist.checked = policy.enable_global_blacklist;
        const missing = [];
        if (!state.bot.can_delete_messages) missing.push("删除消息");
        if (!state.bot.can_restrict_members) missing.push("封禁/限制用户");
        botWarning.hidden = missing.length === 0;
        botWarning.textContent = `Bot 在该群缺少以下管理员权限，验证可能无法正常工作：${missing.join("、")}`;
        form.hidden = false;
    }

    async function main() {
        if (!webApp || !webApp.initData) {
            showStatus("请在 Telegram 中打开此页面。", "error");
            return;
        }
        webApp.ready();
        webApp.expand();
        const chatId = resolveChatId();
        if (!chatId) {
            showStatus("没有指定群组。请在群里发送 /config，或私聊 Bot 发送 /config 选择群组。", "error");
            return;
        }
        try {
            render(await request(chatId, { method: "GET" }));
            status.hidden = true;
        } catch (error) {
            showStatus(error.message, "error");
            return;
        }
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const payload = {
                challenge_type: form.elements.challenge_type.value,
                challenge_timeout: Number(form.elements.challenge_timeout.value),
                challenge_failed_action: form.elements.challenge_failed_action.value,
                challenge_timeout_action: form.elements.challenge_timeout_action.value,
                enable_global_blacklist: form.elements.enable_global_blacklist.checked,
            };
            saveButton.disabled = true;
            try {
                render(await request(chatId, { method: "PUT", body: JSON.stringify(payload) }));
                showStatus("已保存，新配置立即生效。", "success");
                if (webApp.HapticFeedback) webApp.HapticFeedback.notificationOccurred("success");
            } catch (error) {
                showStatus(error.message, "error");
                if (webApp.HapticFeedback) webApp.HapticFeedback.notificationOccurred("error");
            } finally {
                saveButton.disabled = false;
            }
        });
    }

    main();
})();
