"use strict";

(() => {
    const webApp = window.Telegram && window.Telegram.WebApp;
    const status = document.getElementById("status");
    const views = { group: document.getElementById("group-view"), admin: document.getElementById("admin-view") };
    const tabs = document.getElementById("tabs");

    function showStatus(text, kind) {
        status.textContent = text;
        status.className = `status ${kind || ""}`.trim();
        status.hidden = false;
    }

    function haptic(kind) {
        if (webApp.HapticFeedback) webApp.HapticFeedback.notificationOccurred(kind);
    }

    function confirmAction(message) {
        return new Promise((resolve) => {
            if (webApp.showConfirm) {
                webApp.showConfirm(message, (ok) => resolve(Boolean(ok)));
            } else {
                resolve(window.confirm(message));
            }
        });
    }

    async function api(path, options) {
        const response = await fetch(`/miniapp/api/${path}`, {
            ...options,
            headers: {
                Authorization: `tma ${webApp.initData}`,
                "Content-Type": "application/json",
            },
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(typeof body.detail === "string" ? body.detail : "请求失败，请检查输入");
        }
        return body;
    }

    function element(tag, text, className) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    }

    function formatTime(value) {
        return value ? new Date(value).toLocaleString() : "未知";
    }

    // 按钮执行期间禁用，结果显示在顶部状态栏
    async function run(button, action) {
        button.disabled = true;
        try {
            const message = await action();
            if (message) {
                showStatus(message, "success");
                haptic("success");
            }
        } catch (error) {
            showStatus(error.message, "error");
            haptic("error");
        } finally {
            button.disabled = false;
        }
    }

    function selectView(name) {
        for (const [key, view] of Object.entries(views)) view.hidden = key !== name;
        for (const button of tabs.querySelectorAll("button")) {
            button.classList.toggle("active", button.dataset.view === name);
        }
    }

    function resolveChatId() {
        const fromQuery = new URLSearchParams(window.location.search).get("chat_id");
        const fromStart = webApp.initDataUnsafe ? webApp.initDataUnsafe.start_param : null;
        const raw = fromQuery || fromStart || "";
        return /^-\d+$/.test(raw) ? raw : null;
    }

    function setupGroupView(chatId) {
        const form = document.getElementById("config-form");
        const botWarning = document.getElementById("bot-warning");
        const saveButton = document.getElementById("save");

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
        }

        form.addEventListener("submit", (event) => {
            event.preventDefault();
            const payload = {
                challenge_type: form.elements.challenge_type.value,
                challenge_timeout: Number(form.elements.challenge_timeout.value),
                challenge_failed_action: form.elements.challenge_failed_action.value,
                challenge_timeout_action: form.elements.challenge_timeout_action.value,
                enable_global_blacklist: form.elements.enable_global_blacklist.checked,
            };
            run(saveButton, async () => {
                render(await api(`chats/${encodeURIComponent(chatId)}`, { method: "PUT", body: JSON.stringify(payload) }));
                return "已保存，新配置立即生效。";
            });
        });

        return api(`chats/${encodeURIComponent(chatId)}`, { method: "GET" }).then(render);
    }

    function renderLogs(container, logs) {
        container.replaceChildren();
        if (logs.length === 0) {
            container.append(element("p", "没有找到相关记录", "meta"));
            return;
        }
        for (const log of logs) {
            const card = element("div", undefined, "record");
            card.append(
                element("p", `${log.action} · ${formatTime(log.created_at)}`),
                element("p", `用户 ${log.user_id} · 群组 ${log.group_id}`, "meta"),
                element("p", `IP: ${log.ip_addr}`, "meta"),
                element("p", `UA: ${log.user_agent}`, "meta"),
                element("p", `验证 ID: ${log.challenge_id}`, "meta"),
            );
            container.append(card);
        }
    }

    function renderIpGroups(container, ip, groups) {
        container.replaceChildren();
        if (groups.length === 0) {
            container.append(element("p", "没有找到通过该 IP 验证的用户", "meta"));
            return;
        }
        for (const group of groups) {
            const card = element("div", undefined, "record");
            card.append(element("p", `${group.title} (${group.group_id})`));
            for (const user of group.users) {
                card.append(element("p", `用户 ${user.user_id} · 最近通过 ${formatTime(user.last_passed_at)}`, "meta"));
            }
            const ban = element("button", `封禁这 ${group.users.length} 个用户`, "danger");
            ban.type = "button";
            ban.addEventListener("click", async () => {
                if (!(await confirmAction(`确定在「${group.title}」封禁通过 IP ${ip} 验证的所有用户吗？`))) return;
                run(ban, async () => {
                    const result = await api(`admin/ip/${encodeURIComponent(ip)}/ban`, {
                        method: "POST",
                        body: JSON.stringify({ group_id: group.group_id }),
                    });
                    const failed = result.failures.map((item) => `${item.user_id}: ${item.error}`).join("\n");
                    return `封禁完成: 成功 ${result.success} 个，失败 ${result.failures.length} 个。${failed ? `\n${failed}` : ""}`;
                });
            });
            card.append(ban);
            container.append(card);
        }
    }

    function setupAdminView() {
        const logsForm = document.getElementById("logs-form");
        logsForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const kind = logsForm.elements.kind.value;
            const value = logsForm.elements.value.value.trim();
            if (kind === "user_id" && !/^\d+$/.test(value)) {
                showStatus("用户 ID 必须是数字", "error");
                return;
            }
            run(logsForm.querySelector("button"), async () => {
                const result = await api(`admin/logs?${new URLSearchParams({ [kind]: value })}`, { method: "GET" });
                renderLogs(document.getElementById("logs-results"), result.logs);
                status.hidden = true;
            });
        });

        const ipForm = document.getElementById("ip-form");
        ipForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const ip = ipForm.elements.ip.value.trim();
            run(ipForm.querySelector("button"), async () => {
                const result = await api(`admin/ip/${encodeURIComponent(ip)}`, { method: "GET" });
                renderIpGroups(document.getElementById("ip-results"), ip, result.groups);
                status.hidden = true;
            });
        });

        const leaveForm = document.getElementById("leave-form");
        leaveForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const chatId = leaveForm.elements.chat_id.value.trim();
            if (!/^-\d+$/.test(chatId)) {
                showStatus("群组 ID 必须是负数", "error");
                return;
            }
            if (!(await confirmAction(`确定让 Bot 离开群组 ${chatId} 吗？`))) return;
            run(leaveForm.querySelector("button"), async () => {
                const result = await api("admin/leave", { method: "POST", body: JSON.stringify({ chat_id: Number(chatId) }) });
                return result.message;
            });
        });

        const reload = document.getElementById("reload");
        reload.addEventListener("click", () => {
            run(reload, async () => (await api("admin/reload", { method: "POST" })).message);
        });

        const clean = document.getElementById("clean");
        clean.addEventListener("click", async () => {
            if (!(await confirmAction("确定从黑名单中清除所有已删号的用户吗？"))) return;
            run(clean, async () => (await api("admin/clean", { method: "POST" })).message);
        });
    }

    async function main() {
        if (!webApp || !webApp.initData) {
            showStatus("请在 Telegram 中打开此页面。", "error");
            return;
        }
        webApp.ready();
        webApp.expand();

        let me;
        try {
            me = await api("me", { method: "GET" });
        } catch (error) {
            showStatus(error.message, "error");
            return;
        }
        const chatId = resolveChatId();
        const wantsAdmin = new URLSearchParams(window.location.search).get("view") === "admin";
        if (me.is_bot_admin) setupAdminView();

        if (chatId && !wantsAdmin) {
            try {
                await setupGroupView(chatId);
            } catch (error) {
                showStatus(error.message, "error");
                if (me.is_bot_admin) selectView("admin");
                return;
            }
            status.hidden = true;
            if (me.is_bot_admin) tabs.hidden = false;
            selectView("group");
        } else if (me.is_bot_admin) {
            document.getElementById("chat-title").textContent = "Bot 管理";
            status.hidden = true;
            selectView("admin");
        } else {
            showStatus("没有指定群组。请在群里发送 /config，或私聊 Bot 发送 /config 选择群组。", "error");
            return;
        }

        tabs.addEventListener("click", (event) => {
            const view = event.target.dataset && event.target.dataset.view;
            if (view) selectView(view);
        });
    }

    main();
})();
