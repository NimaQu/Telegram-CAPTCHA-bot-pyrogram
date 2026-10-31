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

    function switcher(nav, attribute, panes) {
        nav.addEventListener("click", (event) => {
            const name = event.target.dataset && event.target.dataset[attribute];
            if (!name) return;
            for (const [key, pane] of Object.entries(panes)) pane.hidden = key !== name;
            for (const button of nav.querySelectorAll("button")) {
                button.classList.toggle("active", button.dataset[attribute] === name);
            }
        });
    }

    function readFile(file) {
        return new Promise((resolve, reject) => {
            if (file.size > 2 * 1024 * 1024) {
                reject(new Error(`${file.name} 超过 2 MB`));
                return;
            }
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error(`无法读取 ${file.name}`));
            reader.readAsDataURL(file);
        });
    }

    function thresholdInput(value) {
        const input = element("input", undefined, "threshold");
        input.type = "number";
        input.min = "1";
        input.max = "100";
        input.step = "1";
        input.placeholder = "默认";
        input.setAttribute("aria-label", "单独的处置阈值(%)");
        if (value) input.value = value;
        return input;
    }

    function optionalNumber(input) {
        return input.value === "" ? null : Number(input.value);
    }

    function setupAntispam(chatId) {
        const base = `chats/${encodeURIComponent(chatId)}/antispam`;
        const form = document.getElementById("antispam-form");
        const testForm = document.getElementById("test-form");
        const keyForm = document.getElementById("key-form");
        const enabled = document.getElementById("antispam-enabled");
        const classifierList = document.getElementById("classifier-list");
        const customList = document.getElementById("custom-list");
        const customAdd = document.getElementById("custom-add");
        const keyClear = document.getElementById("key-clear");
        let state = null;

        switcher(document.getElementById("group-tabs"), "panel", {
            captcha: document.getElementById("captcha-panel"),
            antispam: document.getElementById("antispam-panel"),
        });
        switcher(document.getElementById("antispam-tabs"), "pane", { settings: form, test: testForm });

        function addCustom(item) {
            const card = element("section", undefined, "group stack custom");
            const fields = [
                ["name", "名称，例如：招聘广告", 20],
                ["yes", "判为「是」的情况", 200],
                ["no", "判为「否」的情况", 200],
            ];
            for (const [name, placeholder, maxLength] of fields) {
                const input = element("input");
                input.type = "text";
                input.name = name;
                input.placeholder = placeholder;
                input.maxLength = maxLength;
                input.required = true;
                input.value = item[name] || "";
                const row = element("div", undefined, "row");
                row.append(input);
                card.append(row);
            }
            const options = element("label", undefined, "row");
            const toggle = element("input");
            toggle.type = "checkbox";
            toggle.name = "enabled";
            toggle.checked = item.enabled !== false;
            options.append(element("span", "启用", "name"), thresholdInput(item.threshold), toggle);
            const remove = element("button", "删除这个分类器", "danger");
            remove.type = "button";
            remove.addEventListener("click", () => {
                card.remove();
                customAdd.hidden = customList.children.length >= 3;
            });
            card.append(options, remove);
            customList.append(card);
            customAdd.hidden = customList.children.length >= 3;
        }

        function render(next) {
            state = next;
            const unavailable = document.getElementById("antispam-unavailable");
            unavailable.hidden = state.available;
            unavailable.textContent = "Bot 管理员还没有在配置文件中启用 AI 反垃圾，暂时无法使用。";
            const disabled = document.getElementById("antispam-disabled");
            disabled.hidden = !state.disabled_reason || state.enabled;
            disabled.textContent = `已于 ${formatTime(state.disabled_at)} 自动关闭：${state.disabled_reason}\n处理好之后请重新开启。`;
            enabled.checked = state.enabled;
            enabled.disabled = !state.available || !state.key.set;

            const key = state.key;
            document.getElementById("key-info").textContent = key.set
                ? `已设置 ····${key.last4 || ""} · 由 ${key.set_by_name || "未知"}${key.mine ? "(你)" : ""} 于 ${formatTime(key.set_at)} 设置。出于安全原因无法查看，只能替换或清除。`
                : "还没有设置 token。设置后其他管理员只能替换，无法查看。";
            keyClear.hidden = !key.set;

            const config = state.config;
            classifierList.replaceChildren();
            for (const item of state.classifiers) {
                const setting = config.builtin[item.id];
                const row = element("label", undefined, "row");
                row.dataset.id = item.id;
                const name = element("span", item.name, "name");
                name.append(element("small", item.yes));
                const toggle = element("input");
                toggle.type = "checkbox";
                toggle.checked = setting.enabled;
                row.append(name, thresholdInput(setting.threshold), toggle);
                classifierList.append(row);
            }
            customList.replaceChildren();
            for (const item of config.custom) addCustom(item);
            customAdd.hidden = config.custom.length >= 3;

            const action = form.elements.action;
            action.replaceChildren(...state.actions.map((item) => new Option(item.label, item.value)));
            action.value = config.action;
            form.elements.act_threshold.value = config.act_threshold;
            form.elements.log_threshold.value = config.log_threshold;
            form.elements.daily_limit.value = config.daily_limit;
            form.elements.report_votes.value = config.report_votes;
            form.elements.rules.value = config.rules;
            const usage = state.usage;
            document.getElementById("antispam-usage").textContent =
                `今日调用 ${usage.today_calls} 次(${usage.today_tokens} tokens)，本月 ${usage.month_calls} 次(${usage.month_tokens} tokens)`;
        }

        function collectConfig() {
            const builtin = {};
            for (const row of classifierList.children) {
                builtin[row.dataset.id] = {
                    enabled: row.querySelector('input[type="checkbox"]').checked,
                    threshold: optionalNumber(row.querySelector("input.threshold")),
                };
            }
            const custom = [...customList.children].map((card) => ({
                name: card.querySelector('[name="name"]').value.trim(),
                yes: card.querySelector('[name="yes"]').value.trim(),
                no: card.querySelector('[name="no"]').value.trim(),
                enabled: card.querySelector('[name="enabled"]').checked,
                threshold: optionalNumber(card.querySelector("input.threshold")),
            }));
            return {
                builtin,
                custom,
                action: form.elements.action.value,
                act_threshold: Number(form.elements.act_threshold.value),
                log_threshold: Number(form.elements.log_threshold.value),
                daily_limit: Number(form.elements.daily_limit.value),
                report_votes: Number(form.elements.report_votes.value),
                rules: form.elements.rules.value.trim(),
            };
        }

        customAdd.addEventListener("click", () => addCustom({}));

        form.addEventListener("submit", (event) => {
            event.preventDefault();
            run(form.querySelector('button[type="submit"]'), async () => {
                render(await api(base, { method: "PUT", body: JSON.stringify(collectConfig()) }));
                return "反垃圾设置已保存。";
            });
        });

        keyForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const apiKey = keyForm.elements.api_key.value.trim();
            run(keyForm.querySelector('button[type="submit"]'), async () => {
                render(await api(`${base}/key`, { method: "PUT", body: JSON.stringify({ api_key: apiKey }) }));
                keyForm.elements.api_key.value = "";
                return "token 验证通过并已保存，AI 反垃圾已开启。";
            });
        });

        keyClear.addEventListener("click", async () => {
            if (!(await confirmAction("确定清除 token 吗？AI 反垃圾会随之关闭。"))) return;
            run(keyClear, async () => {
                render(await api(`${base}/key`, { method: "DELETE" }));
                return "token 已清除。";
            });
        });

        enabled.addEventListener("change", () => {
            const wanted = enabled.checked;
            enabled.checked = !wanted;
            run(enabled, async () => {
                render(await api(`${base}/enabled`, { method: "PUT", body: JSON.stringify({ enabled: wanted }) }));
                return wanted ? "AI 反垃圾已开启。" : "AI 反垃圾已关闭。";
            });
        });

        testForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const results = document.getElementById("test-results");
            run(testForm.querySelector('button[type="submit"]'), async () => {
                const files = [...testForm.elements.images.files];
                if (files.length > 4) throw new Error("最多上传 4 张图片");
                const avatarFile = testForm.elements.avatar.files[0];
                const payload = {
                    config: collectConfig(),
                    text: testForm.elements.text.value,
                    sender_name: testForm.elements.sender_name.value.trim() || "测试用户",
                    username: testForm.elements.username.value.trim() || null,
                    bio: testForm.elements.bio.value.trim() || null,
                    forwarded_from: testForm.elements.forwarded_from.value.trim() || null,
                    images: await Promise.all(files.map(readFile)),
                    avatar: avatarFile ? await readFile(avatarFile) : null,
                };
                const result = await api(`${base}/test`, { method: "POST", body: JSON.stringify(payload) });
                const outcomes = { act: "会处置", log: "只记录到日志频道", pass: "放行" };
                results.replaceChildren(element("p", `结果：${outcomes[result.outcome]}`));
                if (payload.images.length || payload.avatar) {
                    results.append(element("p", result.images_sent ? "图片已送检" : "图片没有送检(未开启或被 jev 拒绝)", "meta"));
                }
                for (const score of result.scores) {
                    const card = element("div", undefined, score.hit ? "score hit" : "score");
                    const bar = element("div", undefined, "bar");
                    const fill = element("span");
                    fill.style.width = `${score.percent}%`;
                    bar.append(fill);
                    card.append(element("p", `${score.name}：${score.percent}%(阈值 ${score.threshold}%)`, "meta"), bar);
                    results.append(card);
                }
                status.hidden = true;
            });
        });

        return api(base, { method: "GET" }).then(render);
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
                element("p", `IP: ${log.ip_addr}${log.ip_location ? ` (${log.ip_location})` : ""}`, "meta"),
                element("p", `UA: ${log.user_agent}`, "meta"),
                element("p", `验证 ID: ${log.challenge_id}`, "meta"),
            );
            container.append(card);
        }
    }

    function renderIpGroups(container, ip, location, groups) {
        container.replaceChildren();
        if (location) container.append(element("p", `归属地: ${location}`, "meta"));
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
                renderIpGroups(document.getElementById("ip-results"), ip, result.location, result.groups);
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
                await setupAntispam(chatId);
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
