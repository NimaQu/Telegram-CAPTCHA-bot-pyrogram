# Telegram CAPTCHA Bot

基于 Kurigram、FastAPI 和 PostgreSQL 的异步 Telegram 入群验证机器人。支持普通入群与申请入群、数学题与 Cloudflare Turnstile、人工通过/拒绝、超时处理、全局黑名单及验证日志/IP 管理。

本版本固定使用 **Python 3.14**，依赖只由 `pyproject.toml` 与 `uv.lock` 管理。配置只读取 TOML；旧 INI/JSON 配置需要先通过迁移命令转换。

## 准备

需要：

- Python 3.14
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL
- Telegram Bot Token、API ID 与 API Hash
- Cloudflare Turnstile site key 与 secret key

安装锁定依赖：

```bash
uv sync --locked
cp config.example.toml config.toml
chmod 600 config.toml
```

编辑 `config.toml` 中的 `[bot]`、`[database]`、`[web]`、`[proxy]`、`[turnstile]`、`[defaults]` 和 `[messages]`。数据库 URL 必须使用 PostgreSQL，例如：

```toml
[database]
url = "postgresql+psycopg://captcha:password@127.0.0.1/captcha"
```

配置会在启动前严格校验：ID 和端口类型、正数范围、动作/验证类型枚举、HTTP URL、可信代理 CIDR 及消息占位符均不合法时拒绝启动。Token、API Hash、数据库 URL 和 Turnstile secret 在模型日志中会被隐藏。

## 从旧配置迁移

```bash
uv run captcha-bot migrate-config \
  --ini config.ini \
  --json config.json \
  --output config.toml
```

迁移命令不会覆盖已有输出文件，不会输出秘密，并会报告已删除的遗留字段。POSIX 系统上的新文件权限会设置为 `0600`。运行时不再读取 INI 或 JSON。

## 数据库升级与启动

首次部署或每次更新代码后，必须先显式升级数据库；应用不会自动修改生产库：

```bash
CAPTCHA_BOT_CONFIG=config.toml uv run alembic upgrade head
CAPTCHA_BOT_CONFIG=config.toml uv run alembic current
uv run captcha-bot run --config config.toml
```

兼容入口仍然可用：

```bash
uv run python main.py
```

Web 服务保留以下接口：

- `GET /`：状态页，缓存五分钟
- `GET|POST /recaptcha?challenge=...`：Turnstile 验证页，禁止缓存
- `GET /healthz`：数据库和 Telegram client 健康状态

只有直接连接来源属于 `[web].trusted_proxy_cidrs` 时，服务才接受 `CF-Connecting-IP`。默认只信任本机反向代理；直接暴露 Uvicorn 时应按实际网络结构调整，不要信任任意公网 CIDR。

## 配置热重载

Telegram 中的 `/reload` 会先完整校验 TOML。仅 `[defaults]` 与 `[messages]` 可以热更新；Bot 身份、数据库、Web、代理或 Turnstile 等启动级配置变化时会拒绝重载并提示重启，旧配置继续生效。

群管理员可继续使用原语法设置群策略：

```text
/faset challenge_timeout 120
/faset challenge_type recaptcha
/faset challenge_failed_action kick
/faset challenge_timeout_action ban
/faset enable_global_blacklist true
```

首次设置由 PostgreSQL upsert 原子写入并立即生效。

## 旧 CSV 导入

目标库必须已经升级到当前 Alembic head：

```bash
uv run captcha-bot import-csv group_config.csv --table group-config --config config.toml
uv run captcha-bot import-csv blacklist_user.csv --table blacklist-user --config config.toml
```

## systemd

复制并修改仓库中的 `example.service`：

```bash
sudo cp example.service /etc/systemd/system/captchabot.service
sudo systemctl daemon-reload
sudo systemctl enable --now captchabot.service
sudo journalctl -f -u captchabot.service
```

服务使用 `Restart=on-failure`。正常停止时，应用依次取消 challenge timeout、停止 Telegram client、关闭 HTTP client 并释放数据库连接池。

## 开发与质量门禁

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run ty check src main.py tests
uv run pytest
uv run pip-audit
```

PostgreSQL 集成测试只对显式指定的一次性测试库运行，测试过程会清空并重建该数据库：

```bash
TEST_DATABASE_URL=postgresql+psycopg://captcha:password@127.0.0.1/captcha_test uv run pytest -m integration
```

不要把生产数据库 URL 传给 `TEST_DATABASE_URL`。GitHub Actions 使用 Python 3.14 与独立 PostgreSQL service 执行格式、静态检查、类型检查、测试、覆盖率、Alembic check 和依赖审计。

## 项目结构

```text
src/captcha_bot/
├── app.py            # FastAPI lifespan 与资源所有权
├── challenges.py     # 验证状态及并发安全 Registry
├── config.py         # TOML 模型、热重载及旧配置迁移
├── handlers/         # Telegram 管理、入群、回调处理
├── db/               # SQLAlchemy 2.0 async repository 与导入
├── services.py       # 群策略和 Turnstile 服务
└── web.py            # Web/健康检查路由
```

`main.py` 只保留兼容启动包装。未完成的 `/report`、OpenAI、第三方黑名单、`mute` 和无效消息项已移除。

## 许可证

[GNU Affero General Public License v3.0](LICENSE)
