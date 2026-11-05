# AGENTS.md —— 给接手的 AI / 开发者的工作指引

本仓库是 **license-service**：给 Windows 桌面软件签发「机器码绑定 + Ed25519 签名」的授权码，并提供试用、续期、设备公钥登记、持证换钥、查询与统计。

- 设计规范与接口契约：[`docs/license-design-spec.md`](docs/license-design-spec.md)（**改代码前先读对应章节**）
- 客户端界面参考：[`docs/client-ui-demo.html`](docs/client-ui-demo.html)
- 现网：`https://licenses.lonk.vip` 已部署设备签名版（2026-11-05 核对，详见规范 §8.1）

## 快速开始

```bash
python -m pip install -r requirements.txt      # Python 3.10+；Flask>=3、cryptography>=42
cp .env.example .env                           # 至少填 ADMIN_TOKEN 与 MACHINE_CODE_SALT
python app.py                                  # 开发用，默认 8765，禁止直接暴露公网

python -m unittest discover -s tests -v        # 全部测试（当前 75 个）
python -m unittest tests.test_migration -v     # 只跑 schema 迁移测试
```

首次启动会自动生成 `keys/ed25519-{private,public}.pem`；**已有环境迁移时不要重新生成**，私钥、公钥、数据库、机器码哈希盐必须一起备份与恢复。

CI（`.github/workflows/ci.yml`）在 push / PR 时跑同一套测试（Python 3.10 与 3.12）外加文档链接检查（`python scripts/check_docs.py .`）；本地跑通即可预期 CI 绿。

## 目录结构

```
app.py                        # 入口：加载 .env 后 create_app()
license_service/
  __init__.py                 # 路由 + 限流 + 错误处理（admin_* 前缀 = 需 X-Admin-Token）
  service.py                  # 业务逻辑：签发/试用/续期/换钥/激活码/校验/解绑/设备档案/统计
  device_auth.py              # 设备挑战与签名证明（trial/latest/register/validate/activate）
  errors.py                   # 带业务 code 的异常（InputError/ForbiddenError/ConflictError）
  crypto.py                   # Token 编解码、Ed25519 签发与验签、密钥对生成
  db.py                       # 建表 + SCHEMA_VERSION 迁移
  config.py                   # 环境变量 → Config（统一 LICENSE_SERVICE_ 前缀）
  static/                     # admin.html / stats.html（与 docs 里的 demo 共用一套设计 token）
client/                       # 参考客户端（Python）：机器码/密钥/协议验签/防回拨/API/门面
tests/                        # test_service.py（业务）、test_migration.py（schema）、test_static_pages.py（前端契约）、test_reference_client.py（客户端协议）
scripts/backup_db.py          # VACUUM INTO 热备
scripts/check_docs.py         # 文档内部链接检查（CI 的 docs 任务调用）
scripts/deploy.sh             # 服务器端部署：备份→拉取→重启→核对→回滚提示
scripts/verify_deploy.py      # 部署核对（19 项探测端点/错误信封），部署后对现网跑
.github/workflows/ci.yml      # CI：测试（Python 3.10 / 3.12）+ 文档链接
.github/workflows/deploy.yml  # 部署：手动触发或 Release 发布时 SSH 执行 deploy.sh
docs/license-design-spec.md   # 唯一权威规范（含数据模型附录 I、运维附录 J）
```

## 硬约束（违反会破坏数据或安全边界）

1. **改表必须走迁移**：提升 `db.SCHEMA_VERSION`，在 `_migrate()` 里加 `if version < N` 分支，并同步更新规范附录 I。禁止直接改已发布列名/语义；SQLite 老库不会被 `CREATE TABLE IF NOT EXISTS` 升级。
2. **审计 `action` 名是持久化契约**（如 `forget_machine`、`device_rotate`）。改名必须先迁移历史数据，否则审计链条断裂。
3. **机器码一律以 `machine_code_hash`（加盐哈希）入库**；明文 `machine_code` 只允许出现在 `device_registry`，仅用于管理台展示。
4. **敏感物永不入库/入日志**：发行私钥、`ADMIN_TOKEN`、`MACHINE_CODE_SALT`、设备私钥、完整 `license_token` **不入日志**；`license_issues.license_token` 存完整 Token 是既定设计（供 `latest`/`active_key` 原样返还），查询与去重一律用 `license_token_hash`，别把 Token 写进审计 `detail` 或日志。
5. **旧 `GET /api/v1/licenses/latest` 必须保持 405**：它是被废弃的无认证接口，恢复等于放弃设备认证。
6. **不许把 `X-Admin-Token` 设计进客户端**：客户端只持 `license_key`（见规范 §8.5）。
7. 新增/修改接口时，**同时**更新 `README.md` 接口表与规范 §8.1 的「代码/已部署/现网可用」三态表。

## 代码约定

- 术语：设备 = device，机器码 = `machine_code`，其哈希 = `machine_code_hash`（不要写 `machine_hash`）。
- 服务层函数用动词开头：`issue_*` / `fetch_*` / `register_*` / `revoke_*` / `update_*` / `list_*` / `forget_*`。
- 路由层用 `admin_*` 前缀表示「需要管理员令牌」，公开路径不加前缀。
- 错误映射：`ValueError → 400`、`PermissionError → 403`、`RuntimeError → 409`、未认证 `→ 401`；响应信封固定 `{"ok":true,"data":…}` / `{"ok":false,"error":"…","code":"…"}`。业务码用 `license_service/errors.py` 的 `InputError`/`ForbiddenError`/`ConflictError` 抛出（继承内建异常，映射不变），code 取值见规范 §8.4。
- 错误串是兼容契约，尽量不改文案；客户端（含 AI 对接）按 `code` 分支，不匹配 `error` 文本。新增错误码/错误串都要写进规范对应小节（换钥相关写进 §8.5）。
- 前端：`admin.html` / `stats.html` / `client-ui-demo.html` 共用一套设计 token（`--bg/--card/--border/--text/--text-dim/--accent/--accent-hover/--success/--warn/--danger`），深浅色由 `[data-theme]` 切换，不要另起一套命名。

## 改完怎么自检

1. `python -m unittest discover -s tests -v` 全绿；
2. 动过 `db.py` → 额外确认 `tests.test_migration` 通过（含旧库迁移场景）；
3. 动过接口 → 起本地服务跑 `python scripts/verify_deploy.py http://127.0.0.1:8765 --admin-token <令牌>`（19 项探测）；
4. 动过 UI → 跑 `tests.test_static_pages`（接口路径/token 契约），再开 `/admin`、`/admin/stats` 浅色/深色各看一遍；
5. 动过契约 → 更新规范与 README，保持「文档是唯一事实源」。

## 已知缺口（不要假装已解决）

- **自助换机已实现**（`licenses/transfer`，按 `transfer_count` 谱系限次，§8.9）；**自助解绑已实现**（`unbind` 双授权，§8.8）；**恢复码已实现**（§8.10，覆盖私钥+Token 双丢）；
- 账户级凭据恢复（统一身份、跨授权恢复）未实现——需要账户体系，属产品决策；单授权恢复走恢复码；
- 无反向代理/HTTPS/监控的实际配置（属面板与宿主机）；参考配置在 `docs/nginx-sample.conf`；
- **参考客户端 `client/` 是 Python 实现**；其他语言客户端仓库内无实现（协议见规范 §8 + `client/protocol.py` 测试向量）；
- `activation-codes` / `activate` / `validate` / `unbind` / `licenses/transfer` / `licenses/recovery-codes` / `licenses/recover` 已实现但**尚未部署**（三态见规范 §8.1，部署后跑 `scripts/verify_deploy.py`）；

## 提交约定

中文、Conventional Commits 风格（`feat:` / `fix:` / `refactor:` / `docs:`），正文用要点说明**为什么**改，而不只是改了什么。
