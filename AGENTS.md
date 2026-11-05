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

python -m unittest discover -s tests -v        # 全部测试（当前 41 个，覆盖率约 87%）
python -m unittest tests.test_migration -v     # 只跑 schema 迁移测试
```

首次启动会自动生成 `keys/ed25519-{private,public}.pem`；**已有环境迁移时不要重新生成**，私钥、公钥、数据库、机器码哈希盐必须一起备份与恢复。

## 目录结构

```
app.py                        # 入口：加载 .env 后 create_app()
license_service/
  __init__.py                 # 路由 + 限流 + 错误处理（admin_* 前缀 = 需 X-Admin-Token）
  service.py                  # 业务逻辑：签发/试用/续期/换钥/设备档案/统计
  device_auth.py              # 设备挑战与签名证明（trial/latest/register）
  crypto.py                   # Token 编解码、Ed25519 签发与验签、密钥对生成
  db.py                       # 建表 + SCHEMA_VERSION 迁移
  config.py                   # 环境变量 → Config（统一 LICENSE_SERVICE_ 前缀）
  static/                     # admin.html / stats.html（与 docs 里的 demo 共用一套设计 token）
tests/                        # test_service.py（业务）、test_migration.py（schema）
scripts/backup_db.py          # VACUUM INTO 热备
docs/license-design-spec.md   # 唯一权威规范（含数据模型附录 I、运维附录 J）
```

## 硬约束（违反会破坏数据或安全边界）

1. **改表必须走迁移**：提升 `db.SCHEMA_VERSION`，在 `_migrate()` 里加 `if version < N` 分支，并同步更新规范附录 I。禁止直接改已发布列名/语义；SQLite 老库不会被 `CREATE TABLE IF NOT EXISTS` 升级。
2. **审计 `action` 名是持久化契约**（如 `forget_machine`、`device_rotate`）。改名必须先迁移历史数据，否则审计链条断裂。
3. **机器码一律以 `machine_code_hash`（加盐哈希）入库**；明文 `machine_code` 只允许出现在 `device_registry`，仅用于管理台展示。
4. **敏感物永不入库/入日志**：发行私钥、`ADMIN_TOKEN`、`MACHINE_CODE_SALT`、设备私钥、完整 `license_token`。
5. **旧 `GET /api/v1/licenses/latest` 必须保持 405**：它是被废弃的无认证接口，恢复等于放弃设备认证。
6. **不许把 `X-Admin-Token` 设计进客户端**：客户端只持 `license_key`（见规范 §8.5）。
7. 新增/修改接口时，**同时**更新 `README.md` 接口表与规范 §8.1 的「代码/已部署/现网可用」三态表。

## 代码约定

- 术语：设备 = device，机器码 = `machine_code`，其哈希 = `machine_code_hash`（不要写 `machine_hash`）。
- 服务层函数用动词开头：`issue_*` / `fetch_*` / `register_*` / `revoke_*` / `update_*` / `list_*` / `forget_*`。
- 路由层用 `admin_*` 前缀表示「需要管理员令牌」，公开路径不加前缀。
- 错误映射：`ValueError → 400`、`PermissionError → 403`、未认证 `→ 401`；响应信封固定 `{"ok":true,"data":…}` / `{"ok":false,"error":"…"}`（当前不返回业务 `code`）。
- 新增错误串要写进规范对应小节（换钥相关写进 §8.5），客户端按字符串分支。
- 前端：`admin.html` / `stats.html` / `client-ui-demo.html` 共用一套设计 token（`--bg/--card/--border/--text/--text-dim/--accent/--accent-hover/--success/--warn/--danger`），深浅色由 `[data-theme]` 切换，不要另起一套命名。

## 改完怎么自检

1. `python -m unittest discover -s tests -v` 全绿；
2. 动过 `db.py` → 额外确认 `tests.test_migration` 通过（含旧库迁移场景）；
3. 动过接口 → 起本地服务冒烟：`curl localhost:8765/api/v1/health`、带 `X-Admin-Token` 调 `/api/v1/devices`；
4. 动过 UI → 打开 `/admin`、`/admin/stats`、`docs/client-ui-demo.html`，浅色/深色各看一遍；
5. 动过契约 → 更新规范与 README，保持「文档是唯一事实源」。

## 已知缺口（不要假装已解决）

- `activate` / `validate` / `unbind` 仍是目标接口，未实现；
- 业务错误码 `code` 未落地，客户端只能匹配错误字符串；
- 无反向代理/HTTPS/监控配置（属面板与宿主机）；
- Linux 客户端设计缺失（规范只覆盖 Windows 客户端的机器码、DPAPI、防回拨）；
- 无 CI、无前端自动化测试。

## 提交约定

中文、Conventional Commits 风格（`feat:` / `fix:` / `refactor:` / `docs:`），正文用要点说明**为什么**改，而不只是改了什么。
