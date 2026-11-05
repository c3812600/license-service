# 贡献指南

感谢参与 license-service。动手前请先读两份文档：

- [AGENTS.md](AGENTS.md)：目录结构、硬约束（改表走迁移、审计动作名是契约、敏感物不入库）、自检流程；
- [docs/license-design-spec.md](docs/license-design-spec.md)：**唯一权威规范**——接口契约、错误码（§8.4）、数据模型（附录 I）。

## 开发环境

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt            # 生产部署用 requirements.lock
cp .env.example .env                                  # 本地至少填 ADMIN_TOKEN 与 MACHINE_CODE_SALT
python -m unittest discover -s tests -v               # 全量测试（75 个）
```

## 提交前自检（CI 会跑同样的检查）

1. `python -m unittest discover -s tests -v` 全绿；
2. 动过 `db.py` → `tests.test_migration` 必须过（含旧库迁移场景）；
3. 动过接口 → `python scripts/verify_deploy.py http://127.0.0.1:8765 --admin-token <令牌>` 全过；
4. 动过 UI → `tests.test_static_pages` 过 + 浏览器浅/深色各看一遍；
5. 动过契约 → 同步更新规范与 README（文档是唯一事实源）。

## 代码约定（与 AGENTS.md 一致）

- 术语：设备 device，机器码 `machine_code`，其哈希 `machine_code_hash`；
- 服务层动词开头：`issue_*` / `fetch_*` / `register_*` / `revoke_*` / `update_*` / `list_*` / `forget_*`；
- 错误映射：`ValueError → 400`、`PermissionError → 403`、`RuntimeError → 409`；
  业务码用 `license_service/errors.py` 的异常携带，**不改已有 error 文案**（兼容契约）；
- **改表必须走迁移**：`SCHEMA_VERSION` + `_migrate()` 分支 + 规范附录 I 同步；审计 `action` 名不可随意改；
- 前端三端共用设计 token（`--bg/--card/--accent/...`），不另起命名。

## 提交信息

中文、[Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/)：
`feat:` / `fix:` / `refactor:` / `docs:` / `test:` / `ci:`，正文用要点写**为什么**改，
不只写改了什么。参考 `git log` 现有风格。

## 安全问题

**不要公开提 Issue**，按 [SECURITY.md](SECURITY.md) 私密报告。

## 范围说明

- 本仓库是**服务端**；参考客户端在 `client/`（Python，供移植对照，跨语言向量见测试）。
- 反向代理 / HTTPS / 监控属于部署侧，仓库内只有参考配置（`docs/nginx-sample.conf`）。
- 大型特性（账户体系、自助解绑配额模型变更等）请先开 Issue 讨论再动代码。
