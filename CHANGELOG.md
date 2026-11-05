# Changelog

本文件记录 license-service 的主要变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> 约定：**代码版本**（本文件）与**数据库 schema 版本**（`license_service/db.py` 的 `SCHEMA_VERSION`）
> 是两套独立的号。schema 变更必须走迁移，详见规范附录 I。
> 0.x 阶段不承诺接口向后兼容，破坏性变更会在 `Changed` 里显式标注。

## [Unreleased]

### 计划中

- 业务错误码 `code`（当前仅返回 `error` 字符串，客户端只能匹配文本）。
- `POST /api/v1/activate`、`POST /api/v1/validate`、解绑接口（目标设计见规范 §8.2）。
- Linux 客户端的机器码 / 密钥存储 / 防回拨方案（当前仅 Windows）。

## [0.1.0] - 2026-11-05

首个可移交版本：设备签名认证闭环、持证换钥、管理台与统计页、schema 迁移、CI 全部就位。
现网 `https://licenses.lonk.vip` 已部署设备签名版（当日核对 `/api/v1/health`）。

### Added

- **许可证 Token**：`<产品前缀>.<base64url(payload)>.<base64url(Ed25519 签名)>`，内置前缀
  `ControlCommand=RCC1`、`E-Player=EPL`、`WinPilot=WPL`、`iCMS=ICMS`、`rust-node=RUSTNODE`。
- **设备签名协议**：`POST /api/v1/devices/challenge` 签发一次性挑战（`trial`/`latest` 120 秒、
  `register` 900 秒），客户端用设备私钥对规范化消息签名，签名输入与跨语言对拍向量见规范 §8.1。
- **试用**：`POST /api/v1/trial/apply` 自助登记设备公钥并签发试用，按产品上限钳制 `trial_days`，
  同一机器沿用首次到期日，过期返回 409 `trial expired`。
- **认证领取**：`POST /api/v1/licenses/latest` 按设备签名返回未过期的在线授权；
  无有效授权返回 404（不等于吊销）。
- **设备凭据管理**：`POST /api/v1/devices/register`、`POST /api/v1/devices/revoke`。
- **持证换钥（设备公钥漂移自愈）**：`devices/register` 接受机内有效 `license_key` 替代管理员令牌，
  校验签名/绑定/有效期，吊销不复活，每机 24 小时最多 3 次，写 `device_rotate` 审计（规范 §8.5）。
- **管理端**：设备为中心的列表（搜索、应用过滤、续期/重置、授权码一键复制、备注列内滚动），
  管理页与统计页支持深浅色切换，设计 token 与客户端统一。
- **管理 API**：`licenses/renew`（支持 `supersede` 降期）、`licenses/offline-issue`、
  `licenses/query`、`licenses/active_key`、`GET/PATCH /api/v1/devices`、`devices/forget`、`stats`。
- **统计页**：`/admin/stats`，图表配色跟随主题。
- **内置限流**：challenge 30/min、trial 5/min、latest 10/min、register 10/min（按来源 IP + 接口），
  `LICENSE_SERVICE_RATE_LIMIT=0` 可关闭。
- **schema 迁移框架**：`SCHEMA_VERSION` + `PRAGMA user_version`，v1 将
  `device_challenges.expires_at` 改名为 `expires_at_epoch`。
- **运维脚本**：`scripts/backup_db.py`（VACUUM INTO 热备）、`license_service_autostart.sh`（cron 自启）、
  `bt_create_license.py`（宝塔面板建项）。
- **CI**：GitHub Actions，Python 3.10 / 3.12 跑全量测试 + Markdown 内部链接检查。
- **文档**：规范迁移到 `docs/license-design-spec.md`（新增 §8.5 持证换钥、附录 I 数据模型与迁移、
  附录 J Linux 部署运维、§8.1 部署三态矩阵）；新增 `docs/client-ui-demo.html` 界面规范 Demo 与
  `AGENTS.md` 接手指引。

### Changed

- **试用默认时长 365 天 → 30 天**（`LICENSE_SERVICE_TRIAL_DAYS`，可用 `..._TRIAL_DAYS_MAP` 按产品覆盖）。
- 管理端与统计页改用与客户端同一套设计 token（浅色默认 + 深色可切换），管理端不再固定深色。
- 机器码哈希变量统一命名 `machine_code_hash`（与库列名一致）；`forget_machine()` 更名为 `forget_device()`
  （审计动作名 `forget_machine` 保留历史值）。
- 私钥/公钥路径环境变量统一 `LICENSE_SERVICE_` 前缀，旧名 `LICENSE_PRIVATE_KEY_PATH` /
  `LICENSE_PUBLIC_KEY_PATH` 继续兼容。
- 时间统一「存 UTC、显示北京时间」，`last_seen` 在每次领取授权时刷新。

### Removed

- **`GET /api/v1/licenses/latest`**：只凭机器码取 Token 的无认证接口，现固定返回 405，旧客户端必须升级。

### Security

- 挑战一次性，绑定 `action` / 产品 / 机器码，不可跨用途复用。
- 管理员令牌无默认值，使用常量时间比较；未配置时管理 API 不可用。
- 代理头仅在来源是本机/容器网桥时采纳 `X-Forwarded-For`，直连伪造头一律剥离。
- 机器码只以加盐哈希入库，明文仅用于管理台展示；完整 Token、私钥、盐不入日志。
- 持证换钥的固有限制已在规范 §8.5 写明：授权码 + 机器码泄露即可换绑，靠 3 次/日限频、审计与吊销兜底。

### Fixed

- `supersede` 签发失败时回滚，不再留下半撤销状态。
- 统计接口的 N+1 查询与统计口径（过期/即将到期按日期边界计算）。
- `last_seen` 时区解析（补 `Z` 按 UTC 解析，避免显示成凌晨）。
- 管理端备注列在窄窗口下撑破表格（改为格内横滚 + 悬停细滚动条）。

### Tests

- 41 个用例、覆盖率约 87%（`python -m unittest discover -s tests -v`），
  含 schema 迁移的旧库场景、持证换钥限频、XFF 伪造、并发领取试用。

[Unreleased]: https://github.com/c3812600/license-service/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/c3812600/license-service/releases/tag/v0.1.0
