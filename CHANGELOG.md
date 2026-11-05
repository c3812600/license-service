# Changelog

本文件记录 license-service 的主要变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> 约定：**代码版本**（本文件）与**数据库 schema 版本**（`license_service/db.py` 的 `SCHEMA_VERSION`）
> 是两套独立的号。schema 变更必须走迁移，详见规范附录 I。
> 0.x 阶段不承诺接口向后兼容，破坏性变更会在 `Changed` 里显式标注。

## [Unreleased]

### Deployed

- **V0.3.0 已部署现网**（2026-11-05）：`https://licenses.lonk.vip` 全量上线
  （错误码 / 自助换机 / 自助解绑 / 恢复码 / 参考客户端同源），schema v2→v4 迁移生效，
  `verify_deploy.py --admin-token` 19/19 通过。拓扑：Cloudflare 隧道 → nginx:8766
  → gunicorn:8765，分访客限流 + 安全头 + 64KB 请求体在 nginx 层，签名协议与错误码
  在应用层。部署教训（ufw 端口、CF-Connecting-IP 限流键、宝塔 reload 不换 worker、
  venv 缺 CA 链）记入规范附录 J §7。

### Added

- `SECURITY.md`：漏洞私密披露渠道（GitHub Security Advisories）、支持版本、响应承诺与安全边界；
- `CONTRIBUTING.md`：开发环境、提交前自检、代码约定与范围说明；
- `requirements.lock`：`pip-compile --generate-hashes` 生成的精确版本 + 哈希锁（12 个包），
  生产安装用它防供应链篡改；开发仍用 `requirements.txt`；
- `scripts/restore_drill.py`：可重复的恢复演练（备份→灾难→恢复→数据/迁移/服务/安全四重校验，
  9 步全过才算通过），恢复单位固化为「库 + 密钥」一体。
- `tests/test_doc_contract.py`：文档↔代码契约测试（路由/错误码/环境变量/表结构/过时标记/
  敏感物），文档漂移会让测试红，守住「文档是唯一事实源」。

### Fixed

- 规范 §8.4 补 `FORBIDDEN`（`ForbiddenError` 兜底码，代码在用但文档漏记）；§8.2 三处
  「已实现（待部署）」翻转为已部署——文档对齐审计发现的漂移。
- `scripts/verify_deploy.py`：自带浏览器式 User-Agent——CDN/WAF（如 Cloudflare 机器人防护）
  会403 拦截 Python-urllib 默认 UA，导致误判全线失败；非 JSON 的 403 现在标注「疑似 WAF 拦截」。

### Changed

- `scripts/deploy.sh`：部署核对挂上 `verify_deploy.py` 全量探测（19 项），
  设置 `ADMIN_TOKEN` 可附加管理端核对；schema 回滚提示去掉 v1→v2 特例（v2/v3/v4 纯新增、
  旧代码可跑新库），数据恢复步骤明确要求连同密钥还原。

## [0.3.0] - 2026-11-05

### Added

- **自助换机 `POST /api/v1/licenses/transfer`**（规范 §8.9）：持旧机有效授权码 + 新机设备签名，
  一次调用完成「解绑旧机 + 新机签发」，继承原类型与原有效期（`channel=transfer`、`previous_issue_id`
  串链可追）。换机按谱系计次（`transfer_count`），上限 `LICENSE_SERVICE_TRANSFER_LIMIT`（默认 3），
  超限 `ACTIVATION_LIMIT`；响应含 `transfer_count` / `transfer_remaining`。
- **自助解绑**：`POST /api/v1/unbind` 双授权（管理员令牌，或 `license_key` + 本机设备签名双因子），
  销毁性幂等、无需配额；审计动作 `unbind_self`（§8.8）。
- **恢复码 `POST /api/v1/licenses/recovery-codes` / `POST /api/v1/licenses/recover`**（规范 §8.10）：
  设备私钥与 Token 双丢后的一次性恢复通道。同机换绑公钥并原样返还既有 Token（`recovery_same`）；
  异机等同换机迁移（`recovery`，不占 `transfer_count`）。schema v4 新增 `recovery_codes` 表。
- **参考客户端 `client/`**：Python 可运行实现——机器码采集（附录 A/K）、Ed25519 密钥持久化
  （DPAPI / 0600）、设备证明签名、Token 离线验签、防回拨状态（附录 C）、HTTP 客户端。
  跨语言向量与服务端逐字节一致（`tests/test_reference_client.py`）。
- **`scripts/verify_deploy.py`**：部署核对脚本（19 项探测覆盖全部端点与错误信封），部署后一键核对。
- **业务错误码 `code`**：错误信封变为 `{"ok":false,"error":"...","code":"..."}`，
  新增 `license_service/errors.py`（`InputError`/`ForbiddenError`/`ConflictError` 携带 code）。
  授权状态码（`MACHINE_MISMATCH`/`EXPIRED`/`SIGNATURE_INVALID`/`REVOKED`/`ACTIVATION_LIMIT`/
  `LICENSE_REQUIRED`）与接口层码（`INVALID_INPUT`/`PRODUCT_MISMATCH`/`CHALLENGE_INVALID`/`CONFLICT`/
  `NOT_FOUND`/`UNAUTHORIZED`/`RATE_LIMITED`/`METHOD_NOT_ALLOWED`/`INTERNAL`）见规范 §8.4；
  客户端按 `code` 分支，不再匹配 `error` 文本（AI 对接的契约依据）。
- **schema v3 / v4**：`license_issues` 新增 `transfer_count`（旧行回填 0）；新增 `recovery_codes` 表，迁移见规范附录 I。
- **MIT License**（`LICENSE` 文件），README 补「许可证」一节。
- `LICENSE_SERVICE_MAX_CONTENT_LENGTH`：请求体上限（默认 64KB，超限 413 `INVALID_INPUT`）。
- `docs/nginx-sample.conf`：反代参考配置（HTTPS、分接口 IP 限流、请求体上限、管理路径白名单）。
- `GET /api/v1/health` 返回 `schema_version`，便于部署核对。

### Changed

- 错误文案**保持不变**（兼容旧客户端字符串匹配）；`device not enrolled or revoked` 现按状态携带
  `LICENSE_REQUIRED`（未登记）或 `REVOKED`（已停用）两种 code，文案本身不变。
- `expires_at` 等日期参数解析失败的报错统一为 `invalid date format, expected YYYY-MM-DD`
  （原来是 `strptime` 原始堆栈文案），code=`INVALID_INPUT`。
- AGENTS.md 硬约束 4 修正：`license_issues.license_token` 存完整 Token 是既定设计
  （供 `latest`/`active_key` 原样返还），约束改为「不入日志、审计 detail 只放 hash」。
- 代码内生产拓扑注释泛化，不再含具体内网 IP/主机。

### Tests

- 新增用例覆盖错误信封/错误码分流、换钥限频、换机（主路径/限次/拒绝分支）、自助解绑、
  恢复码（同机/异机/拒绝分支）、schema v3/v4 迁移、前端契约（接口路径/token/主题）、
  参考客户端（跨语言向量/Token 验签/防回拨），全量 70+。

## [0.2.0] - 2026-11-05

### Added

- `POST /api/v1/activation-codes`：管理员批量生成一次性激活码（16 字符 ≈ 80 bit，可设失效日，1–100 个/次）。
- `POST /api/v1/activate`：设备签名兑换激活码，同一事务内「核销码 + 绑定设备公钥 + 签发 Token」。
- `POST /api/v1/validate`：设备签名的在线状态核查，返回 `active`/`expired`/`revoked`/`unknown` 与 `server_time`，
  不签发新 Token（避免心跳变成无限续期旁路）。
- `POST /api/v1/unbind`：管理员解绑，吊销该机器全部 active 授权并停用设备凭据，保留历史（换机场景）。
- schema v2：新增 `activation_codes` 表（纯新增，无数据回填）。
- 规范附录 K：**Linux 客户端设计**——DMI / machine-id 机器码取值、容器与虚拟机弱指纹判定、
  `0600` + 可选 keyring 的密钥存储、boot id + 签名状态 + `server_time` 的防回拨、GPG 签包、Linux 测试矩阵。

### Changed

- 规范 §8.2 由「尚未实现的目标接口」改为「落地状态」表，逐项标明已实现 / 部分实现 / 未实现；
  新增 §8.6 激活码、§8.7 在线校验、§8.8 解绑三节契约（含错误串、限流、审计）。
- README 接口表补 4 个端点（15 → 19），能力边界不再写「不含激活码核销」。

### 计划中

- 业务错误码 `code`（当前仅返回 `error` 字符串，客户端只能匹配文本）。
- 自助解绑（按 `license_id` 计次）、账户级凭据恢复、自助换机。
- Linux 客户端的**实现**（附录 K 目前是设计，仓库内无代码）。

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

[Unreleased]: https://github.com/c3812600/license-service/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/c3812600/license-service/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/c3812600/license-service/releases/tag/v0.2.0
[0.1.0]: https://github.com/c3812600/license-service/releases/tag/v0.1.0
