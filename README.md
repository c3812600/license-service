# License Service

[![CI](https://github.com/c3812600/license-service/actions/workflows/ci.yml/badge.svg)](https://github.com/c3812600/license-service/actions/workflows/ci.yml)

为 Windows 软件签发机器码绑定的 Ed25519 授权码。当前仓库实现设备公钥登记、签名认证领取续期、试用申请、激活码签发与兑换、在线状态核查、管理员签发/登记/吊销/解绑设备凭据、查询和统计；**不包含**完整的自助换机（换到另一台机器）、账户级凭据恢复或已下发离线 Token 的远程撤销。客户端须自行实现机器码计算、本地验签、持久化与防时间回拨；详见 [设计规范](docs/license-design-spec.md)。

## 文档

- [设计规范与对接文档](docs/license-design-spec.md)：机器码、Token 字节格式、DPAPI 存储、防回拨、接口契约，附录含数据模型与迁移约定（附录 I）、Linux 部署运维（附录 J）、持证换钥（§8.5）、自助换机（§8.9）。
- [Nginx 反代示例](docs/nginx-sample.conf)：HTTPS、分接口 IP 限流、请求体上限、管理路径白名单的参考配置。
- [参考客户端](client/)：Python 可运行实现（机器码采集、密钥持久化、设备证明、Token 离线验签、防回拨状态），跨语言对接看 `client/protocol.py` 与测试向量。
- [客户端界面规范 Demo](docs/client-ui-demo.html)：单文件参考实现，覆盖正常/到期/未授权/服务器不可达/自愈各状态，含深浅色主题。设计 token 与管理端 `admin.html`、`stats.html` 共用同一套命名。
- [AGENTS.md](AGENTS.md)：给接手的 AI / 开发者的工作指引（命令、目录、硬约束、自检流程）。
- [CHANGELOG.md](CHANGELOG.md)：版本变更记录（代码版本与数据库 schema 版本分开记录）。

## 本仓库接口

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | 无 | 健康检查、允许的产品和全局试用上限 |
| GET | `/api/v1/public-key` | 无 | 构建时核对公钥；不能直接作为客户端运行时信任锚 |
| POST | `/api/v1/devices/challenge` | 无 | 一次性挑战：`trial/latest` 120 秒，`register` 15 分钟 |
| POST | `/api/v1/trial/apply` | 设备签名 | 首次登记公钥并签发试用；重复领取须用原设备私钥签名 |
| POST | `/api/v1/licenses/latest` | 已登记设备签名 | 领取未过期的在线授权；原无认证 GET 现返回 405 |
| POST | `/api/v1/devices/register` | `X-Admin-Token` **或** `license_key` + 新设备签名 | 登记/轮换公钥；持有效授权码可自助换钥（每机 24 小时 3 次，见规范 §8.5） |
| POST | `/api/v1/devices/revoke` | `X-Admin-Token` | 禁止设备继续联网领取；**不撤销已签发的离线 Token** |
| POST | `/api/v1/licenses/renew` | `X-Admin-Token` | 新签一张授权，**不会自动撤销旧授权** |
| POST | `/api/v1/licenses/offline-issue` | `X-Admin-Token` | 签发离线授权供手动交付 |
| GET | `/api/v1/licenses/query` | `X-Admin-Token` | 按产品和机器码查签发记录 |
| GET | `/api/v1/licenses/active_key` | `X-Admin-Token` | 取该设备当前有效授权码（管理台「📋 授权码」按钮）；无有效授权返回 404 |
| GET | `/api/v1/devices` | `X-Admin-Token` | 设备列表 + 统计摘要，支持 `q`（机器码/客户/备注模糊搜索）与 `app_name` 过滤 |
| PATCH | `/api/v1/devices` | `X-Admin-Token` | 编辑设备档案（`customer_name` / `notes`），不动授权 |
| POST | `/api/v1/devices/forget` | `X-Admin-Token` | **重置设备**：删除该机器码的授权、设备凭证与未用挑战，测试设备可重新试用；不可恢复 |
| POST | `/api/v1/activation-codes` | `X-Admin-Token` | 批量生成一次性激活码（`days` 必填，`count` 1–100，可设码失效日） |
| POST | `/api/v1/activate` | 设备签名 | 兑换激活码：同一事务内核销 + 绑定公钥 + 签发 Token（规范 §8.6） |
| POST | `/api/v1/validate` | 已登记设备签名 | 在线状态核查，返回 `active`/`expired`/`revoked`/`unknown` 与 `server_time`；不签发新 Token（§8.7） |
| POST | `/api/v1/unbind` | `X-Admin-Token` **或** `license_key` + 本设备签名 | **解绑**：吊销该机全部 active 授权并停用设备凭据；自助模式双因子（§8.8） |
| POST | `/api/v1/licenses/transfer` | 旧机 `license_key` + 新设备签名 | **自助换机**：授权迁移到新机器（继承有效期，按谱系限次，默认 3 次）（§8.9） |
| POST | `/api/v1/licenses/recovery-codes` | `X-Admin-Token` | 为设备当前有效授权生成一次性恢复码（1–10 个，可设失效日）（§8.10） |
| POST | `/api/v1/licenses/recover` | 恢复码 + 新设备签名 | **凭据恢复**：私钥+Token 双丢后换绑/迁移（同机原样返还 Token）（§8.10） |
| GET | `/api/v1/stats` | `X-Admin-Token` | 统计数据，不返回完整 Token |

请求和响应均为 JSON：成功 `{"ok":true,"data":{...}}`，失败 `{"ok":false,"error":"...","code":"..."}`。`error` 为人类可读文案（保持稳定以兼容旧客户端），**`code` 为机器可读业务码**（取值与分流见[设计规范 §8.4](docs/license-design-spec.md)），客户端按 `code` 分支。`/admin` 为管理页，`/admin/stats` 为统计页。未配置管理员 Token 时管理 API 不可用；**没有默认管理员 Token**。

## 设备签名协议

客户端为每个产品/机器生成独立 Ed25519 密钥对，私钥仅留客户端并用 Windows DPAPI 保护（可用时优先采用不可导出的硬件密钥）；只发送 32 字节原始公钥的**无填充 base64url**编码。首次试用登记是自助的，无法远程证明真实硬件身份：机器码若提前泄露，可能被他人抢先占用；付费设备或丢失私钥后必须由管理员核验再登记。

1. `POST /api/v1/devices/challenge`，JSON 为 `{"app_name":"ControlCommand","machine_code":"本机机器码","action":"trial"}`；获取 `data.challenge`（`trial/latest` 有效 120 秒，人工 `register` 有效 900 秒）。`machine_code` 在签名前先去两侧空格并转大写，格式为 8-128 位大写字母、数字、`:`、`_` 或 `-`；**自助试用还要求 64 位十六进制 SHA-256 机器码**。
2. 签名输入是下面 **UTF-8 原始字节**，以 `\n` 分隔，**没有尾部换行**；`action` 必须与获取挑战时一致。`signature` 为 64 字节签名的无填充 base64url 编码：

```text
license-service/device/v1
{action}
{app_name}
{normalized_machine_code}
{challenge}
```

3. 首次试用向 `POST /api/v1/trial/apply` 提交：

```json
{"app_name":"ControlCommand","machine_code":"本机机器码","app_version":"1.2.3","trial_days":30,"device_public_key":"43位无填充base64url","challenge":"服务端挑战","signature":"86位无填充base64url"}
```

恢复试用须重新领取 `trial` 挑战并用**原私钥**签名；没有公钥登记的旧试用/付费记录不得自助认领，由管理员核实后走 `register`。领取续期先取 `latest` 挑战，再向 `POST /api/v1/licenses/latest` 提交 `app_name`、`machine_code`、`challenge`、`signature`（不提交公钥）。挑战仅能使用一次，不能跨用途、产品或机器；设备凭据被吊销或证明失败返回 403；没有未过期在线授权返回 404，**不是吊销证据**。离线手工签发的 Token 不由 `latest` 返回。管理员登记/轮换时，客户端先获取 `register` 挑战并对相同格式内容签名，管理员通过受控渠道取得公钥、机器码、挑战和签名，连同管理员 Token 调用 `/api/v1/devices/register`；若客户端仍持有效授权码，可用它替代管理员 Token 自助换钥（每机 24 小时 3 次，见规范 §8.5），既无授权码又无可用私钥时才必须人工核验并重新登记。管理员可通过 `/api/v1/devices/revoke` 提交 `app_name` 和 `machine_code` 停用旧设备凭据。

`LICENSE_SERVICE_TRIAL_DAYS` 是全局上限（代码与示例配置默认 30），`LICENSE_SERVICE_TRIAL_DAYS_MAP` 可设置产品上限。有效正整数 `trial_days` 被钳制到上限；缺失/非法时取上限。新签试用按服务端 UTC 日期计算首次到期日；响应 `data.trial_days` 是首次实际发放天数。已登记设备重复领取会新签一个 Token，但沿用首次到期日；过期后返回 HTTP 409 `trial expired`。服务端内置接口限流（challenge 30/min、trial 5/min、latest 10/min，按来源 IP+接口计数，`LICENSE_SERVICE_RATE_LIMIT=0` 关闭），公网仍建议在代理层再加一层 IP 限流、请求体大小限制与监控。审计/限流所用的客户端 IP **只在连接来源是本机或容器网桥**（`127/8`、`::1`、`172.16/12`，如 cloudflared 容器）时才采纳 `X-Forwarded-For`；直连 8765 的伪造代理头一律剥掉，审计 IP 不可伪造。设备公钥签名用于**取回授权**，不能代替客户端下载后的 Ed25519 许可证验签。

Token 格式为 `<产品前缀>.<base64url(payload)>.<base64url(Ed25519签名)>`；签名覆盖原始 payload JSON 字节。内置前缀：`ControlCommand=RCC1`、`E-Player=EPL`、`WinPilot=WPL`、`iCMS=ICMS`、`rust-node=RUSTNODE`。代码及示例配置默认允许这五个产品，生产部署应按实际开通范围收窄 `LICENSE_SERVICE_ALLOWED_APPS`；客户端需内置经独立渠道核对的生产公钥并校验前缀、签名、产品、机器码、日期。

## 部署准备

1. 使用受支持的 Python 环境安装依赖：开发用 `python -m pip install -r requirements.txt`；**生产部署用 `requirements.lock`**（`pip-compile --generate-hashes` 生成，精确版本 + 哈希校验，防供应链篡改）。从 `.env.example` 创建本机 `.env`，将管理员 Token 和机器码哈希盐设为随机且私密的值，配置实际允许的产品与试用上限；`.env` 不入库。
2. 新环境第一次启动可创建 Ed25519 密钥对；**现有服务迁移时必须恢复原私钥、公钥、数据库和原机器码哈希盐，不要重新生成/更改**。任意一把缺失/两把不匹配、或已有数据库但密钥均缺失时服务拒绝启动。生产私钥和数据库（包括 SQLite 的 WAL/SHM）要作为同一恢复点备份；私钥只留服务端，不放进安装包。更改哈希盐会使历史机器码无法查询，并可能重新领取试用。
3. `python app.py` 仅用于本地开发。公网使用进程管理器和生产 WSGI 服务，反向代理配置 HTTPS、请求体限制、试用限流、管理路径访问控制及健康检查。不要把 Flask 开发服务器直接暴露公网。
4. 旧版 `GET /api/v1/licenses/latest` 与无设备签名的试用客户端**不兼容**。上线前先更新测试客户端，备份原数据及密钥；现有试用/付费机器若未登记公钥，需要管理员验证身份后调用 `/api/v1/devices/register`，不得仅凭机器码自动迁移。部署后只读核对 `/api/v1/health`、`/api/v1/public-key` 和允许的产品；从安全渠道与客户端内置公钥对拍。签发测试使用独立测试环境，避免占用真实设备试用资格。

## 与公网版本的关系

`https://licenses.lonk.vip` **已部署 V0.3.0 全量**（2026-11-05）：现网 `GET /api/v1/health` 返回 `schema_version=4` 与允许产品清单，错误信封带业务 `code`；`verify_deploy.py --admin-token` 19/19 全过。只凭机器码取 Token 的旧 `GET /api/v1/licenses/latest` 已下线（返回 405）。拓扑：Cloudflare 隧道 → nginx（8766，分访客限流）→ gunicorn（8765）。各端点的「代码已实现 / 已部署 / 现网可用」三态见规范 §8.1，部署运维教训见附录 J。

现网部署仍不保证与本地 HEAD 完全同源：发布前请用 `git log -1` 记录部署 commit，核对数据库备份与密钥指纹，并按上述步骤完成已授权设备迁移；不要直接覆盖生产版本。

## 测试

`python -m unittest discover -s tests -v`。测试使用临时数据库和临时密钥，不访问公网，也不会修改生产授权。CI（`.github/workflows/ci.yml`）在 push / PR 时用 Python 3.10 与 3.12 跑同一套测试，并校验文档内部链接（`python scripts/check_docs.py .`）。部署后用 `python scripts/verify_deploy.py <现网地址> --admin-token <令牌>` 核对端点与错误信封（19 项探测）。

## 许可证

本项目采用 [MIT License](LICENSE) 开源。
