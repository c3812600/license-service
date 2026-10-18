# License Service

为 Windows 软件签发机器码绑定的 Ed25519 授权码。当前仓库实现设备公钥登记、签名认证领取续期、试用申请、管理员签发/登记/吊销设备凭据、查询和统计；**不包含**激活码核销、完整许可证吊销同步或换绑。客户端须自行实现机器码计算、本地验签、持久化与防时间回拨；详见 [设计规范](Windows%20软件加密授权系统设计规范与对接文档.md)。

## 本仓库接口

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | 无 | 健康检查、允许的产品和全局试用上限 |
| GET | `/api/v1/public-key` | 无 | 构建时核对公钥；不能直接作为客户端运行时信任锚 |
| POST | `/api/v1/devices/challenge` | 无 | 一次性挑战：`trial/latest` 120 秒，`register` 15 分钟 |
| POST | `/api/v1/trial/apply` | 设备签名 | 首次登记公钥并签发试用；重复领取须用原设备私钥签名 |
| POST | `/api/v1/licenses/latest` | 已登记设备签名 | 领取未过期的在线授权；原无认证 GET 现返回 405 |
| POST | `/api/v1/devices/register` | `X-Admin-Token` + 新设备签名 | 人工登记/轮换公钥，适用于已有付费授权或密钥丢失 |
| POST | `/api/v1/devices/revoke` | `X-Admin-Token` | 禁止设备继续联网领取；**不撤销已签发的离线 Token** |
| POST | `/api/v1/licenses/renew` | `X-Admin-Token` | 新签一张授权，**不会自动撤销旧授权** |
| POST | `/api/v1/licenses/offline-issue` | `X-Admin-Token` | 签发离线授权供手动交付 |
| GET | `/api/v1/licenses/query` | `X-Admin-Token` | 按产品和机器码查签发记录 |
| GET | `/api/v1/stats` | `X-Admin-Token` | 统计数据，不返回完整 Token |

请求和响应均为 JSON：成功 `{"ok":true,"data":{...}}`，失败 `{"ok":false,"error":"..."}`；当前不保证返回 `code`。`/admin` 为管理页，`/admin/stats` 为统计页。未配置管理员 Token 时管理 API 不可用；**没有默认管理员 Token**。

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

恢复试用须重新领取 `trial` 挑战并用**原私钥**签名；没有公钥登记的旧试用/付费记录不得自助认领，由管理员核实后走 `register`。领取续期先取 `latest` 挑战，再向 `POST /api/v1/licenses/latest` 提交 `app_name`、`machine_code`、`challenge`、`signature`（不提交公钥）。挑战仅能使用一次，不能跨用途、产品或机器；设备凭据被吊销或证明失败返回 403；没有未过期在线授权返回 404，**不是吊销证据**。离线手工签发的 Token 不由 `latest` 返回。管理员登记/轮换时，客户端先获取 `register` 挑战并对相同格式内容签名，管理员通过受控渠道取得公钥、机器码、挑战和签名，连同管理员 Token 调用 `/api/v1/devices/register`；丢失私钥需要人工核验并重新登记。管理员可通过 `/api/v1/devices/revoke` 提交 `app_name` 和 `machine_code` 停用旧设备凭据。

`LICENSE_SERVICE_TRIAL_DAYS` 是全局上限（代码与示例配置默认 30），`LICENSE_SERVICE_TRIAL_DAYS_MAP` 可设置产品上限。有效正整数 `trial_days` 被钳制到上限；缺失/非法时取上限。新签试用按服务端 UTC 日期计算首次到期日；响应 `data.trial_days` 是首次实际发放天数。已登记设备重复领取会新签一个 Token，但沿用首次到期日；过期后返回 HTTP 409 `trial expired`。请通过代理对公开挑战/试用/领取接口配置 IP 限流、请求体大小限制与监控。设备公钥签名用于**取回授权**，不能代替客户端下载后的 Ed25519 许可证验签。

Token 格式为 `<产品前缀>.<base64url(payload)>.<base64url(Ed25519签名)>`；签名覆盖原始 payload JSON 字节。内置前缀：`ControlCommand=RCC1`、`E-Player=EPL`、`WinPilot=WPL`、`iCMS=ICMS`、`rust-node=RUSTNODE`。代码及示例配置默认允许这五个产品，生产部署应按实际开通范围收窄 `LICENSE_SERVICE_ALLOWED_APPS`；客户端需内置经独立渠道核对的生产公钥并校验前缀、签名、产品、机器码、日期。

## 部署准备

1. 使用受支持的 Python 环境安装依赖：`python -m pip install -r requirements.txt`。从 `.env.example` 创建本机 `.env`，将管理员 Token 和机器码哈希盐设为随机且私密的值，配置实际允许的产品与试用上限；`.env` 不入库。
2. 新环境第一次启动可创建 Ed25519 密钥对；**现有服务迁移时必须恢复原私钥、公钥、数据库和原机器码哈希盐，不要重新生成/更改**。任意一把缺失/两把不匹配、或已有数据库但密钥均缺失时服务拒绝启动。生产私钥和数据库（包括 SQLite 的 WAL/SHM）要作为同一恢复点备份；私钥只留服务端，不放进安装包。更改哈希盐会使历史机器码无法查询，并可能重新领取试用。
3. `python app.py` 仅用于本地开发。公网使用进程管理器和生产 WSGI 服务，反向代理配置 HTTPS、请求体限制、试用限流、管理路径访问控制及健康检查。不要把 Flask 开发服务器直接暴露公网。
4. 旧版 `GET /api/v1/licenses/latest` 与无设备签名的试用客户端**不兼容**。上线前先更新测试客户端，备份原数据及密钥；现有试用/付费机器若未登记公钥，需要管理员验证身份后调用 `/api/v1/devices/register`，不得仅凭机器码自动迁移。部署后只读核对 `/api/v1/health`、`/api/v1/public-key` 和允许的产品；从安全渠道与客户端内置公钥对拍。签发测试使用独立测试环境，避免占用真实设备试用资格。

## 与公网版本的关系

本地工作区已将原先只凭机器码获取完整 Token 的 `GET /api/v1/licenses/latest` 改为设备签名认证的 POST 协议；**此改动尚未部署到 `https://licenses.lonk.vip`，不能以本 README 推断现网能力**。发布前须核对部署 commit、数据库备份及密钥指纹，并按上述步骤完成客户端与已授权设备迁移；不要直接覆盖生产版本。

## 测试

`python -m unittest discover -s tests -v`。测试使用临时数据库和临时密钥，不访问公网，也不会修改生产授权。
