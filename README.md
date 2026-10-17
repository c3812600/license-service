# License Service

为 Windows 软件签发机器码绑定的 Ed25519 授权码。当前仓库实现试用申请、管理员续期签发、离线签发、管理员查询和统计；**不包含**激活码核销、客户端自动续期的设备认证、校验/吊销或换绑。客户端须自行实现机器码计算、本地验签、持久化与防时间回拨；详见 [设计规范](Windows%20软件加密授权系统设计规范与对接文档.md)。

## 本仓库接口

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | 无 | 健康检查、允许的产品和全局试用上限 |
| GET | `/api/v1/public-key` | 无 | 构建时核对公钥；不能直接作为客户端运行时信任锚 |
| POST | `/api/v1/trial/apply` | 无 | 领取/恢复试用 |
| POST | `/api/v1/licenses/renew` | `X-Admin-Token` | 新签一张授权，**不会自动撤销旧授权** |
| POST | `/api/v1/licenses/offline-issue` | `X-Admin-Token` | 签发离线授权供手动交付 |
| GET | `/api/v1/licenses/query` | `X-Admin-Token` | 按产品和机器码查签发记录 |
| GET | `/api/v1/stats` | `X-Admin-Token` | 统计数据，不返回完整 Token |

请求和响应均为 JSON：成功 `{"ok":true,"data":{...}}`，失败 `{"ok":false,"error":"..."}`；当前不保证返回 `code`。`/admin` 为管理页，`/admin/stats` 为统计页。未配置管理员 Token 时管理 API 不可用；**没有默认管理员 Token**。

试用请求示例：

```json
{"app_name":"ControlCommand","machine_code":"本机机器码","app_version":"1.2.3","trial_days":365}
```

`LICENSE_SERVICE_TRIAL_DAYS` 是全局上限（代码默认 365；示例配置为 30），`LICENSE_SERVICE_TRIAL_DAYS_MAP` 可设置产品上限。有效正整数 `trial_days` 被钳制到上限；缺失/非法时取上限。新签试用按服务端 UTC 日期计算首次到期日；响应 `data.trial_days` 是首次实际发放天数。相同产品和机器码重复领取会新签一个 Token，但沿用首次到期日；过期后返回 HTTP 409 `trial expired`。请通过代理对公开接口配置限流，并监控异常试用请求。

Token 格式为 `<产品前缀>.<base64url(payload)>.<base64url(Ed25519签名)>`；签名覆盖原始 payload JSON 字节。内置前缀：`ControlCommand=RCC1`、`E-Player=EPL`、`WinPilot=WPL`、`iCMS=ICMS`、`rust-node=RUSTNODE`。代码及示例配置默认允许这五个产品，生产部署应按实际开通范围收窄 `LICENSE_SERVICE_ALLOWED_APPS`；客户端需内置经独立渠道核对的生产公钥并校验前缀、签名、产品、机器码、日期。

## 部署准备

1. 使用受支持的 Python 环境安装依赖：`python -m pip install -r requirements.txt`。从 `.env.example` 创建本机 `.env`，将管理员 Token 和机器码哈希盐设为随机且私密的值，配置实际允许的产品与试用上限；`.env` 不入库。
2. 新环境第一次启动可创建 Ed25519 密钥对；**现有服务迁移时必须恢复原私钥、公钥、数据库和原机器码哈希盐，不要重新生成/更改**。任意一把缺失/两把不匹配、或已有数据库但密钥均缺失时服务拒绝启动。生产私钥和数据库（包括 SQLite 的 WAL/SHM）要作为同一恢复点备份；私钥只留服务端，不放进安装包。更改哈希盐会使历史机器码无法查询，并可能重新领取试用。
3. `python app.py` 仅用于本地开发。公网使用进程管理器和生产 WSGI 服务，反向代理配置 HTTPS、请求体限制、试用限流、管理路径访问控制及健康检查。不要把 Flask 开发服务器直接暴露公网。
4. 部署后只读核对 `/api/v1/health`、`/api/v1/public-key` 和允许的产品；从安全渠道与客户端内置公钥对拍。测试签发必须用专门测试机器码和测试环境，避免占用真实设备的一次试用资格。

## 与公网版本的关系

2026-10-17 的只读探测显示 `https://licenses.lonk.vip` 还提供 `/api/v1/licenses/latest` 和 `/api/v1/stats`，但前者**不在本仓库中**。历史文档描述 `latest` 可仅凭机器码取完整 Token，未用真实机器码重新验证；无论如何都不可把它作为可信的自动续期或恢复接口。公网 `/api/v1/activate`、`/api/v1/validate` 的 GET 返回 404。无法仅凭健康检查证明部署版本和仓库相同，发布前应比较部署 commit、环境配置及备份密钥指纹。不要把本仓库当前版本直接覆盖生产版本，除非先完成差异核对与回滚准备。

## 测试

`python -m unittest discover -s tests -v`。测试使用临时数据库和临时密钥，不访问公网，也不会修改生产授权。
