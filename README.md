## License Service

为 `ControlCommand`、`E-Player` 和 `WinPilot` 提供的独立授权服务。

### 功能

- 发放在线试用授权（1 年）
- 通过管理员 API 续期授权
- 为内网/离线环境发放离线授权
- 通过机器码查询授权状态

### 配置

编辑 `.env` 文件进行配置：

```env
PORT=8765
LICENSE_SERVICE_SECRET_KEY=your-secret-key
LICENSE_SERVICE_ADMIN_TOKEN=your-admin-token
LICENSE_SERVICE_MACHINE_CODE_SALT=your-salt
LICENSE_SERVICE_ALLOWED_APPS=ControlCommand,E-Player,WinPilot
LICENSE_SERVICE_TRIAL_DAYS=365
```

### 管理员 Token

以下操作需要管理员 Token：
- 查询授权
- 续期授权
- 发放离线授权

**默认 Token：** `rcc-admin-token-2024`

### API 接口

| 方法 | 路径 | 鉴权 | 说明 |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | 否 | 健康检查 |
| GET | `/api/v1/public-key` | 否 | 获取 Ed25519 公钥 |
| POST | `/api/v1/trial/apply` | 否 | 申请试用授权 |
| POST | `/api/v1/licenses/renew` | 管理员 | 续期授权 |
| POST | `/api/v1/licenses/offline-issue` | 管理员 | 发放离线授权 |
| GET | `/api/v1/licenses/query` | 管理员 | 查询授权 |

### 授权格式

#### 新格式（Ed25519 签名）
```
PREFIX.{payload}.{signature}
```

- ControlCommand: `RCC1.xxx.xxx`
- E-Player: `EPL.xxx.xxx`
- WinPilot: `WPL.xxx.xxx`

#### 旧格式（AES-CBC）
```
Base64 encrypted string
```

### 管理后台

在浏览器打开 `http://localhost:8765/admin`。

在 “Admin Token” 输入框中填写管理员 Token。
