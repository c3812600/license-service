## RCC License Service

Standalone license service for `ControlCommand`, `E-Player`, and `WinPilot`.

### Features

- Issue online trial licenses (1 year)
- Renew licenses via admin API
- Issue offline licenses for air-gapped deployments
- Query license status by machine code

### Quick Start

#### macOS/Linux:

```bash
cd license-service
chmod +x start.sh
./start.sh
```

#### Windows:

```cmd
cd license-service
start.bat
```

### Configuration

Edit `.env` file to configure:

```env
PORT=8765
LICENSE_SERVICE_SECRET_KEY=your-secret-key
LICENSE_SERVICE_ADMIN_TOKEN=your-admin-token
LICENSE_SERVICE_MACHINE_CODE_SALT=your-salt
LICENSE_SERVICE_ALLOWED_APPS=ControlCommand,E-Player,WinPilot
LICENSE_SERVICE_TRIAL_DAYS=365
```

### Admin Token

The admin token is required for:
- Querying licenses
- Renewing licenses
- Issuing offline licenses

**Default token:** `rcc-admin-token-2024`

### API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/public-key` | No | Get Ed25519 public key |
| POST | `/api/v1/trial/apply` | No | Request trial license |
| POST | `/api/v1/licenses/renew` | Admin | Renew license |
| POST | `/api/v1/licenses/offline-issue` | Admin | Issue offline license |
| GET | `/api/v1/licenses/query` | Admin | Query licenses |

### License Format

#### New Format (Ed25519 signed):
```
PREFIX.{payload}.{signature}
```

- ControlCommand: `RCC1.xxx.xxx`
- E-Player: `EPL.xxx.xxx`
- WinPilot: `WPL.xxx.xxx`

#### Legacy Format (AES-CBC):
```
Base64 encrypted string
```

### Admin Interface

Open `http://localhost:8765/admin` in browser.

Enter the admin token in the "Admin Token" field.
