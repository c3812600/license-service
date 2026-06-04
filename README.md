## RCC License Service

Standalone license service for `ControlCommand`.

Current goals:
- issue a one-time 1-year trial license for new users
- prevent repeated trial claims for the same machine code
- renew or upgrade licenses on the server side
- keep offline activation support for air-gapped deployments

## Directory Layout

- `app.py`: service entrypoint
- `license_service/`: Flask app, SQLite helpers, signing logic
- `.env.example`: required environment variables
- `requirements.txt`: Python dependencies

## Current API

- `GET /api/v1/health`
- `GET /api/v1/public-key`
- `POST /api/v1/trial/apply`
- `POST /api/v1/licenses/renew` (`X-Admin-Token` required)
- `POST /api/v1/licenses/offline-issue` (`X-Admin-Token` required)
- `GET /api/v1/licenses/query` (`X-Admin-Token` required)

## Quick Start

1. Create a virtual environment and install dependencies.
2. Copy `.env.example` to `.env` and adjust the values.
3. Start the service with `python app.py`.
4. On first start, the service auto-generates an Ed25519 key pair under `keys/`.
5. The SQLite database is created automatically under `data/`.

Example:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Notes

- Keep `keys/ed25519-private.pem` private and never expose it publicly.
- The RCC client should only use the public key for license verification.
- Trial claim deduplication is enforced on the server side by machine-code hash records.
- This directory is meant to be moved out and deployed separately from the main RCC project.
