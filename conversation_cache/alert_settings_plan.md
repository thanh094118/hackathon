# Alert Credential Settings Plan (2026-05-31)

Goal: add a dashboard Settings section served by `src/dashboard/server.py` / `src/dashboard/api.py` that lets an operator configure Email, Telegram, and Slack alert credentials for `src/alerts/`, persists those credentials in MongoDB, and stores sensitive values encrypted at rest.

## Current State

- `src/alerts/config.py` currently builds `AlertConfig` only from environment variables.
- `src/alerts/dispatcher.py` calls `load_alert_config()` when no config is injected.
- `src/dashboard/server.py` only starts the FastAPI app with uvicorn.
- `src/dashboard/api.py` owns REST endpoints and serves `src/dashboard/static/index.html`.
- `src/dashboard/static/index.html` currently has `#overview` and `#investigator` views, but no settings view.
- MongoDB connectivity for dashboard reads is centralized through `DashboardQueryAdapter`, which already handles mock mode and missing MongoDB gracefully.
- `requirements.txt` does not currently include an encryption library such as `cryptography`.

## Requirements

- Add a Settings navigation item and Settings view to the static dashboard.
- Provide forms for:
  - global alert enablement, dry-run mode, dashboard URL, channel allow-list
  - Email: enabled, SMTP host, port, username, password, from, to, TLS
  - Telegram: enabled, bot token, chat ID
  - Slack: enabled, webhook URL
- Persist settings in MongoDB, not `.env`.
- Encrypt secrets before writing to MongoDB:
  - `smtp_password`
  - `telegram_bot_token`
  - `slack_webhook_url`
- Never return decrypted secrets to the browser after save; return only masked values and metadata.
- Keep env-based config as fallback for local/manual workflows.
- Preserve dry-run behavior so settings can be tested without network delivery.
- Add tests for encryption, MongoDB persistence, API masking, env fallback, and alert config loading from stored settings.

## Proposed MongoDB Shape

Collection: `alert_settings`

Document key:

```json
{
  "_id": "default",
  "alerts_enabled": true,
  "dry_run": true,
  "channels": ["email", "telegram", "slack"],
  "dashboard_url": "http://127.0.0.1:8501",
  "email": {
    "enabled": true,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_username": "user@example.com",
    "smtp_password_encrypted": "<fernet-token>",
    "smtp_from": "alerts@example.com",
    "smtp_to": "soc@example.com",
    "smtp_use_tls": true
  },
  "telegram": {
    "enabled": true,
    "bot_token_encrypted": "<fernet-token>",
    "chat_id": "123456"
  },
  "slack": {
    "enabled": true,
    "webhook_url_encrypted": "<fernet-token>"
  },
  "created_at": "<utc datetime>",
  "updated_at": "<utc datetime>"
}
```

Browser responses should replace encrypted fields with masks such as:

```json
{
  "smtp_password_set": true,
  "smtp_password_mask": "********"
}
```

## Encryption Design

- Add `cryptography` to `requirements.txt` and use `cryptography.fernet.Fernet`.
- Read key from `ALERT_SETTINGS_ENCRYPTION_KEY`.
- Provide a helper script or documented command to generate a key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

- If the key is missing:
  - API write endpoints must return a clear configuration error and must not store plaintext secrets.
  - API read endpoints may still return non-secret metadata if MongoDB is available.
  - Alert dispatcher fallback should continue using env settings.
- Store encryption-key guidance in `.env.example` as a placeholder only.

## Backend Modules

Add:

- `src/alerts/crypto.py`
  - `encrypt_secret(value: str | None) -> str | None`
  - `decrypt_secret(token: str | None) -> str | None`
  - `mask_secret(is_set: bool) -> str`
  - raises a controlled error if encryption key is missing or invalid.

- `src/alerts/settings_store.py`
  - MongoDB-backed repository for the default alert settings document.
  - Converts between API payloads, stored encrypted documents, masked public documents, and `AlertConfig`.
  - Uses `$set` / `replace_one(..., upsert=True)` on `_id: "default"`.
  - Supports mock/no-Mongo safe failure responses through the API layer.

Update:

- `src/alerts/config.py`
  - Keep `load_alert_config(env=None)` unchanged for compatibility.
  - Add `load_alert_config_from_mongo(...)` or `load_effective_alert_config(...)` that tries MongoDB settings first and falls back to env.

- `src/alerts/dispatcher.py`
  - `build_default_dispatcher()` should use effective config so runtime alert delivery can pick up dashboard-managed settings.

- `src/dashboard/api.py`
  - Add `GET /api/settings/alerts`.
  - Add `PUT /api/settings/alerts`.
  - Add `POST /api/settings/alerts/test` for dry-run or selected-channel test notification.

## Frontend Plan

Update `src/dashboard/static/index.html`:

- Add `#settings` navigation item with a `settings` material icon.
- Add `view-settings-container` below existing view containers.
- Extend `routeView()`:
  - reset `navSettings` with the other nav items
  - title: `Settings`
  - hide timeframe selector
  - show settings container
  - call `loadAlertSettings()`
- Add alert credential form sections:
  - Global
  - Email
  - Telegram
  - Slack
- For secrets:
  - show masked status if already configured
  - leave input blank unless operator is replacing the secret
  - send secret fields only when non-empty
- Add Save Settings and Test Alert buttons.

## Validation And Tests

Add focused tests:

- `tests/test_alert_settings_store.py`
  - encrypt/decrypt round trip
  - missing encryption key refuses secret writes
  - public payload masks secrets
  - Mongo document does not contain plaintext secret values
  - conversion to `AlertConfig` decrypts correctly

- `tests/test_dashboard_api.py`
  - `GET /api/settings/alerts` returns masked payload
  - `PUT /api/settings/alerts` persists settings through a patched store
  - secret fields are not returned
  - missing encryption key returns a 500/503-style configuration error for writes

Run:

```bash
python -m compileall src
pytest -q tests/test_alerts.py tests/test_dashboard_api.py tests/test_alert_settings_store.py
```

## Rollout Order

1. Add dependency and encryption helper.
2. Add MongoDB settings store and tests.
3. Add effective config loading and dispatcher integration.
4. Add dashboard API endpoints and tests.
5. Add Settings UI and client-side API calls.
6. Verify compile and focused tests.
7. Update cache files with implementation status and any final behavior decisions.

## Security Notes

- Do not write secrets to logs, test snapshots, or browser responses.
- Do not modify local `.env`; only update `.env.example` placeholders.
- Do not support plaintext MongoDB fallback for secrets.
- Treat losing `ALERT_SETTINGS_ENCRYPTION_KEY` as losing the ability to decrypt stored dashboard-managed credentials.
