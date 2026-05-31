# CryptoSafe Manager - Technical Summary

## Архитектура

Проект разделен на три слоя:

- `src/gui`: Tkinter GUI, диалоги, таблицы, tray integration.
- `src/core`: бизнес-логика, crypto, vault operations, clipboard, audit, import/export, security hardening.
- `src/database`: SQLite helper, schema migrations, indexes and transactions.

Компоненты связываются через `EventBus`, что позволяет audit logger, clipboard service, panic mode и GUI реагировать на события без жесткой связности.

## Криптографические решения

- **Master password verification**: Argon2id/PBKDF2 параметры в `core.crypto.key_derivation`.
- **Entry encryption**: AES-256-GCM с уникальными nonce.
- **Export encryption**: AES-GCM с ключами, производными от пароля, и metadata для восстановления параметров.
- **Key separation**: authentication hash и encryption key разделены.
- **Constant-time checks**: security-critical comparisons используют constant-time helpers.

## Secure memory и side-channel hardening

`src/core/security` содержит:

- `memory_guard.py`: secure allocation, wiping, canaries, global wipe.
- `side_channel_protection.py`: constant-time compare/search helpers and crypto jitter.
- `activity_monitor.py`: idle tracking and auto-lock.
- `panic_mode.py`: emergency response orchestration.
- `platform_security.py`: OS capability detection and secure fallback policy.
- `security_validator.py`: validation/performance/security reports.

## База данных

SQLite используется как локальное хранилище. Основные таблицы:

- `vault_entries`: зашифрованные записи vault.
- `deleted_entries`: soft-delete/recovery.
- `settings`: конфигурация приложения.
- `key_store`: параметры и данные key management.
- `audit_log`, `audit_keys`, `audit_security_events`: подписанный аудит и проверки.
- `import_export_history`: история импорта/экспорта.
- `shared_entries`, `contacts`: secure sharing и key exchange.

Миграции выполняются в `DatabaseHelper` при инициализации, версия схемы хранится через `PRAGMA user_version`.

## Импорт и экспорт

`src/core/import_export` реализует:

- native encrypted JSON;
- CSV import/export с sanitization;
- Bitwarden/LastPass compatibility;
- dry-run import, merge/replace modes, rollback/checkpoints;
- password/RSA/ECC sharing and QR chunking.

Panic mode interrupt обрывает import/export операции через event bus.

## Testing and coverage

Тесты находятся в `tests/` и покрывают core crypto, vault CRUD, clipboard, audit, import/export, security hardening. Coverage policy Sprint 8 задана в `.coveragerc`; GUI исключен из автоматического coverage и проверяется ручными smoke-сценариями.

Команда финального отчета:

```bash
pytest tests/ --cov=src --cov-report=term --cov-report=html:tests/report/html
```

## Packaging

Сборка выполняется через PyInstaller:

```bash
python build.py
```

Результат: `dist/CryptoSafeManager/`.
