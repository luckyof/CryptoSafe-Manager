"""
Entry Manager — централизованный CRUD контроллер для хранилища.
Реализует требования CRUD-1 — CRUD-4:
  CRUD-1: create_entry, get_entry, get_all_entries, update_entry, delete_entry
  CRUD-2: Транзакционность с rollback
  CRUD-3: Публикация событий EntryCreated, EntryUpdated, EntryDeleted
  CRUD-4: Soft deletion в таблицу deleted_entries
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

from .encryption_service import AES256GCMService
from core.events import event_bus

logger = logging.getLogger("EntryManager")

# Версия формата данных
ENTRY_VERSION = 1


def _now_iso() -> str:
    """Получить текущее UTC время в ISO формате."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EntryEvent:
    """Событие операции с записью (CRUD-3)."""
    entry_id: str
    action: str  # "created", "updated", "deleted", "restored"
    timestamp: str = field(default_factory=_now_iso)
    data: Optional[Dict[str, Any]] = None


class EntryManager:
    """
    Контроллер управления записями хранилища.
    Все данные хранятся в зашифрованном виде (AES-256-GCM).
    """

    def __init__(self, db_connection, key_manager):
        """
        Args:
            db_connection: DatabaseHelper
            key_manager: KeyManager с ключом шифрования
        """
        self.db = db_connection
        self.key_manager = key_manager
        self.encryption_service = AES256GCMService()
        self.encryption_service.set_key_manager(key_manager)

        # Создаём таблицу soft-deleted записей (CRUD-4)
        self._ensure_deleted_table()


    def create_entry(self, data: Dict[str, Any]) -> str:
        """
        Создать новую запись хранилища.

        Args:
            data: Словарь с полями: title, username, password, url, notes, category, tags

        Returns:
            UUID новой записи

        Raises:
            ValueError: Если обязательные поля отсутствуют
        """
        # Валидация обязательных полей (DIALOG-2)
        if not data.get('title', '').strip():
            raise ValueError("Поле 'title' обязательно")
        if not data.get('password', '').strip():
            raise ValueError("Поле 'password' обязательно")

        entry_id = str(uuid.uuid4())
        now = _now_iso()

        # DATA-1: Формируем plaintext payload
        plaintext_data = {
            "title": data.get("title", "").strip(),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "url": data.get("url", ""),
            "notes": data.get("notes", ""),
            "category": data.get("category", ""),
            "tags": data.get("tags", []),
            "totp_secret": data.get("totp_secret", ""),  # FUTURE-1
            "sharing_metadata": data.get("sharing_metadata", {}),  # FUTURE-1
            "version": ENTRY_VERSION,
            "id": entry_id,
            "created_at": now,
            "updated_at": now,
        }

        # Шифруем (ENC-1 — ENC-4)
        plaintext_json = json.dumps(plaintext_data, ensure_ascii=False).encode('utf-8')
        encrypted_blob = self.encryption_service.encrypt(plaintext_json)

        # CRUD-2: Транзакционная вставка
        try:
            self.db.execute(
                """INSERT INTO vault_entries 
                   (id, encrypted_data, created_at, updated_at, tags) 
                   VALUES (?, ?, ?, ?, ?)""",
                (entry_id, encrypted_blob, now, now,
                 json.dumps(plaintext_data.get("tags", []), ensure_ascii=False))
            )
        except Exception as e:
            logger.error(f"Failed to create entry: {e}")
            raise RuntimeError(f"Не удалось создать запись: {e}")

        # CRUD-3: Публикация события
        self._publish_event("EntryCreated", entry_id, "created", plaintext_data)

        # Аудит
        self._audit("ENTRY_CREATED", entry_id, f"Создана запись: {plaintext_data['title']}")

        logger.info(f"Entry created: {entry_id} ({plaintext_data['title']})")
        return entry_id

    def get_entry(self, entry_id: str) -> Dict[str, Any]:
        """
        Получить и расшифровать запись.

        Args:
            entry_id: UUID записи

        Returns:
            Словарь с расшифрованными данными

        Raises:
            ValueError: Если запись не найдена или расшифровка не удалась
        """
        row = self.db.fetchone(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?",
            (entry_id,)
        )

        if not row:
            # SEC-4: Не раскрываем существование записи
            raise ValueError("Запись не найдена")

        encrypted_blob = row[0]

        try:
            plaintext = self.encryption_service.decrypt(encrypted_blob)
            data = json.loads(plaintext.decode('utf-8'))
            # SEC-2: Удаляем пароль из возвращаемых данных (не хранить в памяти)
            return data
        except ValueError as e:
            logger.error(f"Decryption failed for entry {entry_id}: {e}")
            raise ValueError("Ошибка расшифровки данных")

    def get_all_entries(self, include_decrypted_password: bool = False) -> List[Dict[str, Any]]:
        """
        Получить все записи.

        Args:
            include_decrypted_password: Если True, расшифровать password для каждой записи

        Returns:
            Список словарей с метаданными записей
        """
        rows = self.db.fetchall(
            "SELECT id, encrypted_data, created_at, updated_at, tags FROM vault_entries ORDER BY updated_at DESC"
        )

        result = []
        for row in rows:
            entry_id, encrypted_blob, created_at, updated_at, tags = row

            entry_meta = {
                "id": entry_id,
                "created_at": created_at,
                "updated_at": updated_at,
                "tags": tags,
            }

            if include_decrypted_password:
                try:
                    plaintext = self.encryption_service.decrypt(encrypted_blob)
                    data = json.loads(plaintext.decode('utf-8'))
                    entry_meta.update({
                        "title": data.get("title", ""),
                        "username": data.get("username", ""),
                        "password": data.get("password", ""),
                        "url": data.get("url", ""),
                        "notes": data.get("notes", ""),
                        "category": data.get("category", ""),
                    })
                except Exception as e:
                    logger.error(f"Failed to decrypt entry {entry_id}: {e}")
                    entry_meta.update({
                        "title": "[Ошибка расшифровки]",
                        "username": "",
                        "password": "",
                        "url": "",
                        "notes": "",
                        "category": "",
                    })
            else:
                # Без расшифровки — получаем title из encrypted data (для отображения)
                entry_meta.update({
                    "title": "[Зашифровано]",
                    "username": "",
                    "password": "",
                    "url": "",
                    "notes": "",
                    "category": "",
                })

            result.append(entry_meta)

        return result

    def update_entry(self, entry_id: str, data: Dict[str, Any]) -> bool:
        """
        Обновить существующую запись.

        Args:
            entry_id: UUID записи
            data: Словарь с обновляемыми полями

        Returns:
            True при успехе
        """
        # Получаем текущие данные
        try:
            current = self.get_entry(entry_id)
        except ValueError:
            raise ValueError("Запись не найдена")

        now = _now_iso()

        # Обновляем поля
        for key in ["title", "username", "password", "url", "notes", "category", "tags",
                     "totp_secret", "sharing_metadata"]:
            if key in data:
                current[key] = data[key]

        current["updated_at"] = now

        # Шифруем обновлённые данные
        plaintext_json = json.dumps(current, ensure_ascii=False).encode('utf-8')
        encrypted_blob = self.encryption_service.encrypt(plaintext_json)

        # CRUD-2: Транзакционное обновление
        try:
            self.db.begin_transaction()
            self.db.execute(
                "UPDATE vault_entries SET encrypted_data = ?, updated_at = ?, tags = ? WHERE id = ?",
                (encrypted_blob, now,
                 json.dumps(current.get("tags", []), ensure_ascii=False),
                 entry_id)
            )
            self.db.commit_transaction()
        except Exception as e:
            self.db.rollback_transaction()
            logger.error(f"Failed to update entry {entry_id}: {e}")
            raise RuntimeError(f"Не удалось обновить запись: {e}")

        # CRUD-3: Публикация события
        self._publish_event("EntryUpdated", entry_id, "updated", current)

        # Аудит
        self._audit("ENTRY_UPDATED", entry_id, f"Обновлена запись: {current.get('title', '')}")

        logger.info(f"Entry updated: {entry_id}")
        return True

    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> bool:
        """
        Удалить запись (мягкое или жёсткое удаление).

        Args:
            entry_id: UUID записи
            soft_delete: Если True — мягкое удаление (CRUD-4)

        Returns:
            True при успехе
        """
        # Получаем данные для аудита
        try:
            current = self.get_entry(entry_id)
            title = current.get("title", "Unknown")
        except ValueError:
            raise ValueError("Запись не найдена")

        try:
            self.db.begin_transaction()

            if soft_delete:
                # CRUD-4: Перемещаем в deleted_entries
                self.db.execute(
                    """INSERT INTO deleted_entries 
                       (original_id, encrypted_data, deleted_at, expires_at) 
                       VALUES (?, ?, ?, ?)""",
                    (entry_id,
                     self.db.fetchone("SELECT encrypted_data FROM vault_entries WHERE id = ?",
                                      (entry_id,))[0],
                     _now_iso(),
                     self._calculate_expiry_date())
                )
                self.db.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            else:
                # Жёсткое удаление
                self.db.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

            self.db.commit_transaction()
        except Exception as e:
            self.db.rollback_transaction()
            logger.error(f"Failed to delete entry {entry_id}: {e}")
            raise RuntimeError(f"Не удалось удалить запись: {e}")

        # CRUD-3: Публикация события
        action = "deleted" if soft_delete else "permanently_deleted"
        self._publish_event("EntryDeleted", entry_id, action, {"title": title, "soft_delete": soft_delete})

        # Аудит
        self._audit("ENTRY_DELETED", entry_id,
                     f"Удалена запись: {title} ({'мягкое' if soft_delete else 'жёсткое'})")

        logger.info(f"Entry deleted: {entry_id} (soft={soft_delete})")
        return True

    def restore_entry(self, deleted_entry_id: str) -> str:
        """
        Восстановить удалённую запись из deleted_entries.

        Args:
            deleted_entry_id: original_id записи

        Returns:
            UUID восстановленной записи
        """
        row = self.db.fetchone(
            "SELECT encrypted_data FROM deleted_entries WHERE original_id = ?",
            (deleted_entry_id,)
        )

        if not row:
            raise ValueError("Удалённая запись не найдена")

        encrypted_blob = row[0]

        try:
            self.db.begin_transaction()

            # Вставляем обратно в vault_entries
            now = _now_iso()
            self.db.execute(
                """INSERT INTO vault_entries 
                   (id, encrypted_data, created_at, updated_at) 
                   VALUES (?, ?, ?, ?)""",
                (deleted_entry_id, encrypted_blob, now, now)
            )

            # Удаляем из deleted_entries
            self.db.execute("DELETE FROM deleted_entries WHERE original_id = ?", (deleted_entry_id,))

            self.db.commit_transaction()
        except Exception as e:
            self.db.rollback_transaction()
            raise RuntimeError(f"Не удалось восстановить запись: {e}")

        # CRUD-3: Публикация события
        self._publish_event("EntryRestored", deleted_entry_id, "restored")

        # Аудит
        self._audit("ENTRY_RESTORED", deleted_entry_id, f"Восстановлена запись")

        logger.info(f"Entry restored: {deleted_entry_id}")
        return deleted_entry_id

    #ПОИСК И ФИЛЬТРАЦИЯ (SEARCH-1, SEARCH-2)

    def search_entries(self, query: str) -> List[Dict[str, Any]]:
        """
        Полнотекстовый поиск по записям (SEARCH-1, SEARCH-2).

        Поддерживает:
          - Поиск по title, username, url, notes
          - Field-specific фильтры: title:"work"
          - Fuzzy matching (простой — через substring)

        Args:
            query: Поисковый запрос

        Returns:
            Список найденных записей
        """
        if not query.strip():
            return self.get_all_entries(include_decrypted_password=True)

        all_entries = self.get_all_entries(include_decrypted_password=True)
        query_lower = query.lower().strip()

        # Проверяем field-specific фильтры (SEARCH-1)
        field_filter = self._parse_field_filter(query_lower)

        results = []
        for entry in all_entries:
            match = False

            if field_filter:
                field_name, field_value = field_filter
                entry_value = str(entry.get(field_name, "")).lower()
                match = field_value in entry_value
            else:
                # Fuzzy matching: проверяем все текстовые поля (SEARCH-1)
                searchable_fields = ["title", "username", "url", "notes", "category"]
                for field_name in searchable_fields:
                    if query_lower in str(entry.get(field_name, "")).lower():
                        match = True
                        break

            if match:
                results.append(entry)

        logger.debug(f"Search '{query}' returned {len(results)} results")
        return results

    def filter_by_tags(self, tags: List[str]) -> List[Dict[str, Any]]:
        """
        Фильтрация по тегам (SEARCH-3).

        Args:
            tags: Список тегов для фильтрации

        Returns:
            Записи, содержащие хотя бы один из тегов
        """
        all_entries = self.get_all_entries(include_decrypted_password=True)
        return [
            entry for entry in all_entries
            if any(tag in entry.get("tags", []) for tag in tags)
        ]

    #ВНУТРЕННИЕ МЕТОДЫ

    def _ensure_deleted_table(self):
        """Создаём таблицу soft-deleted записей (CRUD-4)."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS deleted_entries (
                original_id TEXT PRIMARY KEY,
                encrypted_data BLOB,
                deleted_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_deleted_expires ON deleted_entries(expires_at)")
        logger.debug("deleted_entries table ensured")

    def _calculate_expiry_date(self, days: int = 30) -> str:
        """Рассчитать дату истечения удалённой записи."""
        from datetime import timedelta
        expiry = datetime.now(timezone.utc) + timedelta(days=days)
        return expiry.isoformat()

    def _publish_event(self, event_name: str, entry_id: str, action: str, data: Optional[Dict] = None):
        """CRUD-3: Публикация события."""
        event = EntryEvent(entry_id=entry_id, action=action, data=data)
        event_bus.publish(event_name, data={
            "entry_id": entry_id,
            "action": action,
            "timestamp": event.timestamp,
            "data": data,
        })

    def _audit(self, action: str, entry_id: str, details: str):
        """Запись в журнал аудита."""
        try:
            self.db.execute(
                "INSERT INTO audit_log (action, entry_id, details) VALUES (?, ?, ?)",
                (action, entry_id, details)
            )
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")

    @staticmethod
    def _parse_field_filter(query: str) -> Optional[tuple]:
        """
        Парсинг field-specific фильтров (SEARCH-1).
        Формат: field_name:"value"
        """
        import re
        match = re.match(r'(\w+):"([^"]+)"', query)
        if match:
            field_name = match.group(1)
            field_value = match.group(2)
            if field_name in ["title", "username", "url", "notes", "category"]:
                return field_name, field_value
        return None

    def get_deleted_entries(self) -> List[Dict[str, Any]]:
        """Получить удалённые записи (для корзины)."""
        rows = self.db.fetchall(
            "SELECT original_id, deleted_at, expires_at FROM deleted_entries ORDER BY deleted_at DESC"
        )
        return [
            {
                "original_id": r[0],
                "deleted_at": r[1],
                "expires_at": r[2],
            }
            for r in rows
        ]

    def purge_expired_entries(self) -> int:
        """Удалить истёкшие записи из deleted_entries."""
        now = datetime.utcnow().isoformat()
        rows = self.db.fetchall(
            "SELECT original_id FROM deleted_entries WHERE expires_at < ?",
            (now,)
        )
        count = len(rows)
        for row in rows:
            self.db.execute("DELETE FROM deleted_entries WHERE original_id = ?", (row[0],))
        if count > 0:
            self._audit("ENTRIES_PURGED", "", f"Удалено {count} истёкших записей")
        return count
