import logging
from typing import TYPE_CHECKING
from .events import event_bus, Event

if TYPE_CHECKING:
    from src.database.db import DatabaseHelper

logger = logging.getLogger("AuditSystem")

class AuditManager:
    def __init__(self, db_helper: 'DatabaseHelper'):
        self.db = db_helper
        self._subscribe()

    def _subscribe(self):
        event_bus.subscribe("EntryAdded", self._log_action)
        event_bus.subscribe("EntryUpdated", self._log_action)
        event_bus.subscribe("EntryDeleted", self._log_action)
        event_bus.subscribe("UserLoggedIn", self._log_action)
        logger.info("AuditManager подписан на события")

    def _log_action(self, event: Event):
        #Запись события в БД.
        try:
            # Преобразуем данные события в строку для простоты (заглушка)
            details = str(event.data) if event.data else ""
            
            self.db.execute(
                "INSERT INTO audit_log (action, details) VALUES (?, ?)",
                (event.name, details)
            )
            logger.debug(f"Записано в аудит: {event.name}")
        except Exception as e:
            logger.error(f"Ошибка записи в аудит: {e}")