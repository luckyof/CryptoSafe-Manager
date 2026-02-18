from typing import Callable, Dict, List, Any
from dataclasses import dataclass
import asyncio
import logging

#определение типов событий (EVT-1)
@dataclass
class Event:
    name: str
    data: Any = None

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger("EventBus")

    def subscribe(self, event_name: str, callback: Callable):
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        self._subscribers[event_name].append(callback)
        self.logger.debug(f"Подписка на событие: {event_name}")

    def publish(self, event_name: str, data: Any = None):
        event = Event(name=event_name, data=data)
        self.logger.info(f"Событие опубликовано: {event_name}")
        
        if event_name in self._subscribers:
            for callback in self._subscribers[event_name]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        try:
                            loop = asyncio.get_event_loop()
                            loop.create_task(callback(event))
                        except RuntimeError:
                            self.logger.warning("Нет активного event loop для async callback")
                    else:
                        callback(event)
                except Exception as e:
                    self.logger.error(f"Ошибка в обработчике события {event_name}: {e}")

#глобальный экземпляр шины событий
event_bus = EventBus()
