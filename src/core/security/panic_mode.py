import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from core.events import event_bus

logger = logging.getLogger("PanicMode")


class PanicMode:
    """Координатор аварийного режима для интеграций GUI и системного трея."""

    def __init__(self, config: Optional[dict] = None, bus=event_bus):
        self.config = config or {}
        self.bus = bus
        self.activated = False
        self._handlers: list[Callable[[str], None]] = []
        self._lock = threading.RLock()
        self._window_positions = deque(maxlen=8)
        self.register_handler(self._wipe_secure_memory)

    def register_handler(self, handler: Callable[[str], None]):
        with self._lock:
            self._handlers.append(handler)

    def activate(self, method: str = "manual") -> bool:
        if not self.is_enabled:
            return False
        with self._lock:
            if self.activated:
                return False
            self.activated = True
            handlers = list(self._handlers)

        payload = self._activation_payload(method)
        self.bus.publish("PanicModeActivated", payload)
        for handler in handlers:
            try:
                handler(method)
            except Exception as exc:
                logger.error("Panic handler failed: %s", exc)
                self.bus.publish("PanicModeHandlerFailed", {"method": method, "error": str(exc)})
        self.execute_stealth_actions(method)
        return True

    def reset(self):
        with self._lock:
            self.activated = False
        self.bus.publish("PanicModeDeactivated", {})

    def recover(self, method: str = "manual") -> bool:
        with self._lock:
            if not self.activated:
                return False
        self.bus.publish("PanicModeRecoveryStarted", {"method": method})
        self.reset()
        return True

    @property
    def is_enabled(self) -> bool:
        return self._config_bool("panic_mode_enabled", True)

    @property
    def close_application(self) -> bool:
        return self._config_bool("panic_close_application", False)

    @property
    def stealth_mode(self) -> bool:
        return self._config_bool("panic_stealth_mode", False)

    def hotkey_sequence(self) -> str:
        hotkey = str(self._config_get("panic_hotkey", "Ctrl+Shift+Esc"))
        tokens = [token.strip().lower() for token in hotkey.replace("+", " ").split() if token.strip()]
        mapping = {
            "ctrl": "Control",
            "control": "Control",
            "shift": "Shift",
            "alt": "Alt",
            "esc": "Escape",
            "escape": "Escape",
        }
        mapped = [mapping.get(token, token.capitalize()) for token in tokens]
        return f"<{'-'.join(mapped)}>" if mapped else "<Control-Shift-Escape>"

    def record_window_position(self, x: int, y: int, now: Optional[float] = None) -> bool:
        if not self._config_bool("panic_mouse_gesture_enabled", True):
            return False
        now = time.monotonic() if now is None else now
        self._window_positions.append((now, int(x), int(y)))
        if self._detect_shake():
            position_count = len(self._window_positions)
            self._window_positions.clear()
            self.bus.publish("PanicMouseGestureDetected", {"positions": position_count})
            return True
        return False

    def execute_stealth_actions(self, method: str = "manual") -> list[dict]:
        if not self.stealth_mode:
            return []
        actions = []
        if self._config_bool("panic_show_fake_error", False):
            actions.append(
                {
                    "type": "fake_error",
                    "message": self._config_get(
                        "panic_fake_error_message",
                        "The application has encountered an unexpected error.",
                    ),
                }
            )
        if self._config_bool("panic_launch_decoy", False):
            command = str(self._config_get("panic_decoy_command", "") or "").strip()
            if command:
                actions.append({"type": "launch_decoy", "command": command})
        redirect_url = str(self._config_get("panic_redirect_url", "") or "").strip()
        if redirect_url:
            actions.append({"type": "redirect_url", "url": redirect_url})

        for action in actions:
            payload = {"method": method, **action}
            self.bus.publish("PanicStealthActionRequested", payload)
        return actions

    def _wipe_secure_memory(self, method: str):
        from core.security.memory_guard import get_secure_memory

        wiped = get_secure_memory().wipe_all()
        self.bus.publish("SecureMemoryWiped", {"reason": "panic_mode", "count": wiped, "method": method})

    def _activation_payload(self, method: str) -> dict:
        return {
            "method": method,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stealth_mode": self.stealth_mode,
            "close_application": self.close_application,
        }

    def _detect_shake(self) -> bool:
        if len(self._window_positions) < 6:
            return False
        positions = list(self._window_positions)
        if positions[-1][0] - positions[0][0] > 1.2:
            return False

        changes = 0
        previous_direction = 0
        for (_, prev_x, _), (_, cur_x, _) in zip(positions, positions[1:]):
            delta = cur_x - prev_x
            if abs(delta) < 24:
                continue
            direction = 1 if delta > 0 else -1
            if previous_direction and direction != previous_direction:
                changes += 1
            previous_direction = direction
        return changes >= 4

    def _config_get(self, key: str, default=None):
        if hasattr(self.config, "get"):
            return self.config.get(key, default)
        return default

    def _config_bool(self, key: str, default: bool = False) -> bool:
        value = self._config_get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)
