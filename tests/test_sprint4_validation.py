import os
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.clipboard import clipboard_service as clipboard_service_module
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from core.clipboard.platform_adapter import (
    ClipboardAdapter,
    InMemoryClipboardAdapter,
    LinuxClipboardAdapter,
    get_default_clipboard_adapter,
)
from core.events import EventBus


class UnlockedState:
    is_locked = False


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


def make_service(config=None, adapter=None):
    adapter = adapter or InMemoryClipboardAdapter()
    events = EventBus()
    if config is None:
        config = MemoryConfig({"clipboard_timeout": "never"})
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=config,
        state=UnlockedState(),
        register_exit_handler=False,
    )
    return service, adapter, events


def test_test_1_auto_clear_timing_is_close_to_configured_timeout(monkeypatch):
    monkeypatch.setattr(clipboard_service_module, "MIN_TIMEOUT_SECONDS", 1)
    service, adapter, events = make_service(MemoryConfig({"clipboard_timeout": 1}))
    cleared = threading.Event()
    clear_times = []

    events.subscribe(
        "ClipboardCleared",
        lambda event: (clear_times.append(time.monotonic()), cleared.set()),
    )

    start = time.monotonic()
    assert service.copy_password("timed-secret", source_entry_id="entry-test-1")

    assert cleared.wait(2.0)
    elapsed = clear_times[-1] - start

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert 0.9 <= elapsed <= 1.1


def test_test_2_default_adapter_selects_native_platform_before_fallback(monkeypatch):
    class FakeWindowsAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-windows"

    class FakeMacAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-macos"

    class FakeLinuxAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-linux"

    monkeypatch.setattr("core.clipboard.platform_adapter.WindowsClipboardAdapter", FakeWindowsAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.MacOSClipboardAdapter", FakeMacAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.LinuxClipboardAdapter", FakeLinuxAdapter)

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Windows")
    assert get_default_clipboard_adapter().backend_name == "fake-windows"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Darwin")
    assert get_default_clipboard_adapter().backend_name == "fake-macos"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Linux")
    assert get_default_clipboard_adapter().backend_name == "fake-linux"


def test_test_2_linux_adapter_supports_xclip_and_xsel_distros(monkeypatch):
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command == "xclip"),
    )
    xclip_adapter = LinuxClipboardAdapter()

    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command == "xsel"),
    )
    xsel_adapter = LinuxClipboardAdapter()

    assert xclip_adapter.backend == "xclip"
    assert xclip_adapter._copy_cmd == ["xclip", "-selection", "clipboard"]
    assert xsel_adapter.backend == "xsel"
    assert xsel_adapter._copy_cmd == ["xsel", "--clipboard", "--input"]
    assert xsel_adapter._paste_cmd == ["xsel", "--clipboard", "--output"]


def test_test_2_adapter_falls_back_to_pyperclip_then_memory(monkeypatch):
    class BrokenNativeAdapter(ClipboardAdapter):
        backend_name = "broken-native"

        def __init__(self):
            raise RuntimeError("native unavailable")

        def copy_to_clipboard(self, data: str) -> bool:
            return False

        def clear_clipboard(self) -> bool:
            return False

        def get_clipboard_content(self):
            return None

    class FakePyperclipAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Windows")
    monkeypatch.setattr("core.clipboard.platform_adapter.WindowsClipboardAdapter", BrokenNativeAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", FakePyperclipAdapter)

    assert get_default_clipboard_adapter().backend_name == "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", BrokenNativeAdapter)
    assert get_default_clipboard_adapter().backend_name == "in-memory"


def test_test_3_password_plaintext_is_not_kept_in_secure_buffers_and_is_wiped():
    secret = "memory-dump-target-secret"
    item = SecureClipboardItem(secret, "password", "entry-test-3")

    assert secret.encode("utf-8") not in bytes(item._data)
    assert secret.encode("utf-8") not in bytes(item._mask)
    assert item.reveal() == secret

    data_buffer = item._data
    mask_buffer = item._mask
    item.secure_wipe()

    assert all(byte == 0 for byte in data_buffer)
    assert all(byte == 0 for byte in mask_buffer)
    assert item._data == bytearray()
    assert item._mask == bytearray()


def test_test_4_rapid_concurrent_copy_operations_do_not_leak_previous_content():
    service, adapter, _ = make_service()
    secrets = [f"rapid-secret-{index:02d}" for index in range(30)]
    errors = []

    def copy_secret(secret):
        try:
            service.copy_password(secret, source_entry_id=secret)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=copy_secret, args=(secret,)) for secret in secrets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    status = service.get_clipboard_status()
    current_system_value = adapter.get_clipboard_content()
    current_secure_value = service.current_content.reveal()

    assert errors == []
    assert status.active is True
    assert current_system_value in secrets
    assert current_secure_value == current_system_value
    assert current_secure_value.encode("utf-8") not in bytes(service.current_content._data)


def test_test_5_process_exit_recovery_clears_sensitive_clipboard_data():
    service, adapter, events = make_service()
    cleared = []
    events.subscribe("ClipboardCleared", lambda event: cleared.append(event.data))

    assert service.copy_password("crash-recovery-secret", source_entry_id="entry-test-5")
    service._clear_on_exit()

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert cleared[-1]["reason"] == "process_exit"
