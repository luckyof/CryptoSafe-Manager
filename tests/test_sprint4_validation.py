import os
import ctypes
import subprocess
import sys
import threading
import time
import textwrap

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

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


def _scan_windows_process_memory(pid, needle):
    kernel32 = ctypes.windll.kernel32
    process_query_information = 0x0400
    process_vm_read = 0x0010
    mem_commit = 0x1000
    page_guard = 0x100
    page_noaccess = 0x01

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("PartitionId", ctypes.c_ushort),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    process = kernel32.OpenProcess(process_query_information | process_vm_read, False, pid)
    if not process:
        pytest.skip("Cannot open child process memory for TEST-3 scan")

    try:
        address = 0
        chunk_size = 1024 * 1024
        overlap_size = max(len(needle) - 1, 0)
        mbi = MEMORY_BASIC_INFORMATION()

        while kernel32.VirtualQueryEx(
            process,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        ):
            protect = mbi.Protect
            if mbi.State == mem_commit and not (protect & page_guard) and not (protect & page_noaccess):
                region_start = int(mbi.BaseAddress or 0)
                region_end = region_start + int(mbi.RegionSize)
                tail = b""
                cursor = region_start

                while cursor < region_end:
                    read_size = min(chunk_size, region_end - cursor)
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t()

                    if kernel32.ReadProcessMemory(
                        process,
                        ctypes.c_void_p(cursor),
                        buffer,
                        read_size,
                        ctypes.byref(bytes_read),
                    ):
                        chunk = tail + buffer.raw[: bytes_read.value]
                        if needle in chunk:
                            return True
                        tail = chunk[-overlap_size:] if overlap_size else b""

                    cursor += read_size

            next_address = int(mbi.BaseAddress or 0) + int(mbi.RegionSize)
            if next_address <= address:
                break
            address = next_address

        return False
    finally:
        kernel32.CloseHandle(process)


def _scan_linux_process_memory(pid, needle):
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    overlap_size = max(len(needle) - 1, 0)

    try:
        with open(maps_path, "r", encoding="utf-8") as maps_file, open(mem_path, "rb", buffering=0) as mem_file:
            for line in maps_file:
                parts = line.split()
                if len(parts) < 2 or "r" not in parts[1]:
                    continue

                start_raw, end_raw = parts[0].split("-", 1)
                start = int(start_raw, 16)
                end = int(end_raw, 16)
                cursor = start
                tail = b""

                while cursor < end:
                    read_size = min(1024 * 1024, end - cursor)
                    try:
                        mem_file.seek(cursor)
                        data = mem_file.read(read_size)
                    except OSError:
                        break

                    chunk = tail + data
                    if needle in chunk:
                        return True
                    tail = chunk[-overlap_size:] if overlap_size else b""
                    cursor += read_size
    except OSError:
        pytest.skip("Cannot read process memory for TEST-3 scan")

    return False


def _process_memory_contains(pid, needle):
    if sys.platform == "win32":
        return _scan_windows_process_memory(pid, needle)
    if sys.platform.startswith("linux"):
        return _scan_linux_process_memory(pid, needle)
    pytest.skip("TEST-3 process memory scan is implemented for Windows and Linux")


def test_auto_clear_timing(monkeypatch):
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


def test_native_adapter_priority(monkeypatch):
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


def test_linux_xclip_xsel(monkeypatch):
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


def test_adapter_fallback(monkeypatch):
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


def test_item_obfuscates_data():
    secret = "memory-dump-target-secret"
    item = SecureClipboardItem(secret, "password", "entry-test-3")

    assert secret.encode("utf-8") not in bytes(item._data)
    assert secret.encode("utf-8") not in bytes(item._mask)
    assert item.reveal() == secret


def test_memory_dump_no_plaintext():
    secret = "UNIQUE_SECRET_TEST_PASSWORD_12345_XYZ"
    child_code = textwrap.dedent(
        """
        import ctypes
        import gc
        import os
        import sys

        sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "src")))

        from core.clipboard.clipboard_service import ClipboardService
        from core.clipboard.platform_adapter import ClipboardAdapter
        from core.events import EventBus

        class UnlockedState:
            is_locked = False

        class MemoryConfig(dict):
            def set(self, key, value):
                self[key] = value

        class NonRetainingClipboardAdapter(ClipboardAdapter):
            backend_name = "test-non-retaining"

            def __init__(self):
                self.copy_calls = 0
                self.last_payload_length = None
                self.retained_plaintext = None

            def copy_to_clipboard(self, data):
                self.copy_calls += 1
                self.last_payload_length = len(data)
                return True

            def clear_clipboard(self):
                return True

            def get_clipboard_content(self):
                return ""

        def zero_compact_ascii_string(value):
            if not value.isascii():
                return
            data_offset = sys.getsizeof("") - 1
            ctypes.memset(id(value) + data_offset, 0, len(value))

        def zero_bytearray(value):
            if value:
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(value)), 0, len(value))

        adapter = NonRetainingClipboardAdapter()
        service = ClipboardService(
            platform_adapter=adapter,
            event_system=EventBus(),
            config=MemoryConfig({"clipboard_timeout": "never"}),
            state=UnlockedState(),
            register_exit_handler=False,
        )

        copied_value = "".join(chr(int(codepoint)) for codepoint in sys.stdin.readline().split(","))
        target_bytes = bytearray(copied_value, "utf-8")
        service.copy_password(copied_value, source_entry_id="entry-test-3")

        item = service.current_content
        mask_valid = (
            item is not None
            and len(item._mask) > 0
            and len(item._data) == len(target_bytes)
            and bytes(target_bytes) not in bytes(item._data)
            and bytes(target_bytes) not in bytes(item._mask)
            and not all(byte == 0 for byte in item._mask)
            and not all(byte == 0 for byte in item._data)
            and adapter.copy_calls == 1
            and adapter.last_payload_length == len(target_bytes)
            and adapter.retained_plaintext is None
        )

        zero_bytearray(target_bytes)
        zero_compact_ascii_string(copied_value)
        del target_bytes
        del copied_value
        gc.collect()

        print(f"{os.getpid()}:{int(mask_valid)}", flush=True)
        command = sys.stdin.readline().strip()
        if command == "clear":
            service.clear_clipboard("manual")
            gc.collect()
            print("cleared", flush=True)
        sys.stdin.readline()
        """
    )

    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        process.stdin.write(",".join(str(ord(char)) for char in secret) + "\n")
        process.stdin.flush()

        child_status_line = process.stdout.readline().strip()
        if not child_status_line:
            pytest.fail(f"TEST-3 child process failed: {process.stderr.read()}")

        child_pid_raw, mask_valid_raw = child_status_line.split(":", 1)
        child_pid = int(child_pid_raw)
        target_bytes = secret.encode("utf-8")

        plaintext_found = _process_memory_contains(child_pid, target_bytes)
        process.stdin.write("clear\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == "cleared"
        residue_found = _process_memory_contains(child_pid, target_bytes)

        assert plaintext_found is False, "Plaintext password found in process memory during copy"
        assert residue_found is False, "Plaintext password residue found after clipboard clear"
        assert mask_valid_raw == "1", "SecureClipboardItem mask or obfuscated data is invalid"
    finally:
        if process.stdin:
            try:
                process.stdin.write("\n")
                process.stdin.flush()
            except BrokenPipeError:
                pass
        process.wait(timeout=5)


def test_wipe_zeroes_buffers():
    secret = "memory-dump-target-secret"
    item = SecureClipboardItem(secret, "password", "entry-test-3")
    data_buffer = item._data
    mask_buffer = item._mask

    item.secure_wipe()

    assert all(byte == 0 for byte in data_buffer)
    assert all(byte == 0 for byte in mask_buffer)
    assert item._data == bytearray()
    assert item._mask == bytearray()


def test_service_obfuscates_password():
    secret = "service-memory-target-secret"
    service, _, _ = make_service()

    assert service.copy_password(secret, source_entry_id="entry-test-3")

    current_item = service.current_content
    assert current_item is not None
    assert secret.encode("utf-8") not in bytes(current_item._data)
    assert secret.encode("utf-8") not in bytes(current_item._mask)
    assert secret not in current_item.preview()

    service.clear_clipboard("manual")
    assert service.current_content is None


def test_concurrent_copy_no_leak():
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


def test_exit_clears_clipboard():
    service, adapter, events = make_service()
    cleared = []
    events.subscribe("ClipboardCleared", lambda event: cleared.append(event.data))

    assert service.copy_password("crash-recovery-secret", source_entry_id="entry-test-5")
    service._clear_on_exit()

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert cleared[-1]["reason"] == "process_exit"
