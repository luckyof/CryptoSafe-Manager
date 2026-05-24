import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import logging
import subprocess
import webbrowser
from datetime import datetime, timezone

from .widgets.secure_table import SecureTable
from .widgets.audit_log_viewer import AuditLogViewer
from .widgets.search_widget import SearchWidget
from .settings_dialog import SettingsDialog
from .setup_wizard import SetupWizard
from .dialogs.login_dialog import LoginDialog
from .dialogs.change_password_dialog import ChangePasswordDialog
from .dialogs.entry_dialog import EntryDialog
from .dialogs.export_dialog import ExportDialog
from .dialogs.import_dialog import ImportDialog
from .dialogs.sharing_dialog import SharingDialog
from .tray_manager import TrayManager
from .ux import COMMON_SHORTCUTS, ToolTip, friendly_error_message, security_state_color

from core.config import ConfigManager
from core.state_manager import state_manager
from core.events import event_bus
from core.audit import AuditManager
from database.db import DatabaseHelper
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from core.vault.encryption_service import AES256GCMService
from core.vault.password_generator import PasswordStrength
from core.clipboard import ClipboardMonitor, ClipboardService
from core.security import ActivityMonitor, PanicMode, PlatformSecurityManager

logger = logging.getLogger("MainWindow")


class MainWindow(tk.Tk):
    def __init__(self, config: ConfigManager, defer_startup: bool = False):
        super().__init__()
        self.title("CryptoSafe Manager - Sprint 3")
        self.geometry("900x650")

        self.app_config = config
        self.db = None
        self.audit = None
        self.key_manager = None
        self.encryption_service = None
        self.entry_manager = None
        self.clipboard_service = ClipboardService(config=self.app_config, state=state_manager)
        self.clipboard_monitor = None
        self.activity_monitor = ActivityMonitor(
            self._schedule_auto_lock,
            config=self.app_config.get_security_settings(),
            is_locked_callback=lambda: state_manager.is_locked,
        )
        self.panic_mode = PanicMode(config=self.app_config.get_security_settings())
        self.panic_mode.register_handler(self._schedule_panic_response)
        self.platform_security = PlatformSecurityManager(config=self.app_config.get_security_settings())
        self.platform_security.detect_capabilities()
        self.tray_manager = TrayManager(
            self,
            self.app_config,
            lock_callback=lambda: self.lock_application("tray"),
            unlock_callback=self.show_window_from_tray,
            show_callback=self.show_window_from_tray,
            quick_search_callback=self.quick_search_from_tray,
            clear_clipboard_callback=lambda: self.clipboard_service.clear_clipboard("tray"),
            panic_callback=lambda: self.activate_panic_mode("tray"),
            settings_callback=self.show_settings,
            exit_callback=self.exit_application,
        )
        self._clipboard_warning_shown = False
        self._lock_in_progress = False
        self._hidden_to_tray = False
        self._loading_entries = False
        self._last_entries_snapshot = []

        self.create_toolbar()
        self.create_search_area()
        self.create_main_area()
        self.create_menu()
        self.create_status_bar()
        self.setup_clipboard_ui()
        self.setup_tray()

        if not defer_startup:
            self.after(100, self.startup_sequence)

        self.auto_lock_check_interval = 60000
        self.after(self.auto_lock_check_interval, self.check_inactivity)

        self.bind("<Unmap>", self.on_minimize_event)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def startup_sequence(self):
        db_path = self.app_config.db_path
        if not os.path.exists(db_path):
            self.run_setup_wizard()
        else:
            self.login_and_load()

    def run_setup_wizard(self):
        wizard = SetupWizard(self, self.app_config)
        self.wait_window(wizard)

        if wizard.completed:
            if self.initialize_new_vault(wizard.db_path, wizard.password):
                self.on_login_success()
                messagebox.showinfo("Успех", "Хранилище успешно создано!", parent=self)
            else:
                messagebox.showerror("Ошибка", "Не удалось создать хранилище.", parent=self)
                self.quit()
        else:
            self.quit()

    def initialize_new_vault(self, db_path, password):
        try:
            self.db = DatabaseHelper(db_path)
            self.app_config.db_path = db_path
            self.app_config.set("db_path", db_path)
            self.app_config.attach_database(self.db)

            self.key_manager = KeyManager(self.db, self.app_config.get_security_settings())
            if not self.key_manager.setup_new_vault(password):
                return False
            self.app_config.attach_key_manager(self.key_manager)

            self.encryption_service = AES256GCMService()
            self.encryption_service.set_key_manager(self.key_manager)
            self.entry_manager = EntryManager(self.db, self.key_manager)
            return True
        except Exception as e:
            logger.error(f"Init error: {e}")
            return False

    def login_and_load(self):
        try:
            self.db = DatabaseHelper(self.app_config.db_path)
            self.app_config.attach_database(self.db)
            self.key_manager = KeyManager(self.db, self.app_config.get_security_settings())

            login = LoginDialog(self, self.key_manager, secure_desktop=self.platform_security.should_use_secure_desktop())
            if login.success:
                self.app_config.attach_key_manager(self.key_manager)
                self.encryption_service = AES256GCMService()
                self.encryption_service.set_key_manager(self.key_manager)
                self.entry_manager = EntryManager(self.db, self.key_manager)
                state_manager.login("default_user")
                self.on_login_success()
            else:
                self.quit()
        except Exception as e:
            logger.error(f"Load error: {e}")
            messagebox.showerror("Ошибка", f"Не удалось открыть БД:\n{e}")
            self.quit()

    def on_login_success(self):
        self.audit = AuditManager(self.db, key_manager=self.key_manager)
        self.update_security_status(False)
        self.status_label.config(text="Статус: Разблокировано")
        self.tray_manager.update_security_state(False)
        event_bus.publish("UserLoggedIn", data={"user": "default_user"})
        self.start_clipboard_monitor()
        self.start_activity_monitor()
        self.load_entries()

    def load_entries(self, search_query: str = "", filters=None):
        try:
            if search_query:
                data = self.entry_manager.search_entries(search_query)
            else:
                data = self.entry_manager.get_all_entries(include_decrypted_password=False)

            if filters:
                data = self._apply_demo_filters(data, filters)

            self._last_entries_snapshot = list(data)
            self._load_entries_into_table(data)
            self._update_search_categories(data)
            self.update_status(f"Записей: {len(data)}")
        except Exception as e:
            logger.exception("Load entries error")
            self.show_friendly_error(e, "load entries")
            return

    def on_minimize_event(self, event):
        self.record_focus_change(False)
        if event.widget is self and self.app_config.get_bool("minimize_to_tray", True):
            self.hide_to_tray()
        elif event.widget is self and self.key_manager and not state_manager.is_locked:
            self._schedule_auto_lock("minimize")

    def check_inactivity(self):
        if self.key_manager and not state_manager.is_locked:
            if self.activity_monitor.should_lock():
                self._schedule_auto_lock("fallback_timer")
            else:
                self.key_manager.touch()

        self.after(self.auto_lock_check_interval, self.check_inactivity)

    def lock_application(self, reason: str = "manual"):
        if self._lock_in_progress or state_manager.is_locked:
            return
        self._lock_in_progress = True
        logger.info("Locking application...")
        self.stop_activity_monitor()
        self.clipboard_service.clear_clipboard(reason)
        if self.key_manager:
            self.key_manager.lock()
        state_manager.logout()
        self.tray_manager.update_security_state(True)
        event_bus.publish("VaultLocked", data={"reason": reason})
        self.update_security_status(True)

        self.status_label.config(text="Статус: ЗАБЛОКИРОВАНО")
        self.table.load_data([])
        self._show_lock_overlay()

        login = LoginDialog(self, self.key_manager, secure_desktop=self.platform_security.should_use_secure_desktop())
        if login.success:
            self._hide_lock_overlay()
            state_manager.login("default_user")
            event_bus.publish("VaultUnlocked", data={"reason": "reauthentication"})
            self.on_login_success()
        else:
            self.on_close()
        self._lock_in_progress = False

    def on_close(self):
        if self.app_config.get_bool("minimize_to_tray", True) and self.tray_manager.state.running:
            self.hide_to_tray()
            return
        self.exit_application()

    def exit_application(self):
        logger.info("Closing application...")
        self.stop_activity_monitor()
        if self.tray_manager:
            self.tray_manager.stop()
        if self.clipboard_monitor:
            self.clipboard_monitor.stop()
        self.clipboard_service.shutdown()
        if self.audit and hasattr(self.audit, "shutdown"):
            self.audit.shutdown()
        if self.key_manager:
            self.key_manager.lock()
        self.destroy()

    def create_toolbar(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="➕ Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="✏️ Редактировать", command=self.edit_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🗑 Удалить", command=self.delete_selected).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        self.password_toggle_btn = ttk.Button(
            toolbar,
            text="Показать/скрыть выбранные",
            command=self.toggle_password_visibility,
        )
        self.password_toggle_btn.pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        ttk.Button(toolbar, text="Экспорт", command=self.show_export_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Импорт", command=self.show_import_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Поделиться", command=self.share_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Копировать логин", command=self.copy_username).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📋 Копировать пароль", command=self.copy_password).pack(side=tk.LEFT, padx=2)

        self._apply_toolbar_accessibility(toolbar)

    def _apply_toolbar_accessibility(self, toolbar):
        tooltips = [
            "Add entry (Ctrl+N)",
            "Edit selected entry (Ctrl+E)",
            "Move selected entries to trash (Delete)",
            "Show or hide selected passwords (Ctrl+Shift+P)",
            "Export vault data",
            "Import vault data",
            "Share selected entry securely",
            "Copy selected username (Ctrl+U)",
            "Copy selected password (Ctrl+C)",
        ]
        buttons = [child for child in toolbar.winfo_children() if isinstance(child, ttk.Button)]
        for button, tooltip in zip(buttons, tooltips):
            ToolTip(button, tooltip)

    def create_search_area(self):
        self.search_widget = SearchWidget(self, on_search=self.on_search)
        self.search_widget.pack(fill=tk.X, padx=10, pady=(0, 5))

    def on_search(self, query):
        if isinstance(query, dict):
            self.load_entries(search_query=query.get("query", ""), filters=query)
        else:
            self.load_entries(search_query=query)

    def create_main_area(self):
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.bind_all("<Button-1>", lambda e: self.record_user_activity("mouse"))
        self.bind_all("<Motion>", lambda e: self.record_user_activity("mouse"))
        self.bind_all("<Key>", lambda e: self.record_user_activity("keyboard"))
        self.bind_all("<FocusIn>", lambda e: self.record_focus_change(True))
        self.bind_all("<FocusOut>", lambda e: self.record_focus_change(False))
        self.bind_all("<Control-Shift-P>", lambda e: self.toggle_password_visibility())
        self.bind_all(self.panic_mode.hotkey_sequence(), lambda e: self.activate_panic_mode("hotkey"))
        self._bind_common_shortcuts()
        self.bind("<Configure>", self._on_window_configure)

        self.table.set_context_callback(self._on_table_action)
        self.table.set_password_reveal_callback(self._load_password_for_table)

    def _bind_common_shortcuts(self):
        bindings = {
            "add_entry": lambda event: self.add_entry(),
            "edit_entry": lambda event: self.edit_selected(),
            "delete_entry": lambda event: self.delete_selected(),
            "copy_username": lambda event: self.copy_username(),
            "copy_password": lambda event: self.copy_password(),
            "search": lambda event: self.focus_search(),
            "lock": lambda event: self.lock_application("shortcut"),
            "settings": lambda event: self.show_settings(),
        }
        for action, callback in bindings.items():
            self.bind_all(COMMON_SHORTCUTS[action], callback)

    def focus_search(self):
        if hasattr(self.search_widget, "focus_search"):
            self.search_widget.focus_search()

    def setup_clipboard_ui(self):
        self.clipboard_service.add_observer(lambda status: self.after(0, self._on_clipboard_status, status))
        event_bus.subscribe("ClipboardCopied", lambda event: self.after(0, self._on_clipboard_copied, event.data))
        event_bus.subscribe("ClipboardCleared", lambda event: self.after(0, self._on_clipboard_cleared, event.data))
        event_bus.subscribe("ClipboardWarning", lambda event: self.after(0, self._on_clipboard_warning, event.data))
        event_bus.subscribe("ClipboardCopyBlockChanged", lambda event: self.after(0, self._on_clipboard_block_changed, event.data))
        event_bus.subscribe("ClipboardError", lambda event: self.after(0, self._on_clipboard_error, event.data))
        self.after(1000, self.refresh_clipboard_status)

    def setup_tray(self):
        if not self.app_config.get_bool("tray_enabled", True):
            return
        self.tray_manager.start()
        self.tray_manager.update_security_state(state_manager.is_locked)
        if self.app_config.get_bool("start_minimized_to_tray", False):
            self.after(250, self.hide_to_tray)

    def apply_tray_setting(self):
        if self.app_config.get_bool("tray_enabled", True):
            self.tray_manager.start()
            self.tray_manager.update_security_state(state_manager.is_locked)
        else:
            self.tray_manager.stop()

    def apply_panic_setting(self):
        self.panic_mode.config = self.app_config.get_security_settings()

    def apply_platform_security_setting(self):
        self.platform_security.config = self.app_config.get_security_settings()
        self.platform_security.detect_capabilities()

    def hide_to_tray(self):
        if self._hidden_to_tray or not self.tray_manager.state.running:
            return
        self._hidden_to_tray = True
        self.tray_manager.hide_window()
        self.tray_manager.notify("CryptoSafe Manager", "Running in the background.")

    def show_window_from_tray(self):
        if self.panic_mode.activated:
            self.recover_from_panic("tray")
            return
        self._hidden_to_tray = False
        self.tray_manager.show_window()

    def quick_search_from_tray(self):
        self.show_window_from_tray()
        query = simpledialog.askstring("Quick search", "Search vault:", parent=self)
        if query is not None:
            self.load_entries(search_query=query)

    def activate_panic_mode(self, method: str = "manual"):
        self.panic_mode.activate(method)

    def recover_from_panic(self, method: str = "manual"):
        self.panic_mode.recover(method)
        self._hidden_to_tray = False
        self.tray_manager.show_window()
        if self.key_manager and state_manager.is_locked:
            self.lock_application("panic_recovery")

    def _schedule_panic_response(self, method: str):
        try:
            self.after(0, lambda: self._perform_panic_response(method))
        except Exception:
            self._perform_panic_response(method)

    def _perform_panic_response(self, method: str):
        self.clipboard_service.handle_panic_mode("panic_mode")
        self.stop_activity_monitor()
        if self.key_manager:
            self.key_manager.lock()
        state_manager.logout()
        self._destroy_child_windows()
        self.table.load_data([])
        self.tray_manager.update_security_state(True)
        event_bus.publish("VaultLocked", data={"reason": "panic_mode"})
        self._execute_panic_stealth_actions(method)
        if self.panic_mode.close_application:
            self.exit_application()
        else:
            self.withdraw()

    def _destroy_child_windows(self):
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass
        self._hide_lock_overlay()

    def _execute_panic_stealth_actions(self, method: str):
        if not self.panic_mode.stealth_mode:
            return
        if self.app_config.get_bool("panic_show_fake_error", False):
            message = self.app_config.get(
                "panic_fake_error_message",
                "The application has encountered an unexpected error.",
            )
            self.after(50, lambda: messagebox.showerror("Application Error", message))
        command = str(self.app_config.get("panic_decoy_command", "") or "").strip()
        if self.app_config.get_bool("panic_launch_decoy", False) and command:
            try:
                subprocess.Popen(command, shell=True)
            except Exception as exc:
                logger.warning("Failed to launch panic decoy: %s", exc)
        redirect_url = str(self.app_config.get("panic_redirect_url", "") or "").strip()
        if redirect_url:
            try:
                webbrowser.open(redirect_url)
            except Exception as exc:
                logger.warning("Failed to open panic redirect URL: %s", exc)

    def _on_window_configure(self, event):
        if event.widget is not self or state_manager.is_locked:
            return
        if self.panic_mode.record_window_position(event.x, event.y):
            self.activate_panic_mode("mouse_gesture")

    def start_clipboard_monitor(self):
        if self.clipboard_monitor or not self.app_config.get("clipboard_monitor_enabled", True):
            return
        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service)
        self.clipboard_monitor.start()

    def apply_clipboard_monitor_setting(self):
        enabled = self.app_config.get_bool("clipboard_monitor_enabled", True)
        if enabled:
            self.start_clipboard_monitor()
        elif self.clipboard_monitor:
            self.clipboard_monitor.stop()
            self.clipboard_monitor = None

    def start_activity_monitor(self):
        self.activity_monitor.update_config(self.app_config.get_security_settings())
        self.activity_monitor.start_monitoring()

    def stop_activity_monitor(self):
        self.activity_monitor.stop_monitoring()

    def apply_activity_monitor_setting(self):
        self.activity_monitor.update_config(self.app_config.get_security_settings())
        if not state_manager.is_locked:
            self.start_activity_monitor()

    def record_user_activity(self, source: str = "application"):
        state_manager.update_activity()
        if source == "keyboard":
            self.activity_monitor.record_keyboard_activity()
        elif source == "mouse":
            self.activity_monitor.record_mouse_activity()
        else:
            self.activity_monitor.record_activity(source)

    def record_focus_change(self, focused: bool):
        self.activity_monitor.record_focus_change(focused)

    def _schedule_auto_lock(self, reason: str = "inactivity"):
        try:
            self.after(0, lambda: self.lock_application(reason))
        except Exception as exc:
            logger.error("Failed to schedule auto-lock: %s", exc)

    def _show_lock_overlay(self):
        if getattr(self, "_lock_overlay", None):
            return
        overlay = tk.Toplevel(self)
        overlay.title("CryptoSafe Locked")
        overlay.transient(self)
        overlay.resizable(False, False)
        overlay.protocol("WM_DELETE_WINDOW", lambda: None)
        frame = ttk.Frame(overlay, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Vault locked").pack()
        ttk.Label(frame, text="Master password is required to continue.").pack(pady=(6, 0))
        overlay.update_idletasks()
        x = self.winfo_rootx() + max(0, (self.winfo_width() - overlay.winfo_width()) // 2)
        y = self.winfo_rooty() + max(0, (self.winfo_height() - overlay.winfo_height()) // 2)
        overlay.geometry(f"+{x}+{y}")
        self._lock_overlay = overlay

    def _hide_lock_overlay(self):
        overlay = getattr(self, "_lock_overlay", None)
        if overlay:
            try:
                overlay.destroy()
            except Exception:
                pass
        self._lock_overlay = None

    def _apply_demo_filters(self, entries, filters):
        """Применить дополнительные GUI-фильтры к уже найденным записям."""
        category = (filters.get("category") or "").strip()
        tag = (filters.get("tag") or "").strip().lower()
        start_date = self._parse_iso_datetime(filters.get("start_date"))
        end_date = self._parse_iso_datetime(filters.get("end_date"))
        min_strength = filters.get("min_strength")

        results = []
        for entry in entries:
            if category and entry.get("category", "") != category:
                continue

            if tag:
                entry_tags = [str(item).lower() for item in entry.get("tags", [])]
                if tag not in entry_tags:
                    continue

            if start_date or end_date:
                entry_dt = self._parse_iso_datetime(entry.get("updated_at"))
                if entry_dt is None:
                    continue
                if start_date and entry_dt < start_date:
                    continue
                if end_date and entry_dt > end_date:
                    continue

            if min_strength is not None:
                score = PasswordStrength.calculate(entry.get("password", ""))
                if score < min_strength:
                    continue

            results.append(entry)

        return results

    def _update_search_categories(self, entries):
        categories = sorted({
            entry.get("category", "").strip()
            for entry in entries
            if entry.get("category", "").strip()
        })
        self.search_widget.set_categories(categories)

    @staticmethod
    def _parse_iso_datetime(value):
        """Парсинг даты для демо-фильтрации."""
        if not value:
            return None

        text = str(value).strip()
        if not text:
            return None

        if len(text) == 10:
            text = f"{text}T00:00:00+00:00"
        elif len(text) == 16 and "T" in text:
            text = f"{text}:00+00:00"
        elif len(text) == 19 and "T" in text:
            text = f"{text}+00:00"

        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def create_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Импорт...", command=self.show_import_dialog)
        file_menu.add_command(label="Экспорт...", command=self.show_export_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Заблокировать", command=self.lock_application)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.exit_application)
        menubar.add_cascade(label="Файл", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить запись", command=self.add_entry)
        edit_menu.add_command(label="Редактировать", command=self.edit_selected)
        edit_menu.add_command(label="Удалить", command=self.delete_selected)
        edit_menu.add_separator()
        edit_menu.add_command(label="Сменить мастер-пароль", command=self.show_change_password)
        menubar.add_cascade(label="Правка", menu=edit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи аудита", command=self.show_audit_window)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        menubar.add_cascade(label="Вид", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.config(menu=menubar)

    def create_status_bar(self):
        style = ttk.Style(self)
        style.configure("SecurityLocked.TLabel", foreground=security_state_color("locked"))
        style.configure("SecurityUnlocked.TLabel", foreground=security_state_color("unlocked"))
        style.configure("SecurityWarning.TLabel", foreground=security_state_color("warning"))
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(self.status_bar, text="Статус: Заблокировано", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.clipboard_label = ttk.Label(self.status_bar, text="Буфер: --", relief=tk.SUNKEN)
        self.clipboard_label.pack(side=tk.RIGHT, fill=tk.X)
        self.clipboard_label.bind("<Button-1>", lambda event: self.show_clipboard_preview())
        self.status_label.configure(style="SecurityLocked.TLabel")
        self.progress = ttk.Progressbar(self.status_bar, mode="indeterminate", length=96)

    def update_security_status(self, locked: bool):
        if not hasattr(self, "status_label"):
            return
        if locked:
            self.status_label.configure(text="Status: locked", style="SecurityLocked.TLabel")
        else:
            self.status_label.configure(text="Status: unlocked", style="SecurityUnlocked.TLabel")

    def show_progress(self, message: str):
        self._loading_entries = True
        self.update_status(message)
        if hasattr(self, "progress") and not self.progress.winfo_ismapped():
            self.progress.pack(side=tk.LEFT, padx=(6, 0))
            self.progress.start(12)

    def hide_progress(self):
        self._loading_entries = False
        if hasattr(self, "progress") and self.progress.winfo_ismapped():
            self.progress.stop()
            self.progress.pack_forget()

    def _load_entries_into_table(self, data):
        if len(data) < 250:
            self.table.load_data(data)
            self.hide_progress()
            return

        self.show_progress(f"Loading {len(data)} entries...")
        self.table.load_data_incremental(
            data,
            batch_size=100,
            schedule=self.after,
            on_done=lambda total: (self.hide_progress(), self.update_status(f"Entries: {total}")),
        )

    def show_friendly_error(self, error: Exception, context: str):
        message = friendly_error_message(error, context)
        self.update_status(message.title)
        messagebox.showerror(message.title, message.format(), parent=self)

    def add_entry(self):
        EntryDialog(self, on_save=self._on_entry_save)

    def edit_selected(self):
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись для редактирования")
            return

        entry = selected[0]
        EntryDialog(self, entry_data=entry, on_save=lambda data: self._on_entry_save(data, entry.get("id")))

    def delete_selected(self):
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите записи для удаления")
            return

        count = len(selected)
        if messagebox.askyesno("Подтверждение", f"Удалить {count} записей в корзину?"):
            for entry in selected:
                try:
                    self.entry_manager.delete_entry(entry["id"], soft_delete=True)
                except Exception as e:
                    logger.error(f"Delete error for {entry.get('id')}: {e}")

            self.load_entries()
            messagebox.showinfo("Успех", f"Удалено {count} записей")

    def copy_password(self):
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись")
            return

        self.copy_entry_field(selected[0], "password")

    def copy_username(self):
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись")
            return

        self.copy_entry_field(selected[0], "username")

    def copy_entry_field(self, entry: dict, field_name: str):
        entry_id = entry.get("id")
        if not entry_id:
            self.show_clipboard_toast(f"Нет данных для копирования: {field_name}", warning=True)
            return

        try:
            self.clipboard_service.copy_entry_field(self.entry_manager, entry_id, field_name)
        except Exception as e:
            logger.error(f"Clipboard copy error: {e}")
            messagebox.showerror("Буфер обмена", f"Не удалось скопировать данные:\n{e}", parent=self)

    def _load_password_for_table(self, entry_id: str) -> str:
        if not self.entry_manager or not entry_id:
            return ""
        try:
            entry = self.entry_manager.get_entry(entry_id)
            return entry.get("password", "") if entry else ""
        except Exception as e:
            logger.error(f"Password reveal error for {entry_id}: {e}")
            messagebox.showerror("Пароль", f"Не удалось показать пароль:\n{e}", parent=self)
            return ""

    def copy_entry_all(self, entry: dict):
        entry_id = entry.get("id")
        if not entry_id:
            self.show_clipboard_toast("РќРµС‚ РґР°РЅРЅС‹С… РґР»СЏ РєРѕРїРёСЂРѕРІР°РЅРёСЏ", warning=True)
            return

        try:
            self.clipboard_service.copy_entry_summary(self.entry_manager, entry_id)
        except Exception as e:
            logger.error(f"Clipboard copy all error: {e}")
            messagebox.showerror("Р‘СѓС„РµСЂ РѕР±РјРµРЅР°", f"РќРµ СѓРґР°Р»РѕСЃСЊ СЃРєРѕРїРёСЂРѕРІР°С‚СЊ Р·Р°РїРёСЃСЊ:\n{e}", parent=self)

    def _on_entry_save(self, data: dict, entry_id: str = None):
        try:
            if entry_id:
                self.entry_manager.update_entry(entry_id, data)
                messagebox.showinfo("Успех", "Запись обновлена")
            else:
                self.entry_manager.create_entry(data)
                messagebox.showinfo("Успех", "Запись создана")

            self.load_entries()
        except Exception as e:
            logger.error(f"Save error: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить запись:\n{e}")

    def _on_table_action(self, action: str, entry: dict):
        if action == "open":
            messagebox.showinfo("Запись", f"Открыть: {entry.get('title', '')}")
        elif action == "edit":
            EntryDialog(self, entry_data=entry, on_save=lambda data: self._on_entry_save(data, entry.get("id")))
        elif action == "copy_password":
            self.copy_entry_field(entry, "password")
        elif action == "copy_username":
            self.copy_entry_field(entry, "username")
        elif action == "copy_all":
            self.copy_entry_all(entry)
        elif action == "share":
            self.show_sharing_dialog(entry.get("id"))
        elif action == "delete":
            if messagebox.askyesno("Подтверждение", f"Удалить '{entry.get('title')}'?"):
                self.entry_manager.delete_entry(entry["id"], soft_delete=True)
                self.load_entries()
        elif action == "permanent_delete":
            if messagebox.askyesno("Подтверждение", f"Удалить '{entry.get('title')}' НАВСЕГДА?"):
                self.entry_manager.delete_entry(entry["id"], soft_delete=False)
                self.load_entries()

    def show_change_password(self):
        ChangePasswordDialog(self, self.key_manager, self.entry_manager, self.encryption_service)

    def show_export_dialog(self):
        if not self.entry_manager:
            messagebox.showinfo("Экспорт", "Сначала разблокируйте хранилище.", parent=self)
            return
        ExportDialog(self, self.entry_manager, selected_entry_ids=self.table.get_selected_ids())

    def show_import_dialog(self):
        if not self.entry_manager:
            messagebox.showinfo("Импорт", "Сначала разблокируйте хранилище.", parent=self)
            return
        ImportDialog(self, self.entry_manager, on_import_complete=self.load_entries)

    def share_selected(self):
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Обмен", "Выберите запись, которой нужно поделиться.", parent=self)
            return
        self.show_sharing_dialog(selected[0].get("id"))

    def show_sharing_dialog(self, entry_id: str):
        if not entry_id:
            messagebox.showinfo("Обмен", "Не удалось определить выбранную запись.", parent=self)
            return
        SharingDialog(self, self.entry_manager, entry_id)

    def show_settings(self):
        SettingsDialog(self)

    def show_audit_window(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("1100x720")
        viewer = AuditLogViewer(
            win,
            db=self.db,
            audit_manager=self.audit,
            key_manager=self.key_manager,
            on_entry_select=self.highlight_entry_from_audit,
        )
        viewer.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def highlight_entry_from_audit(self, entry_id: str):
        if not entry_id:
            return
        if entry_id not in self.table.get_children():
            self.load_entries()
        if entry_id in self.table.get_children():
            self.table.selection_set(entry_id)
            self.table.focus(entry_id)
            self.table.see(entry_id)
            self.update_status(f"Аудит: выделена запись {entry_id}")
        else:
            messagebox.showinfo("Журнал аудита", f"Запись {entry_id} не найдена в текущем хранилище.", parent=self)

    def show_about(self):
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager v0.3\n"
            "Sprint 3: AES-256-GCM Encryption & Full CRUD\n\n"
            "• Per-entry AES-256-GCM шифрование\n"
            "• Полный CRUD с транзакциями\n"
            "• Безопасный генератор паролей\n"
            "• Поиск и фильтрация\n"
            "• Контекстное меню и маскирование",
        )

    def toggle_password_visibility(self):
        """GUI-3: Переключить видимость у выбранных записей."""
        self.table.toggle_password_visibility()

    def update_status(self, message: str):
        self.status_label.config(text=message)

    def refresh_clipboard_status(self):
        self._on_clipboard_status(self.clipboard_service.get_clipboard_status())
        self.after(1000, self.refresh_clipboard_status)

    def _on_clipboard_status(self, status):
        self.tray_manager.update_clipboard_status(status)
        if status.active:
            remaining = "never" if status.remaining_seconds <= 0 else f"{int(status.remaining_seconds)}s"
            self.clipboard_label.config(
                text=f"Буфер: {status.data_type} {status.preview} ({remaining})"
            )
            self.table.set_clipboard_entry(status.source_entry_id)
            if 0 < status.remaining_seconds <= 5 and not self._clipboard_warning_shown:
                self._clipboard_warning_shown = True
                self.show_clipboard_toast("Буфер обмена скоро будет очищен", warning=True)
        else:
            self._clipboard_warning_shown = False
            self.clipboard_label.config(text="Буфер: --")
            self.table.set_clipboard_entry(None)

    def _on_clipboard_copied(self, data):
        if not self.app_config.get_bool("clipboard_notify_on_copy", True):
            return
        self.show_clipboard_toast(f"Скопировано: {data.get('data_type', 'text')}")

    def _on_clipboard_cleared(self, data):
        if not self.app_config.get_bool("clipboard_notify_on_clear", True):
            return
        reason = data.get("reason", "unknown") if data else "unknown"
        self.show_clipboard_toast(f"Буфер очищен ({reason})")

    def _on_clipboard_warning(self, data):
        if not self.app_config.get_bool("clipboard_notify_on_warning", True):
            return
        message = data.get("message", "Подозрительная активность буфера обмена") if data else "Подозрительная активность буфера обмена"
        self.show_clipboard_toast(message, warning=True)

    def _on_clipboard_block_changed(self, data):
        if data and data.get("blocked"):
            self.show_clipboard_toast("Копирование заблокировано из-за подозрительной активности", warning=True)
        else:
            self.show_clipboard_toast("Копирование снова разрешено")

    def _on_clipboard_error(self, data):
        reason = data.get("reason", "unknown") if data else "unknown"
        message = data.get("message") if data else ""
        if data and data.get("manual_clear_required"):
            message = message or "Clipboard could not be cleared automatically. Clear it manually."
        self.show_clipboard_toast(message or f"Clipboard error: {reason}", warning=True)

    def show_clipboard_toast(self, message: str, warning: bool = False):
        self.clipboard_label.config(text=message)
        toast = tk.Toplevel(self)
        toast.title("Буфер обмена")
        toast.transient(self)
        toast.resizable(False, False)
        frame = ttk.Frame(toast, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=message, foreground="#8a5a00" if warning else "#1f6f43").pack()
        toast.update_idletasks()
        x = self.winfo_rootx() + max(0, self.winfo_width() - toast.winfo_width() - 24)
        y = self.winfo_rooty() + max(0, self.winfo_height() - toast.winfo_height() - 64)
        toast.geometry(f"+{x}+{y}")
        toast.after(2500, toast.destroy)

    def show_clipboard_preview(self):
        status = self.clipboard_service.get_clipboard_status()
        if not status.active:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.", parent=self)
            return

        win = tk.Toplevel(self)
        win.title("Буфер обмена")
        win.transient(self)
        win.resizable(False, False)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=f"Тип: {status.data_type}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Источник: {status.source_entry_id or '--'}").pack(anchor=tk.W, pady=(4, 0))
        preview_var = tk.StringVar(value=f"Предпросмотр: {status.preview}")
        ttk.Label(frame, textvariable=preview_var).pack(anchor=tk.W, pady=(4, 10))

        def reveal():
            try:
                value = self.clipboard_service.reveal_current_content(self._authenticate_for_clipboard_reveal)
                if value is not None:
                    preview_var.set(f"Полное значение: {value}")
            except Exception as e:
                messagebox.showerror("Буфер обмена", str(e), parent=win)

        buttons = ttk.Frame(frame)
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Показать", command=reveal).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Закрыть", command=win.destroy).pack(side=tk.RIGHT)

    def _authenticate_for_clipboard_reveal(self) -> bool:
        if not self.key_manager:
            return False
        password = simpledialog.askstring("Аутентификация", "Введите мастер-пароль:", show="*", parent=self)
        if not password:
            return False
        try:
            return self.key_manager.unlock(password)
        except Exception as e:
            logger.warning(f"Clipboard reveal authentication failed: {e}")
            return False
