import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import logging
from datetime import datetime, timezone

from .widgets.secure_table import SecureTable
from .widgets.audit_log_viewer import AuditLogViewer
from .widgets.search_widget import SearchWidget
from .settings_dialog import SettingsDialog
from .setup_wizard import SetupWizard
from .dialogs.login_dialog import LoginDialog
from .dialogs.change_password_dialog import ChangePasswordDialog
from .dialogs.entry_dialog import EntryDialog

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

logger = logging.getLogger("MainWindow")


class MainWindow(tk.Tk):
    def __init__(self, config: ConfigManager):
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
        self._clipboard_warning_shown = False

        self.create_toolbar()
        self.create_search_area()
        self.create_main_area()
        self.create_menu()
        self.create_status_bar()
        self.setup_clipboard_ui()

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

            self.key_manager = KeyManager(self.db)
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
            self.key_manager = KeyManager(self.db)

            login = LoginDialog(self, self.key_manager)
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
        self.audit = AuditManager(self.db)
        self.status_label.config(text="Статус: Разблокировано")
        event_bus.publish("UserLoggedIn", data={"user": "default_user"})
        self.start_clipboard_monitor()
        self.load_entries()

    def load_entries(self, search_query: str = "", filters=None):
        try:
            if search_query:
                data = self.entry_manager.search_entries(search_query)
            else:
                data = self.entry_manager.get_all_entries(include_decrypted_password=True)

            if filters:
                data = self._apply_demo_filters(data, filters)

            self.table.load_data(data)
            self._update_search_categories(data)
            self.update_status(f"Записей: {len(data)}")
        except Exception as e:
            logger.error(f"Load entries error: {e}")
            messagebox.showerror("Ошибка", f"Не удалось загрузить записи:\n{e}")

    def on_minimize_event(self, event):
        if self.key_manager:
            self.key_manager.on_minimize()

    def check_inactivity(self):
        if self.key_manager and not state_manager.is_locked:
            timeout = self.app_config.get("auto_lock_timeout", 60)
            if state_manager.check_inactivity(timeout):
                self.lock_application()
            else:
                self.key_manager.touch()

        self.after(self.auto_lock_check_interval, self.check_inactivity)

    def lock_application(self):
        logger.info("Locking application...")
        self.clipboard_service.clear_clipboard("lock")
        self.key_manager.lock()
        state_manager.logout()

        self.status_label.config(text="Статус: ЗАБЛОКИРОВАНО")
        self.table.load_data([])

        login = LoginDialog(self, self.key_manager)
        if login.success:
            state_manager.login("default_user")
            self.on_login_success()
        else:
            self.on_close()

    def on_close(self):
        logger.info("Closing application...")
        if self.clipboard_monitor:
            self.clipboard_monitor.stop()
        self.clipboard_service.shutdown()
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
        ttk.Button(toolbar, text="Копировать логин", command=self.copy_username).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📋 Копировать пароль", command=self.copy_password).pack(side=tk.LEFT, padx=2)

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

        self.bind_all("<Button-1>", lambda e: state_manager.update_activity())
        self.bind_all("<Key>", lambda e: state_manager.update_activity())
        self.bind_all("<Control-Shift-P>", lambda e: self.toggle_password_visibility())

        self.table.set_context_callback(self._on_table_action)

    def setup_clipboard_ui(self):
        self.clipboard_service.add_observer(lambda status: self.after(0, self._on_clipboard_status, status))
        event_bus.subscribe("ClipboardCopied", lambda event: self.after(0, self._on_clipboard_copied, event.data))
        event_bus.subscribe("ClipboardCleared", lambda event: self.after(0, self._on_clipboard_cleared, event.data))
        event_bus.subscribe("ClipboardWarning", lambda event: self.after(0, self._on_clipboard_warning, event.data))
        event_bus.subscribe("ClipboardCopyBlockChanged", lambda event: self.after(0, self._on_clipboard_block_changed, event.data))
        event_bus.subscribe("ClipboardError", lambda event: self.after(0, self._on_clipboard_error, event.data))
        self.after(1000, self.refresh_clipboard_status)

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
        file_menu.add_command(label="Заблокировать", command=self.lock_application)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
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
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(self.status_bar, text="Статус: Заблокировано", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.clipboard_label = ttk.Label(self.status_bar, text="Буфер: --", relief=tk.SUNKEN)
        self.clipboard_label.pack(side=tk.RIGHT, fill=tk.X)
        self.clipboard_label.bind("<Button-1>", lambda event: self.show_clipboard_preview())

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

    def show_settings(self):
        SettingsDialog(self)

    def show_audit_window(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("600x400")
        viewer = AuditLogViewer(win)
        viewer.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if self.db:
            logs = self.db.fetchall("SELECT timestamp, action, details FROM audit_log ORDER BY timestamp DESC")
            for log in logs:
                viewer.log(f"{log[0]} - {log[1]}: {log[2]}")

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
