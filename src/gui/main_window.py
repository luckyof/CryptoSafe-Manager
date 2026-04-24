import tkinter as tk
from tkinter import ttk, messagebox
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

        self.create_toolbar()
        self.create_search_area()
        self.create_main_area()
        self.create_menu()
        self.create_status_bar()

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

        password = selected[0].get("password", "")
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.clipboard_label.config(text="Буфер: скопировано!")
            self.after(3000, lambda: self.clipboard_label.config(text="Буфер: --"))

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
            password = entry.get("password", "")
            if password:
                self.clipboard_clear()
                self.clipboard_append(password)
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
