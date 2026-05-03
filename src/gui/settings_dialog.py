import tkinter as tk
from tkinter import ttk, messagebox

from core.config import CLIPBOARD_PRESETS


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.config_manager = parent.app_config
        self.title("Настройки")
        self.geometry("520x460")

        self._build_variables()
        self.create_widgets()

        self.transient(parent)
        self.grab_set()

    def _build_variables(self):
        settings = self.config_manager.get_clipboard_settings()
        self.profile_var = tk.StringVar(value=settings["profile"])
        self.timeout_var = tk.IntVar(value=max(5, min(300, int(settings["timeout"]))))
        self.never_clear_var = tk.BooleanVar(value=not settings["auto_clear"])
        self.monitor_var = tk.BooleanVar(value=settings["monitor_enabled"])
        self.block_var = tk.BooleanVar(value=settings["block_on_suspicious"])
        self.security_level_var = tk.StringVar(value=settings["security_level"])
        self.notify_copy_var = tk.BooleanVar(value=settings["notify_on_copy"])
        self.notify_clear_var = tk.BooleanVar(value=settings["notify_on_clear"])
        self.notify_warning_var = tk.BooleanVar(value=settings["notify_on_warning"])
        self.whitelist_var = tk.StringVar(value=", ".join(settings["allowed_applications"]))
        self.auto_lock_var = tk.IntVar(value=self.config_manager.get_int("auto_lock_timeout", 5))

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        security_tab = ttk.Frame(notebook, padding=10)
        notebook.add(security_tab, text="Безопасность")
        self._create_clipboard_settings(security_tab)

        appearance_tab = ttk.Frame(notebook, padding=10)
        notebook.add(appearance_tab, text="Внешний вид")
        ttk.Label(appearance_tab, text="Тема:").pack(anchor=tk.W)
        ttk.Combobox(appearance_tab, values=["System Default", "Light", "Dark"]).pack(anchor=tk.W, pady=5)

        advanced_tab = ttk.Frame(notebook, padding=10)
        notebook.add(advanced_tab, text="Дополнительно")
        ttk.Label(
            advanced_tab,
            text="Список разрешённых приложений применяется будущими расширенными адаптерами.",
            wraplength=460,
        ).pack(anchor=tk.W)

        footer = ttk.Frame(self)
        footer.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(footer, text="Сохранить", command=self.save).pack(side=tk.RIGHT, padx=4)
        ttk.Button(footer, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _create_clipboard_settings(self, parent):
        ttk.Label(parent, text="Профиль буфера обмена:").pack(anchor=tk.W)
        profile_combo = ttk.Combobox(
            parent,
            textvariable=self.profile_var,
            values=list(CLIPBOARD_PRESETS.keys()),
            state="readonly",
        )
        profile_combo.pack(anchor=tk.W, fill=tk.X, pady=(2, 8))
        profile_combo.bind("<<ComboboxSelected>>", lambda event: self._apply_profile_to_form())

        ttk.Label(parent, text="Таймаут автоочистки (сек):").pack(anchor=tk.W)
        timeout_spin = ttk.Spinbox(parent, from_=5, to=300, textvariable=self.timeout_var)
        timeout_spin.pack(anchor=tk.W, pady=(2, 4))
        ttk.Checkbutton(parent, text="Никогда не очищать автоматически", variable=self.never_clear_var).pack(anchor=tk.W)

        ttk.Label(parent, text="Уровень защиты:").pack(anchor=tk.W, pady=(10, 0))
        ttk.Combobox(
            parent,
            textvariable=self.security_level_var,
            values=["basic", "advanced", "paranoid"],
            state="readonly",
        ).pack(anchor=tk.W, fill=tk.X, pady=(2, 8))

        ttk.Checkbutton(parent, text="Включить мониторинг буфера обмена", variable=self.monitor_var).pack(anchor=tk.W)
        ttk.Checkbutton(parent, text="Блокировать копирование при подозрительной активности", variable=self.block_var).pack(anchor=tk.W)

        notification_box = ttk.LabelFrame(parent, text="Уведомления", padding=8)
        notification_box.pack(fill=tk.X, pady=10)
        ttk.Checkbutton(notification_box, text="При копировании", variable=self.notify_copy_var).pack(anchor=tk.W)
        ttk.Checkbutton(notification_box, text="При очистке", variable=self.notify_clear_var).pack(anchor=tk.W)
        ttk.Checkbutton(notification_box, text="При предупреждениях", variable=self.notify_warning_var).pack(anchor=tk.W)

        ttk.Label(parent, text="Разрешённые приложения (через запятую):").pack(anchor=tk.W)
        ttk.Entry(parent, textvariable=self.whitelist_var).pack(fill=tk.X, pady=(2, 8))

        ttk.Label(parent, text="Авто-блокировка приложения (мин):").pack(anchor=tk.W)
        ttk.Spinbox(parent, from_=1, to=60, textvariable=self.auto_lock_var).pack(anchor=tk.W, pady=(2, 0))

    def _apply_profile_to_form(self):
        preset = CLIPBOARD_PRESETS.get(self.profile_var.get())
        if not preset:
            return
        self.timeout_var.set(preset["clipboard_timeout"])
        self.never_clear_var.set(not preset["clipboard_auto_clear"])
        self.monitor_var.set(preset["clipboard_monitor_enabled"])
        self.block_var.set(preset["clipboard_block_on_suspicious"])
        self.security_level_var.set(preset["clipboard_security_level"])
        self.notify_copy_var.set(preset["clipboard_notify_on_copy"])
        self.notify_clear_var.set(preset["clipboard_notify_on_clear"])
        self.notify_warning_var.set(preset["clipboard_notify_on_warning"])

    def save(self):
        timeout = max(5, min(300, int(self.timeout_var.get())))
        allowed_apps = [
            value.strip()
            for value in self.whitelist_var.get().split(",")
            if value.strip()
        ]

        self.config_manager.set_clipboard_settings(
            {
                "profile": self.profile_var.get(),
                "timeout": timeout,
                "auto_clear": not self.never_clear_var.get(),
                "monitor_enabled": self.monitor_var.get(),
                "block_on_suspicious": self.block_var.get(),
                "security_level": self.security_level_var.get(),
                "notify_on_copy": self.notify_copy_var.get(),
                "notify_on_clear": self.notify_clear_var.get(),
                "notify_on_warning": self.notify_warning_var.get(),
                "allowed_applications": allowed_apps,
            }
        )
        self.config_manager.set("auto_lock_timeout", int(self.auto_lock_var.get()))

        if hasattr(self.parent, "clipboard_service"):
            self.parent.clipboard_service.set_auto_clear_timeout(None if self.never_clear_var.get() else timeout)
        if hasattr(self.parent, "apply_clipboard_monitor_setting"):
            self.parent.apply_clipboard_monitor_setting()

        messagebox.showinfo("Настройки", "Настройки сохранены.", parent=self)
        self.destroy()
