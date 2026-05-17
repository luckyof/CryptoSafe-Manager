import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.import_export import ImportOptions, VaultImporter


class ImportDialog(tk.Toplevel):
    def __init__(self, parent, entry_manager, on_import_complete=None):
        super().__init__(parent)
        self.parent = parent
        self.entry_manager = entry_manager
        self.on_import_complete = on_import_complete
        self.file_content = None

        self.title("Импорт хранилища")
        self.geometry("760x560")
        self.transient(parent)
        self.grab_set()

        self._build_variables()
        self._create_widgets()

    def _build_variables(self):
        self.path_var = tk.StringVar()
        self.format_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value="dry-run")
        self.duplicate_var = tk.StringVar(value="skip")
        self.password_var = tk.StringVar()
        self.private_key_path_var = tk.StringVar()

    def _create_widgets(self):
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        file_frame = ttk.LabelFrame(root, text="Файл", padding=8)
        file_frame.pack(fill=tk.X)
        ttk.Entry(file_frame, textvariable=self.path_var).grid(row=0, column=0, sticky=tk.EW, padx=(0, 6))
        ttk.Button(file_frame, text="Выбрать", command=self._choose_file).grid(row=0, column=1)
        file_frame.columnconfigure(0, weight=1)

        settings = ttk.LabelFrame(root, text="Параметры", padding=8)
        settings.pack(fill=tk.X, pady=8)
        ttk.Label(settings, text="Формат").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Combobox(
            settings,
            textvariable=self.format_var,
            values=["", "encrypted_json", "csv", "bitwarden_json", "lastpass_csv", "json"],
            state="readonly",
            width=22,
        ).grid(row=0, column=1, sticky=tk.W, pady=3)
        ttk.Label(settings, text="Режим").grid(row=0, column=2, sticky=tk.W, padx=(16, 6), pady=3)
        ttk.Combobox(settings, textvariable=self.mode_var, values=["dry-run", "merge", "replace"], state="readonly", width=12).grid(row=0, column=3, sticky=tk.W)
        ttk.Label(settings, text="Дубликаты").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Combobox(settings, textvariable=self.duplicate_var, values=["skip", "update", "rename", "error"], state="readonly", width=12).grid(row=1, column=1, sticky=tk.W)

        secrets = ttk.LabelFrame(root, text="Расшифровка", padding=8)
        secrets.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(secrets, text="Пароль").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(secrets, textvariable=self.password_var, show="*").grid(row=0, column=1, sticky=tk.EW, pady=3)
        ttk.Label(secrets, text="Private key PEM").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(secrets, textvariable=self.private_key_path_var).grid(row=1, column=1, sticky=tk.EW, pady=3)
        ttk.Button(secrets, text="Выбрать", command=self._choose_private_key).grid(row=1, column=2, padx=(6, 0))
        secrets.columnconfigure(1, weight=1)

        result_frame = ttk.LabelFrame(root, text="Предпросмотр", padding=8)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.summary_var = tk.StringVar(value="Файл не выбран")
        ttk.Label(result_frame, textvariable=self.summary_var).pack(anchor=tk.W)
        self.preview_tree = ttk.Treeview(result_frame, columns=("title", "username", "url"), show="headings", height=10)
        self.preview_tree.heading("title", text="Название")
        self.preview_tree.heading("username", text="Логин")
        self.preview_tree.heading("url", text="URL")
        self.preview_tree.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        footer = ttk.Frame(root)
        footer.pack(fill=tk.X)
        ttk.Button(footer, text="Предпросмотр", command=self._preview).pack(side=tk.LEFT)
        ttk.Button(footer, text="Импорт", command=self._import).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(footer, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT)

    def _choose_file(self):
        path = filedialog.askopenfilename(parent=self)
        if not path:
            return
        self.path_var.set(path)
        with open(path, "rb") as file:
            self.file_content = file.read()
        detected = VaultImporter(self.entry_manager).detect_format(self.file_content, path)
        self.format_var.set(detected if detected != "unknown" else "")
        self.summary_var.set(f"Определён формат: {detected}")

    def _choose_private_key(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("PEM", "*.pem"), ("Все файлы", "*.*")])
        if path:
            self.private_key_path_var.set(path)

    def _private_key_bytes(self):
        path = self.private_key_path_var.get().strip()
        if not path:
            return None
        with open(path, "rb") as file:
            return file.read()

    def _build_import_options(self, mode=None):
        return ImportOptions(
            format=self.format_var.get() or None,
            mode=mode or self.mode_var.get(),
            duplicate_policy=self.duplicate_var.get(),
            encryption_password=self.password_var.get() or None,
            private_key_pem=self._private_key_bytes(),
        )

    def _require_content(self):
        if self.file_content is None:
            messagebox.showerror("Импорт", "Выберите файл для импорта.", parent=self)
            return False
        return True

    def _preview(self):
        if not self._require_content():
            return
        try:
            result = VaultImporter(self.entry_manager).import_from_bytes(self.file_content, self._build_import_options(mode="dry-run"), self.path_var.get())
            self._show_result(result)
        except Exception as exc:
            messagebox.showerror("Импорт", f"Не удалось построить предпросмотр:\n{exc}", parent=self)

    def _import(self):
        if not self._require_content():
            return
        try:
            result = VaultImporter(self.entry_manager).import_from_bytes(self.file_content, self._build_import_options(), self.path_var.get())
            self._show_result(result)
            if self.on_import_complete:
                self.on_import_complete()
            messagebox.showinfo("Импорт", f"Добавлено: {result.imported_count}\nОбновлено: {result.updated_count}\nПропущено: {result.skipped_count}", parent=self)
        except Exception as exc:
            messagebox.showerror("Импорт", f"Не удалось выполнить импорт:\n{exc}", parent=self)

    def _show_result(self, result):
        self.preview_tree.delete(*self.preview_tree.get_children())
        for entry in result.preview:
            self.preview_tree.insert("", tk.END, values=(entry.get("title", ""), entry.get("username", ""), entry.get("url", "")))
        self.summary_var.set(
            f"Формат: {result.format}; режим: {result.mode}; записей в предпросмотре: {len(result.preview)}; "
            f"дубликатов: {result.duplicate_count}; предупреждений: {len(result.warnings)}"
        )
