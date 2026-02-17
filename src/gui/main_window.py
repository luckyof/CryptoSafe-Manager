import tkinter as tk
from tkinter import ttk, messagebox
from .widgets.secure_table import SecureTable
from .setup_wizard import SetupWizard
from .settings_dialog import SettingsDialog
from .widgets.audit_log_viewer import AuditLogViewer

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("800x600")

        # Меню
        menubar = tk.Menu(self)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=lambda: messagebox.showinfo("Placeholder", "Создание хранилища (заглушка)"))
        file_menu.add_command(label="Открыть", command=lambda: messagebox.showinfo("Placeholder", "Открытие хранилища (заглушка)"))
        file_menu.add_command(label="Резервная копия", command=lambda: messagebox.showinfo("Placeholder", "Резервная копия (заглушка)"))
        file_menu.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=lambda: messagebox.showinfo("Placeholder", "Добавление записи (заглушка)"))
        edit_menu.add_command(label="Изменить", command=lambda: messagebox.showinfo("Placeholder", "Изменение записи (заглушка)"))
        edit_menu.add_command(label="Удалить", command=lambda: messagebox.showinfo("Placeholder", "Удаление записи (заглушка)"))
        menubar.add_cascade(label="Правка", menu=edit_menu)
        
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи", command=self.view_logs)
        view_menu.add_command(label="Настройки", command=self.view_settings)
        menubar.add_cascade(label="Вид", menu=view_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Справка", command=lambda: messagebox.showinfo("Справка", "Документация по CryptoSafe Manager"))
        menubar.add_cascade(label="Справка", menu=help_menu)
        
        self.config(menu=menubar)

        # Центральный виджет: таблица с тестовыми данными
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True)

        # Строка состояния
        self.status_var = tk.StringVar(value="Статус: Не вошел | Буфер обмена: Пусто (таймер заглушка)")
        status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Для демонстрации мастера настройки (вызвать при первом запуске)
        # self.after(100, self.show_setup_wizard)

    def show_setup_wizard(self):
        SetupWizard(self)

    def view_settings(self):
        SettingsDialog(self)

    def view_logs(self):
        AuditLogViewer(self)

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()