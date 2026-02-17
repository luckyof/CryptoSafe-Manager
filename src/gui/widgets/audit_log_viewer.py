import tkinter as tk
from tkinter import ttk

class AuditLogViewer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Просмотр логов аудита")
        self.geometry("600x400")

        label = tk.Label(self, text="Заглушка для Спринта 5: Здесь будут отображаться логи аудита.")
        label.pack(pady=20)

        # Пример таблицы-заглушки
        tree = ttk.Treeview(self, columns=("timestamp", "action", "details"), show="headings")
        tree.heading("timestamp", text="Время")
        tree.heading("action", text="Действие")
        tree.heading("details", text="Детали")
        tree.pack(fill=tk.BOTH, expand=True)

        ttk.Button(self, text="Закрыть", command=self.destroy).pack(pady=10)