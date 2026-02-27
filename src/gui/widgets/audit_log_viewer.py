
import tkinter as tk
from tkinter import ttk

class AuditLogViewer(ttk.Frame):
    """
    Заглушка виджета для просмотра логов аудита.
    Требование: GUI-2
    """
    def __init__(self, parent):
        super().__init__(parent)
        
        self.text_area = tk.Text(self, state='disabled', wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Тестовая запись
        self.log("[STUB] Инициализация модуля аудита.")

    def log(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state='disabled')
