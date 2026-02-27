# main.py
import sys
import os

# Добавляем путь к src, чтобы работали импорты
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from gui.main_window import MainWindow
from core.config import ConfigManager

if __name__ == "__main__":
    # 1. Инициализация менеджера конфигурации
    config = ConfigManager()
    
    # 2. Запуск главного окна с передачей конфига
    app = MainWindow(config=config)
    app.mainloop()
