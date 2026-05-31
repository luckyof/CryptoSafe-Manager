import os
import sys

# Добавляем src в путь импорта при запуске из корня проекта.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from core.config import ConfigManager
from gui.main_window import MainWindow


if __name__ == "__main__":
    config = ConfigManager()
    app = MainWindow(config=config)
    app.mainloop()
