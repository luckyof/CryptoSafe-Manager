# main.py
import sys
import os

# Добавляем путь к src, чтобы работали импорты
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from gui.main_window import MainWindow

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()