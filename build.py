import os
import subprocess
import sys


def main():
    """Собрать приложение в папку dist через PyInstaller."""
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--paths",
        "src",
        "--name",
        "CryptoSafeManager",
        "run.py",
    ]
    subprocess.check_call(command, cwd=os.path.abspath(os.path.dirname(__file__)))


if __name__ == "__main__":
    main()
