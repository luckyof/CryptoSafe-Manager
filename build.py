import os
import shutil
import subprocess
import sys


def main():
    """Собрать приложение в папку dist через PyInstaller."""
    project_dir = os.path.abspath(os.path.dirname(__file__))
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
    subprocess.check_call(command, cwd=project_dir)

    app_dir = os.path.join(project_dir, "dist", "CryptoSafeManager")
    archive_base = os.path.join(project_dir, "dist", "CryptoSafeManager")
    archive_path = f"{archive_base}.zip"
    if os.path.exists(archive_path):
        os.remove(archive_path)
    shutil.make_archive(archive_base, "zip", root_dir=os.path.dirname(app_dir), base_dir=os.path.basename(app_dir))
    print(f"ZIP archive created: {archive_path}")


if __name__ == "__main__":
    main()
