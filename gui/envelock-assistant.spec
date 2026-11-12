# PyInstaller spec for the Envelock assistant. Build from the repo root:
#   pyinstaller gui/envelock-assistant.spec
# One self-contained window executable per OS (run it on the matching OS; PyInstaller does not
# cross-compile). The encoder and the actions layer travel as data and are loaded by path at
# runtime (via sys._MEIPASS); because they are not statically analysed, every module they import
# is declared below so it is bundled.
import os

from PyInstaller.utils.hooks import collect_all

root = os.path.abspath(os.getcwd())

# Modules imported by encoder/envelock.py, gui/actions.py and gui/_e2e.py (loaded dynamically,
# so listed here). A missing one only fails at run time inside the frozen exe ("No module named
# 'shlex'" killed --selftest on Windows); tests/test_gui_actions.py checks this list against the
# imports of those three files.
hidden = [
    "argparse", "base64", "calendar", "ctypes", "ctypes.util", "ctypes.wintypes", "fnmatch", "getpass",
    "glob", "hashlib", "http.server", "importlib.util", "io", "json", "os", "re", "secrets", "shlex",
    "shutil", "socket", "ssl", "stat", "struct", "subprocess", "tempfile", "threading", "time",
    "types", "unicodedata", "urllib.parse", "urllib.request", "uuid", "zipfile",
]
crypto_datas, crypto_binaries, crypto_hidden = collect_all("cryptography")

a = Analysis(
    [os.path.join(root, "gui", "envelock_gui.py")],
    pathex=[root],
    binaries=crypto_binaries,
    datas=[
        (os.path.join(root, "encoder", "envelock.py"), "encoder"),
        (os.path.join(root, "encoder", "virtualize.php"), "encoder"),
        (os.path.join(root, "third_party", "php-parser"), "third_party/php-parser"),
        (os.path.join(root, "gui", "actions.py"), "gui"),
        (os.path.join(root, "gui", "_e2e.py"), "gui"),
    ] + crypto_datas,
    hiddenimports=hidden + crypto_hidden,
    excludes=["pytest", "numpy", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="envelock-assistant",
    console=False,          # windowed app, no terminal
    strip=False,
    upx=False,
)
