# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — BRIDGE HELPER 32-bit (Windows).
# ⭐ Chạy TỪ GỐC repo bằng Python 32-bit RIÊNG (môi trường ảo x86):
#   py -3.12-32 -m PyInstaller packaging/windows/vn-esign-bridge32.spec
#
# LÝ DO: nhiều middleware token của CA chỉ có DLL PKCS#11 32-bit. Daemon 64-bit
# KHÔNG dlopen được DLL 32-bit -> nó gọi helper NÀY (JSON-RPC qua stdio) để nạp
# module 32-bit trong một tiến trình 32-bit. Helper cố ý TỐI GIẢN (chỉ PyKCS11 +
# stdlib) để chạy được ở môi trường x86.

hiddenimports = ["PyKCS11"]

a = Analysis(
    ["core/bridge/helper.py"],
    pathex=["."],
    binaries=[],
    datas=[],             # helper KHÔNG đọc data/ — không cần bundle kho
    hiddenimports=hiddenimports,
    excludes=["cryptography", "fastapi", "uvicorn", "httpx"],  # không cần ở helper
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="vn-esign-bridge32",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    target_arch=None,     # PHẢI build bằng Python 32-bit để ra exe x86
)
