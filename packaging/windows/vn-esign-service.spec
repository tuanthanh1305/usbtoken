# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — DAEMON vn-esign (Windows, 64-bit).
# Chạy TỪ THƯ MỤC GỐC repo bằng Python 64-bit:
#   pyinstaller packaging/windows/vn-esign-service.spec
#
# Kèm SẴN thư mục data/ (kho neo tin cậy ĐÃ KÝ + Phụ lục + vendor_intel) để máy
# mới không phải ra mạng mới có gốc tin cậy.

datas = [("data", "data")]

hiddenimports = [
    "PyKCS11",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.lifespan.on",
]

a = Analysis(
    ["service/app.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="vn-esign-service",
    debug=False,
    strip=False,
    upx=False,            # KHÔNG nén UPX (SmartScreen/AV hay nghi ngờ file nén)
    console=True,         # daemon nền; đổi False nếu chạy như service ẩn
    target_arch=None,     # theo Python host (build x64 bằng Python x64)
)
