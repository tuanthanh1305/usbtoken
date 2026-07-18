#!/usr/bin/env bash
# build.sh — Build daemon vn-esign (Linux) bằng PyInstaller (ELF).
# Build RIÊNG cho từng kiến trúc (x86_64 / aarch64) — KHÔNG cross-compile.
#   packaging/linux/build.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PY="${PYTHON:-python3}"
REQUIRE_SIGNED="${REQUIRE_SIGNED_STORE:-0}"

echo "== Kiểm kho neo tin cậy (đóng gói sẵn, đã ký) =="
store_args=(-m packaging.common.bundle_trust_store --check)
[ "$REQUIRE_SIGNED" = "1" ] && store_args+=(--require-signed)
"$PY" "${store_args[@]}" || { echo "❌ Kho chưa sẵn sàng — từ chối build."; exit 1; }

echo "== Cài phụ thuộc =="
"$PY" -m pip install -r requirements.txt pyinstaller==6.11.1

echo "== Build DAEMON (ELF $(uname -m)) =="
"$PY" -m PyInstaller --noconfirm --clean --name vn-esign-service \
  --collect-all PyKCS11 --collect-all smartcard \
  --add-data "data:data" \
  -p . service/app.py

echo "✅ Xong: dist/vn-esign-service/  (chạy dist/vn-esign-service/vn-esign-service)"
echo "   Bước tiếp: package.sh (.deb/.rpm/AppImage)."
