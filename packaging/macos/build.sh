#!/usr/bin/env bash
# build.sh — Build daemon universal2 + helper x86_64 (macOS).
#
#   daemon:  universal2 (arm64 + x86_64) — chạy cả Apple Silicon lẫn Intel.
#   helper:  x86_64 RIÊNG — để nạp middleware chỉ-có-x86_64 dưới Rosetta 2 trên
#            máy Apple Silicon (daemon gọi `arch -x86_64 <helper>`).
#
# Cần Python universal2 (python.org) cho daemon. Chạy TỪ GỐC repo.
#   packaging/macos/build.sh
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

echo "== Build DAEMON (universal2) =="
"$PY" -m PyInstaller --noconfirm --clean --name vn-esign-service \
  --target-arch universal2 \
  --collect-all PyKCS11 --collect-all smartcard \
  --add-data "data:data" \
  -p . service/app.py

echo "== Build BRIDGE HELPER (x86_64, cho Rosetta) =="
# Dùng Python x86_64 (qua Rosetta) để ép slice x86_64. Nếu host là Intel, mặc định đã x86_64.
if [ "$(uname -m)" = "arm64" ]; then
  ARCH_PREFIX=(arch -x86_64)
else
  ARCH_PREFIX=()
fi
"${ARCH_PREFIX[@]}" "$PY" -m PyInstaller --noconfirm --clean --name vn-esign-bridge-x86_64 \
  --target-arch x86_64 --distpath dist/bridge_x86_64 \
  --collect-all PyKCS11 \
  -p . core/bridge/helper.py

echo "✅ Xong."
echo "   dist/vn-esign-service.app  (universal2)"
echo "   dist/bridge_x86_64/vn-esign-bridge-x86_64  (x86_64)"
echo "   Bước tiếp: sign_notarize.sh (codesign + entitlements + notarytool + stapler)."
