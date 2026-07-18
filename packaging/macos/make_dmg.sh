#!/usr/bin/env bash
# make_dmg.sh — Đóng .dmg từ .app đã ký + công chứng (macOS).
#   packaging/macos/make_dmg.sh
# (Muốn .pkg: dùng `productbuild --component dist/vn-esign-service.app /Applications out.pkg`
#  rồi `productsign --sign "Developer ID Installer: ..."`.)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

APP="${APP:-dist/vn-esign-service.app}"
DMG="${DMG:-dist/vn-esign-suite.dmg}"
[ -e "$APP" ] || { echo "❌ Chưa có $APP"; exit 1; }

# Thư mục dàn trang tạm CHỦ-SỞ-HỮU-ONLY (không /tmp cố định).
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/vnesign-dmg.XXXXXX")"
chmod 700 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT

cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"   # kéo-thả vào Applications

rm -f "$DMG"
hdiutil create -volname "vn-esign-suite" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
echo "✅ Đã tạo $DMG"
