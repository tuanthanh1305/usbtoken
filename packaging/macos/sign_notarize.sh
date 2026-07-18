#!/usr/bin/env bash
# sign_notarize.sh — codesign (hardened runtime + entitlements) → notarize → staple.
#
#   THIẾU entitlements/disable-library-validation -> KHÔNG dlopen middleware CA.
#   THIẾU notarization -> Gatekeeper CHẶN ("… không thể mở vì Apple không kiểm tra được").
#
# Bí mật: dùng notarytool với keychain profile (tạo trước bằng
#   `xcrun notarytool store-credentials`), KHÔNG nhét Apple ID/mật khẩu vào script.
#
#   APP="dist/vn-esign-service.app" \
#   SIGN_ID="Developer ID Application: TÊN TỔ CHỨC (TEAMID)" \
#   NOTARY_PROFILE="vn-esign-notary" \
#   packaging/macos/sign_notarize.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

APP="${APP:-dist/vn-esign-service.app}"
HELPER="${HELPER:-dist/bridge_x86_64/vn-esign-bridge-x86_64}"
ENTITLEMENTS="packaging/macos/entitlements.plist"
SIGN_ID="${SIGN_ID:?Đặt SIGN_ID='Developer ID Application: ... (TEAMID)'}"
NOTARY_PROFILE="${NOTARY_PROFILE:?Đặt NOTARY_PROFILE (keychain profile của notarytool)}"

[ -e "$APP" ] || { echo "❌ Chưa build: $APP (chạy build.sh trước)."; exit 1; }

sign_one() {
  local target="$1"
  echo "== codesign (hardened runtime + entitlements): $target =="
  codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" --sign "$SIGN_ID" "$target"
  codesign --verify --deep --strict --verbose=2 "$target"
}

# Ký helper x86_64 trước (nếu có), rồi ký .app (--deep sẽ ký nội dung còn lại).
[ -e "$HELPER" ] && sign_one "$HELPER"
sign_one "$APP"

echo "== Đóng gói ZIP để notarize =="
ZIP="dist/vn-esign-service.zip"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

echo "== Notarize (notarytool, chờ kết quả) =="
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait

echo "== Staple vé công chứng vào .app =="
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "✅ Đã ký + công chứng + staple. Gatekeeper sẽ cho phép mở."
