#!/usr/bin/env bash
# package.sh — Đóng gói .deb + .rpm (fpm) và AppImage từ bản build PyInstaller.
# Chạy sau build.sh. Cần: fpm (gem install fpm), và appimagetool cho AppImage.
#   packaging/linux/package.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

VERSION="${VERSION:-0.1.0}"
ARCH="$(uname -m)"                 # x86_64 | aarch64
DIST="dist/vn-esign-service"
[ -d "$DIST" ] || { echo "❌ Chưa build ($DIST). Chạy build.sh trước."; exit 1; }

# Thư mục dàn trang tạm CHỦ-SỞ-HỮU-ONLY.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/vnesign-pkg.XXXXXX")"
chmod 700 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT

# Bố cục cài: /opt/vn-esign-suite (bin), /usr/share (udev rule + unit mẫu),
# symlink /usr/bin.
install -d -m 0755 "$STAGE/opt/vn-esign-suite"
cp -R "$DIST"/. "$STAGE/opt/vn-esign-suite/"
chmod -R go-w "$STAGE/opt/vn-esign-suite"          # không cho group/other ghi
install -d -m 0755 "$STAGE/usr/share/vn-esign-suite"
install -m 0644 packaging/linux/99-vn-token.rules "$STAGE/usr/share/vn-esign-suite/"
install -m 0644 packaging/linux/vn-esign.service  "$STAGE/usr/share/vn-esign-suite/"
install -d -m 0755 "$STAGE/usr/bin"
ln -sf /opt/vn-esign-suite/vn-esign-service "$STAGE/usr/bin/vn-esign-service"

DEPENDS=(--depends pcscd --depends libccid)         # opensc/p11-kit/libnss3-tools: khuyến nghị
COMMON=(
  -s dir -n vn-esign-suite -v "$VERSION" -a "$ARCH"
  --description "Phần mềm ký số & kiểm tra chữ ký số trên USB token (loopback)."
  --url "https://rootca.gov.vn" --license "Proprietary"
  --after-install packaging/linux/postinstall.sh
  --before-remove packaging/linux/preremove.sh
  "${DEPENDS[@]}"
  -C "$STAGE" opt usr
)

if command -v fpm >/dev/null 2>&1; then
  echo "== Đóng .deb =="
  fpm -t deb --depends libnss3-tools "${COMMON[@]}"
  echo "== Đóng .rpm =="
  fpm -t rpm --depends opensc "${COMMON[@]}"
else
  echo "⚠️ Chưa cài fpm (gem install fpm) — bỏ qua .deb/.rpm."
fi

# --- AppImage (portable, không cần cài) ---
if command -v appimagetool >/dev/null 2>&1; then
  echo "== Đóng AppImage =="
  APPDIR="$STAGE/vn-esign.AppDir"
  install -d -m 0755 "$APPDIR/usr/bin"
  cp -R "$DIST"/. "$APPDIR/usr/bin/"
  cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/vn-esign-service" "$@"
EOF
  chmod 0755 "$APPDIR/AppRun"                        # 0755, KHÔNG 777
  cat > "$APPDIR/vn-esign.desktop" <<'EOF'
[Desktop Entry]
Name=vn-esign-suite
Exec=vn-esign-service
Icon=vn-esign
Type=Application
Categories=Utility;Security;
EOF
  : > "$APPDIR/vn-esign.png"                          # icon placeholder
  ARCH="$ARCH" appimagetool "$APPDIR" "dist/vn-esign-suite-$VERSION-$ARCH.AppImage"
else
  echo "⚠️ Chưa cài appimagetool — bỏ qua AppImage."
fi

echo "✅ Xong. Xem thư mục dist/ (và thư mục hiện tại cho .deb/.rpm)."
