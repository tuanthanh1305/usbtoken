#!/usr/bin/env bash
# postinstall.sh — chạy sau khi cài .deb/.rpm (maintainer script).
# Bật pcscd, cài udev rule, reload, nhắc thêm user vào plugdev.
# ⭐ CHỈ đụng những gì CẦN quyền hệ thống (pcscd/udev). KHÔNG chmod 777, KHÔNG tải mạng.
set -euo pipefail

echo "== vn-esign-suite: cấu hình sau cài đặt =="

# 1) PC/SC: bật & chạy pcscd (nếu có systemd).
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now pcscd 2>/dev/null || \
    echo "  ⚠️ Không bật được pcscd tự động — chạy: sudo systemctl enable --now pcscd"
fi

# 2) udev rule cho USB token (gói đã đặt file vào /usr/share; copy sang rules.d).
SRC="/usr/share/vn-esign-suite/99-vn-token.rules"
DEST="/etc/udev/rules.d/99-vn-token.rules"
if [ -f "$SRC" ]; then
  install -m 0644 "$SRC" "$DEST"           # 0644 (rule world-readable là bình thường), KHÔNG 777
  if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules && udevadm trigger || \
      echo "  ⚠️ Reload udev thất bại — chạy: sudo udevadm control --reload-rules && sudo udevadm trigger"
  fi
  echo "  ✓ Đã cài udev rule: $DEST"
fi

# 3) Nhắc quyền plugdev (KHÔNG tự sửa nhóm của user — để user chủ động).
cat <<'EOF'

  ➜ Để user truy cập token, thêm vào nhóm plugdev rồi ĐĂNG NHẬP LẠI:
        sudo usermod -aG plugdev "$USER"

  ➜ Chạy daemon dưới nền (systemd --user, least-privilege — KHÔNG cần root):
        mkdir -p ~/.config/systemd/user
        cp /usr/share/vn-esign-suite/vn-esign.service ~/.config/systemd/user/
        systemctl --user daemon-reload
        systemctl --user enable --now vn-esign.service
        # Để daemon chạy cả khi chưa mở phiên đồ hoạ:
        sudo loginctl enable-linger "$USER"

  Daemon chỉ lắng nghe 127.0.0.1. Kho neo tin cậy (NEAC) đã ký, đóng gói sẵn.
EOF
echo "== Hoàn tất =="
