#!/usr/bin/env bash
# preremove.sh — chạy trước khi gỡ .deb/.rpm. Dừng service user + gỡ udev rule.
set -euo pipefail

# Dừng daemon user (best-effort — có thể chạy dưới nhiều user; nhắc là chính).
echo "Gỡ vn-esign-suite. Nếu đang chạy daemon user, dừng bằng:"
echo "  systemctl --user disable --now vn-esign.service"

# Gỡ udev rule đã cài.
DEST="/etc/udev/rules.d/99-vn-token.rules"
if [ -f "$DEST" ]; then
  rm -f "$DEST"
  command -v udevadm >/dev/null 2>&1 && udevadm control --reload-rules || true
  echo "  ✓ Đã gỡ udev rule."
fi
# KHÔNG tự tắt pcscd (dịch vụ dùng chung, phần mềm khác có thể cần).
