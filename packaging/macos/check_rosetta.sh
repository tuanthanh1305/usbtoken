#!/usr/bin/env bash
# check_rosetta.sh — Trên Apple Silicon, kiểm & (nếu đồng ý) cài Rosetta 2.
# Rosetta cần để chạy helper x86_64 nạp middleware chỉ-có-x86_64.
#   packaging/macos/check_rosetta.sh
set -euo pipefail

if [ "$(uname -m)" != "arm64" ]; then
  echo "Máy Intel (x86_64) — không cần Rosetta."
  exit 0
fi

# Rosetta có mặt? (oahd là daemon của Rosetta)
if /usr/bin/pgrep -q oahd || [ -d /Library/Apple/usr/libexec/oah ]; then
  echo "✅ Rosetta 2 đã được cài."
  exit 0
fi

echo "⚠️ Chưa cài Rosetta 2 — helper x86_64 sẽ không chạy được (middleware chỉ x86_64)."
echo "   Cài bằng: softwareupdate --install-rosetta --agree-to-license"
if [ "${AUTO_INSTALL:-0}" = "1" ]; then
  echo "→ Đang cài Rosetta 2 (bạn đã bật AUTO_INSTALL=1)…"
  softwareupdate --install-rosetta --agree-to-license
  echo "✅ Xong."
else
  echo "   (Chạy lại với AUTO_INSTALL=1 để tự cài, hoặc chạy lệnh trên thủ công.)"
  exit 1
fi
