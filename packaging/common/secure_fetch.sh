#!/usr/bin/env bash
# secure_fetch.sh — hàm TẢI-VÀ-VERIFY tham chiếu (source vào script khác).
#
#   source packaging/common/secure_fetch.sh
#   secure_fetch "https://host/file" "/dest/path" "<sha256-hex>"
#
# TRIẾT LÝ AN TOÀN (đối lập với installer CA rủi ro):
#   * CHỈ HTTPS + TLS1.2+, từ chối redirect sang http (--proto '=https').
#   * Tải vào thư mục tạm CHỦ-SỞ-HỮU-ONLY (mktemp -d), KHÔNG /tmp cố định.
#   * VERIFY sha256 ghim sẵn TRƯỚC khi dùng; sai -> xoá + thoát.
#   * chmod 600/700 — KHÔNG BAO GIỜ 777.
#   * set -euo pipefail; kiểm mã thoát mọi lệnh.
set -euo pipefail

_sha256() {
  # In sha256 hex của $1 (dùng sha256sum hoặc shasum tuỳ OS).
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

secure_fetch() {
  local url="$1" dest="$2" expected_sha="$3"
  case "$url" in
    https://*) : ;;
    *) echo "❌ TỪ CHỐI: chỉ tải qua HTTPS — '$url'." >&2; return 1 ;;
  esac

  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/vnesign.XXXXXX")"
  chmod 700 "$tmpdir"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpdir'" RETURN
  local tmpfile="$tmpdir/download.bin"

  echo "→ Tải $url"
  # --fail: HTTP lỗi -> mã thoát khác 0; --proto '=https': cấm nhảy sang http.
  if ! curl --fail --location --proto '=https' --tlsv1.2 \
            --retry 3 --retry-delay 2 --connect-timeout 20 \
            -o "$tmpfile" "$url"; then
    echo "❌ Tải thất bại (mạng/HTTP): $url" >&2
    return 1
  fi

  local actual
  actual="$(_sha256 "$tmpfile")"
  if [ "$actual" != "$expected_sha" ]; then
    echo "❌ CHECKSUM SAI — từ chối dùng file." >&2
    echo "   mong đợi: $expected_sha" >&2
    echo "   thực tế : $actual" >&2
    return 1
  fi
  echo "✓ Checksum khớp: $actual"

  mkdir -p "$(dirname "$dest")"
  install -m 600 "$tmpfile" "$dest"   # 600, không 777
  echo "✓ Đã lưu (chmod 600): $dest"
}

# Cho phép gọi trực tiếp: secure_fetch.sh URL DEST SHA256
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  if [ "$#" -ne 3 ]; then
    echo "Dùng: $0 <https-url> <dest> <sha256-hex>" >&2
    exit 2
  fi
  secure_fetch "$1" "$2" "$3"
fi
