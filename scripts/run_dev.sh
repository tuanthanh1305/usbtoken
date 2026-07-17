#!/usr/bin/env bash
# Chạy daemon vn-esign ở chế độ DEV trên Linux/macOS (bind CHỈ 127.0.0.1).
#
# Cách dùng:
#   scripts/run_dev.sh                # cổng mặc định 8787 (tự dò cổng trống)
#   VN_ESIGN_PORT=9000 scripts/run_dev.sh
#
# ⭐ KHÔNG tải/chạy installer bên thứ ba. Chỉ khởi động daemon cục bộ.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${VN_ESIGN_PORT:-8787}"
PYTHON="${PYTHON:-python3}"

echo "→ vn-esign daemon (dev) — loopback 127.0.0.1:${PORT}"
echo "  Swagger: http://127.0.0.1:${PORT}/docs"

# reload chỉ để dev; sản phẩm dùng service.app:run (ghi file trạng thái, tự dò cổng).
exec "$PYTHON" -m uvicorn service.app:app \
  --host 127.0.0.1 --port "$PORT" --reload --log-level info
