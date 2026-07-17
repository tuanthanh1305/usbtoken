"""CLI chẩn đoán (bí danh của ``python -m core.platform --diagnose``).

Giữ lại điểm vào ``vn-esign-diagnose`` (pyproject scripts) nhưng ủy quyền cho
hiện thực chuẩn ở ``core.platform.__main__`` để tránh trùng lặp.
"""

from __future__ import annotations

import sys

from core.platform.__main__ import diagnose, main

__all__ = ["diagnose", "main"]


if __name__ == "__main__":
    sys.exit(main())
