// Nhãn tiếng Việt cho mã trạng thái (Điều 5 TT 15/2025: thông báo bằng tiếng Việt).

import type { RevocationStatus, ValidationStatus } from "./types";

export const STATUS_LABEL: Record<ValidationStatus, string> = {
  valid: "HỢP LỆ",
  invalid: "KHÔNG HỢP LỆ",
  expired: "HẾT HẠN",
  revoked: "ĐÃ THU HỒI",
  unknown: "CHƯA XÁC ĐỊNH",
  foreign_recognized: "CÔNG NHẬN NƯỚC NGOÀI",
};

// Lớp CSS theo mức nghiêm trọng (xanh/đỏ/vàng).
export const STATUS_TONE: Record<ValidationStatus, "ok" | "bad" | "warn"> = {
  valid: "ok",
  invalid: "bad",
  expired: "bad",
  revoked: "bad",
  unknown: "warn",
  foreign_recognized: "warn",
};

export const STATUS_HINT: Record<ValidationStatus, string> = {
  valid: "Chứng thư hợp lệ, còn hiệu lực, chưa bị thu hồi — được phép ký.",
  invalid: "Không dựng được đường dẫn tin cậy tới gốc NEAC hoặc ràng buộc sai — KHÔNG được ký.",
  expired: "Chứng thư đã hết hạn — KHÔNG được ký.",
  revoked: "Chứng thư đã bị thu hồi — KHÔNG được ký.",
  unknown: "Chưa đủ căn cứ khẳng định (không lấy được thu hồi / chưa đủ cấu hình) — KHÔNG được ký (fail-closed).",
  foreign_recognized: "Thuộc danh sách tin cậy nước ngoài — không thuộc gốc NEAC.",
};

export const REVOCATION_LABEL: Record<RevocationStatus, string> = {
  good: "Chưa thu hồi",
  revoked: "ĐÃ THU HỒI",
  unknown: "Không xác định",
  unchecked: "Chưa kiểm (offline)",
};

export const OS_LABEL: Record<string, string> = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
};

export const PROFILE_CONFIDENCE_LABEL: Record<string, string> = {
  unknown: "chưa xác định",
  low: "thấp",
  medium: "trung bình",
};
