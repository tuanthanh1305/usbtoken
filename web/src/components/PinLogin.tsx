// Màn 3 — Nhập PIN (masked, không autocomplete). CẢNH BÁO ĐỎ nếu final_try;
// CHẶN nếu locked.

import { useState } from "react";
import type { LoginResponse, TokenInfo } from "../types";
import { useLogin } from "../api/hooks";
import { ApiError } from "../api/client";

export function PinLogin({
  tokenId,
  token,
  onLoggedIn,
}: {
  tokenId: string;
  token: TokenInfo;
  onLoggedIn: (res: LoginResponse) => void;
}) {
  const [pin, setPin] = useState("");
  const login = useLogin();
  const ps = token.pin_state;

  if (ps.locked) {
    return (
      <p className="note bad">
        🔒 PIN của token ĐÃ BỊ KHOÁ. Không thể đăng nhập — liên hệ nhà cung cấp CA để mở khoá bằng PUK.
      </p>
    );
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pin) return;
    login.mutate(
      { tokenId, pin },
      {
        onSuccess: (res) => {
          setPin("");
          onLoggedIn(res);
        },
      },
    );
  };

  return (
    <form className="pinform" onSubmit={submit} autoComplete="off">
      {ps.final_try && (
        <p className="note bad blink">
          ⛔ CẢNH BÁO: đây là LẦN THỬ PIN CUỐI CÙNG. Nhập sai sẽ KHOÁ token VĨNH VIỄN.
        </p>
      )}
      {ps.count_low && !ps.final_try && (
        <p className="note warn">⚠️ Số lần thử PIN còn lại đang thấp.</p>
      )}
      {ps.protected_auth_path ? (
        <p className="note">Token dùng bàn phím riêng (pinpad) — nhập PIN trên thiết bị.</p>
      ) : (
        <input
          type="password"
          className="pin"
          placeholder="Nhập mã PIN"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
          name="vn-esign-pin"
          inputMode="numeric"
        />
      )}
      <button className="btn" type="submit" disabled={login.isPending || (!pin && !ps.protected_auth_path)}>
        {login.isPending ? "Đang đăng nhập…" : "Đăng nhập token"}
      </button>
      {login.isError && (
        <p className="note bad">
          {login.error instanceof ApiError ? login.error.message : "Đăng nhập thất bại."}
        </p>
      )}
    </form>
  );
}
