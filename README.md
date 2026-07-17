# vn-esign-suite

Phần mềm **ký số** và **kiểm tra chữ ký số** trên USB token cho Việt Nam, hỗ trợ
**NGANG HÀNG** Windows, macOS (Intel + Apple Silicon) và Linux.

> ⚠️ **Phần mềm bị điều chỉnh trực tiếp bởi pháp luật.** Đây CHÍNH LÀ "phần mềm
> ký số" và "phần mềm kiểm tra chữ ký số" theo **Điều 17 Nghị định 23/2025/NĐ-CP**
> (hiệu lực 10/4/2025) và **Thông tư 15/2025/TT-BKHCN** (15/8/2025). Các chức
> năng là BẮT BUỘC THEO LUẬT, không phải tuỳ chọn kỹ thuật. Xem
> [`docs/compliance/README.md`](docs/compliance/README.md).

## ⚠️ TRƯỚC KHI hiện thực logic ký/kiểm tra chặt

**Phụ lục I** (tiêu chuẩn kỹ thuật) và **Phụ lục II** (yêu cầu hợp lệ chứng thư)
của TT 15/2025 PHẢI được đọc từ **bản gốc**:

> https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf

và điền vào `data/compliance/appendix_I.yaml` + `appendix_II.yaml` (đổi
`status: filled`). **KHÔNG suy đoán** thuật toán / độ dài khoá / định dạng.

Cơ chế **fail-safe**: khi hai phụ lục chưa điền, `core/trust/policy.py` **từ
chối** mọi kiểm tra "chặt" theo Phụ lục (trả `POLICY_NOT_CONFIGURED`) — cố ý, để
không tạo ra kết luận sai về pháp lý.

---

## Nguyên lý gốc — BA TRỤC ĐỘC LẬP

| Trục | Ý nghĩa | Xác định bằng | Module |
|------|---------|---------------|--------|
| **1 — MODULE** | File ta nạp (dlopen/LoadLibrary) — *cách nạp* | tên file / `vendor_intel.yaml` | `core/platform`, `core/discovery`, `core/bridge` |
| **2 — CHIP** | Phần cứng thật trong token | `C_GetTokenInfo().manufacturerID` | (đọc token — giai đoạn sau) |
| **3 — CA** | Bên phát hành chứng thư | **chain building** tới NEAC Root | `core/trust` |

**Ba trục KHÔNG suy ra được nhau.** Đặc biệt: **TUYỆT ĐỐI KHÔNG nhận diện CA
bằng regex** trên chuỗi Issuer — Việt Nam có 26 CA công cộng, danh sách biến
động; regex sai về nguyên tắc và không có giá trị pháp lý. **Nhận diện CA =
chain building bằng mật mã.**

## Module HAI NHÁNH (TRỤC 1)

- **Track A — theo CHIP**: `eTPKCS11.dll`, `libcastle.so`, `WDPKCS.dll`,
  `aetpkss1.dll`, `opensc-pkcs11.so`…
- **Track B — CA REBRAND**: `/usr/lib/fptca_v4.so` (**ĐÃ XÁC NHẬN**, gói dpkg
  `fptca-4.0`). Hệ thống chỉ quét Track A sẽ **KHÔNG BAO GIỜ** dò ra FPT-CA trên
  Linux.

**Bảng vàng tách khỏi code**: dữ liệu ở `data/vendor_intel.yaml`, nạp qua
`core/intel.py` (validate schema + index + ghi đè qua `VN_TOKEN_INTEL_FILE` và
file người dùng ở `config_dir`). Mức tin cậy: `confirmed` (từ token/bộ cài thật)
› `documented` (tên điển hình, khác theo phiên bản) › `hypothesis` (**chưa biết
tên file — filenames RỖNG**, để Tầng 4 tự dò bằng glob + `C_GetInfo`). 25 CA công
cộng còn lại là `hypothesis` — **tuyệt đối không hard-code tên file đoán mò**.

```bash
python -m core.intel --list --os linux --track B   # xem bảng vàng đã lọc
```

**Phát hiện 4 tầng** (`core/discovery.py`) — triết lý *hỏi hệ điều hành, đừng
đoán tên file*:

1. **`discover_from_system`** (confirmed) — dpkg/rpm/Registry/apps (chính xác nhất).
2. **`discover_from_user_config`** (confirmed) — p11-kit, NSS.
3. **`vendor_intel.yaml`** — Track A/B theo tên file (entry `hypothesis` KHÔNG
   quét bằng tên, chỉ cấp glob_hints).
4. **Glob rộng + xác thực `C_GetInfo`** trong **tiến trình con cô lập** (module
   rác không làm sập daemon) → tự phát hiện module Track B của 25 CA chưa biết
   tên file; `cryptokiVersion` hợp lệ mới nhận.

Lệch kiến trúc chỉ **đánh cờ** `needs_arch_bridge` (không loại bỏ). Không ra
module → chẩn đoán theo thứ tự xác suất (lệch arch → chưa cài middleware → PC/SC
→ udev/plugdev → Rosetta/quarantine → cần login).

**Arch bridge dùng chung** (`core/bridge/`) — khi module lệch kiến trúc, spawn
helper cùng arch (Win python/exe 32-bit · mac `arch -x86_64` Rosetta · Linux
Python 32-bit i386 multilib) và giao tiếp JSON-RPC (`get_info`/`enumerate_tokens`/
`read_certs`/`sign`; PIN là trường **nhạy cảm — loại khỏi mọi log**). `BridgeManager`
lo spawn lười, tự restart, timeout, kill sạch, remediation đúng OS. Tầng trên gọi
**thống nhất** qua `ModuleSession`: in-process (cùng arch) hay bridge (lệch arch)
đều trả `TokenInfo`/`CertInfo` **y hệt** (cùng chạy `core/pkcs11_ops`).

## Quy tắc kiến trúc bất khả xâm phạm

> Mọi `if platform.system() == ...` **CHỈ** nằm trong `core/platform/`.

Được **kiểm tra tự động** bởi `tests/test_architecture_invariant.py`.

---

## Cấu trúc monorepo

```
vn-esign-suite/
├── core/
│   ├── models.py          # pydantic: ModuleCandidate, TokenInfo, CAInfo, ValidationResult...
│   ├── discovery.py       # phát hiện module Track A/B (vendor_intel-driven)
│   ├── engine.py          # facade OS-agnostic
│   ├── config.py          # định vị data/, nạp YAML
│   ├── errors.py          # ngoại lệ + ErrorCode
│   ├── platform/          # === NƠI DUY NHẤT chứa tri thức OS ===
│   │   ├── base.py        # PlatformAdapter (ABC) + parse PE/Mach-O/ELF
│   │   ├── windows.py · macos.py · linux.py
│   │   └── __init__.py    # get_adapter() — điểm rẽ nhánh OS DUY NHẤT
│   ├── bridge/            # arch bridge (JSON-RPC) — chung Win 32-bit & mac Rosetta
│   ├── trust/             # ← TRỌNG TÂM PHÁP LÝ
│   │   ├── anchors.py     # kho neo tin cậy (NEAC + 26 CA)
│   │   ├── chain.py       # chain building (nhận diện CA bằng mật mã)
│   │   ├── revocation.py  # CRL/OCSP + ảnh chụp bằng chứng
│   │   ├── policy.py      # Phụ lục I/II + guard fail-safe
│   │   └── validator.py   # -> ValidationResult (bằng chứng pháp lý)
│   └── esign/             # kết nối Cổng eSign
├── data/
│   ├── trust_store/       # chứng thư NEAC + 26 CA (nạp thủ công, xác minh vân tay)
│   ├── vendor_intel.yaml  # bảng Track A/B
│   └── compliance/        # appendix_I.yaml + appendix_II.yaml (PHẢI điền từ bản gốc)
├── service/ · web/ · tools/ · packaging/ · tests/
└── docs/compliance/       # bảng ánh xạ Điều 5/6 TT 15/2025 → module
```

## `PlatformAdapter` — hợp đồng mỗi OS

`name`, `host_arch` (bits/machine/**rosetta**), `library_search_paths`,
`discover_from_system`, `discover_from_user_config`, `glob_patterns`,
`check_binary_arch`, `needs_arch_bridge`, `spawn_bridge_helper`,
`pcsc_backend_ready`, `certstore_fallback`, `config_dir`, `log_dir`,
`service_install_hint`. Factory `get_adapter()`.

## Bảng khác biệt 3 OS

| Khía cạnh | Windows | macOS (Intel & Apple Silicon) | Linux |
|---|---|---|---|
| Đuôi module | `.dll` | `.dylib` (OpenSC vẫn `.so`) | `.so`, `.so.*` |
| Khám phá | Registry | `system_profiler`, tokend | `p11-kit list-modules` |
| Header native | PE | Mach-O / fat (lipo) | ELF |
| Lệch arch điển hình | 64↔32-bit | arm64↔x86_64 (Rosetta 2) | arm64↔x86_64 (qemu/box64) |
| PC/SC | WinSCard (SCardSvr) | CryptoTokenKit | pcscd |
| Fallback cert | CertStore MY | Keychain | NSS DB |
| Chạy nền | Windows Service | launchd | systemd |
| config_dir | `%APPDATA%` | `~/Library/Application Support` | `$XDG_CONFIG_HOME` |

---

## Bắt đầu nhanh

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

python -m core.platform --diagnose   # chẩn đoán OS/arch/module/PC/SC (per-OS)
python -m core.discovery --scan --verbose   # quét module 4 tầng (Tầng 4: C_GetInfo)
python -m tools.diagnose             # (bí danh của --diagnose)
python -m service.main            # daemon http://127.0.0.1:8787
cd web && npm install && npm run dev   # UI http://localhost:5173

pytest                            # gồm test chain building + guard pháp lý
```

## Trạng thái hiện tại (scaffolding)

- ✅ Cô lập OS, phát hiện module Track A/B, arch bridge (JSON-RPC), chain building
  mật mã, CRL/OCSP, `ValidationResult` lưu bằng chứng, guard Phụ lục fail-safe.
- ⏳ **Chưa** có: đọc token (TRỤC 2), logic ký/gắn dấu thời gian (chờ Phụ lục I),
  endpoint Cổng eSign chính thức, nạp chứng thư NEAC + 26 CA vào `data/trust_store/`.

## Giấy phép

Proprietary — dự án cấp quốc gia.
