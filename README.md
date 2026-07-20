# vn-esign-suite

Phần mềm ký số và kiểm tra chữ ký số trên USB token, chạy trên Windows, macOS
(Intel và Apple Silicon) và Linux với cùng một mã nguồn lõi.

Đây là "phần mềm ký số" và "phần mềm kiểm tra chữ ký số" theo Điều 17 Nghị định
23/2025/NĐ-CP và Thông tư 15/2025/TT-BKHCN, nên phần lớn hành vi là yêu cầu pháp
lý chứ không phải lựa chọn kỹ thuật. Bảng đối chiếu từng điều khoản với module và
test nằm ở [`docs/compliance/`](docs/compliance/README.md).

## Kiến trúc

### Ba trục độc lập

Nhầm lẫn giữa "module nào được nạp", "chip nào trong token" và "CA nào cấp chứng
thư" là nguồn lỗi phổ biến nhất khi làm việc với token của các CA Việt Nam. Hệ
thống tách bạch ba câu hỏi này và không suy ra trục nọ từ trục kia.

| Trục | Câu hỏi | Cách xác định |
|------|---------|---------------|
| Module | Ta nạp file `.dll`/`.dylib`/`.so` nào? | tên file, `data/vendor_intel.yaml` |
| Chip | Phần cứng thật trong token là gì? | `C_GetTokenInfo().manufacturerID` |
| CA | Ai cấp chứng thư? | dựng chuỗi chứng thư tới gốc NEAC |

CA được xác định bằng chain building (mật mã), không bằng regex trên chuỗi
Issuer. Danh sách CA công cộng thay đổi theo thời gian và nhiều CA dùng tên gần
giống nhau (CA2, I-CA, SmartSign là ba đơn vị khác nhau), nên so khớp chuỗi vừa
sai vừa không có giá trị pháp lý. `tests/test_regression_matrix.py` khoá lại kết
luận này.

### Cô lập hệ điều hành

Toàn bộ tri thức phụ thuộc OS nằm trong `core/platform/`. Mọi module khác làm việc
qua interface `PlatformAdapter` và factory `get_adapter()`; không nơi nào ngoài
`core/platform/` được gọi `platform.system()`. Ràng buộc này được kiểm tự động
bởi `tests/test_architecture_invariant.py`.

| | Windows | macOS | Linux |
|---|---|---|---|
| Đuôi module | `.dll` | `.dylib` (OpenSC `.so`) | `.so`, `.so.*` |
| Khám phá | Registry | `system_profiler` | `p11-kit` |
| Header native | PE | Mach-O / fat | ELF |
| PC/SC | WinSCard | CryptoTokenKit | pcscd |
| Fallback cert | CertStore MY | Keychain | NSS DB |
| Chạy nền | Service / Task | LaunchAgent | systemd `--user` |

### Phát hiện module

Việc phát hiện đi theo bốn tầng, ưu tiên hỏi hệ điều hành thay vì đoán tên file:

1. Trình quản lý gói và ứng dụng đã cài (`dpkg`/`rpm`/Registry).
2. Cấu hình người dùng (p11-kit, NSS).
3. Bảng `vendor_intel.yaml` — dữ liệu tách khỏi code, có mức tin cậy
   `confirmed`/`documented`/`hypothesis`. Entry `hypothesis` không có tên file
   (không đoán), chỉ cấp gợi ý cho tầng 4.
4. Quét glob rộng rồi xác thực bằng `C_GetInfo` trong tiến trình con cô lập, để
   một module hỏng không làm sập daemon.

Module có hai nhánh: Track A (đặt tên theo chip, ví dụ `eTPKCS11.dll`,
`opensc-pkcs11.so`) và Track B (CA đóng gói lại, ví dụ `fptca_v4.so` từ gói
`fptca-4.0`). Hệ thống chỉ dò Track A sẽ không bao giờ tìm ra FPT-CA trên Linux —
đây là lý do Track B tồn tại.

### Cầu nối kiến trúc

Nhiều middleware chỉ phát hành cho một kiến trúc (DLL 32-bit, dylib x86_64). Khi
module lệch kiến trúc với tiến trình host, `core/bridge/` spawn một helper cùng
kiến trúc (Python/exe 32-bit trên Windows, `arch -x86_64` qua Rosetta trên macOS,
Python i386 trên Linux) và trao đổi qua JSON-RPC trên stdio. Tầng trên gọi qua
`ModuleSession` và nhận kết quả giống nhau bất kể chạy in-process hay qua cầu nối.
PIN là trường nhạy cảm, được loại khỏi mọi log.

## Thành phần

```
core/
  platform/     interface OS + adapter Windows/macOS/Linux
  discovery.py  phát hiện module 4 tầng
  bridge/       cầu nối kiến trúc (JSON-RPC)
  pkcs11_ops.py thao tác PKCS#11 dùng chung (in-process và bridge)
  cert_reader.py, aggregator.py   đọc & gộp chứng thư đa nguồn
  trust/        chain building, CRL/OCSP, chính sách Phụ lục, validator
  signer.py     ký số (chọn cơ chế theo Phụ lục I, CMS, dấu thời gian)
  signature_verify.py   kiểm chữ ký tách rời
  evidence.py   lưu bằng chứng append-only + nhật ký kiểm toán
  esign/        kết nối Cổng eSign (khung, chờ hướng dẫn kỹ thuật)
service/        daemon FastAPI, chỉ nghe 127.0.0.1
web/            giao diện React + TypeScript + Vite
tools/          chẩn đoán, đồng bộ kho tin cậy, thu thập intel thực địa
packaging/      đóng gói Windows/macOS/Linux
data/           kho tin cậy, bảng vendor_intel, dữ liệu tuân thủ
docs/compliance/ đối chiếu điều khoản, DPIA, ma trận kiểm thử
```

Daemon nghe loopback và kiểm Host/Origin để chống DNS rebinding; PIN chỉ tồn tại
trong RAM với thời hạn ngắn và được ghi đè khi hết phiên. Kho bằng chứng dùng
chuỗi băm để phát hiện sửa đổi. Chi tiết bảo mật nằm trong mã và trong
`docs/compliance/`.

## Điều kiện tiên quyết pháp lý

Ba nhóm tham số phải lấy từ văn bản chính thức, không được suy đoán. Khi chưa có,
hệ thống fail-closed: từ chối thay vì đoán.

| Hạng mục | Nguồn | Nếu thiếu |
|---|---|---|
| Phụ lục I — tiêu chuẩn kỹ thuật (thuật toán, độ dài khoá, định dạng) | bản gốc TT 15/2025 | signer từ chối ký |
| Phụ lục II — tiêu chí hợp lệ chứng thư | bản gốc TT 15/2025 | validator không trả VALID |
| Hướng dẫn kỹ thuật kết nối Cổng eSign | NEAC / Bộ KH&CN | gateway từ chối kết nối |

Điền vào `data/compliance/*.yaml` và đặt `status: filled` sau khi đối chiếu bản
gốc. Nguồn: https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf

## Bắt đầu

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

python -m core.platform --diagnose        # chẩn đoán OS/arch/module/PC-SC
python -m core.discovery --scan --verbose # quét module 4 tầng
python -m service.app                      # daemon http://127.0.0.1:8787
cd web && npm install && npm run dev       # giao diện http://localhost:5173

pytest
```

Đóng gói theo từng OS: xem `packaging/README.md`.

## Kiểm thử

231 test chạy được trong CI không cần phần cứng; SoftHSM2 đảm nhiệm token ảo cho
toàn bộ luồng ký. Ma trận đầy đủ (Track × chip × OS × kiến trúc × PIN × trạng
thái chứng thư) ở `docs/compliance/test_matrix.md`. CI dựng trên bốn runner:
`windows-latest`, `macos-14` (arm64), `macos-13` (x86_64), `ubuntu-latest`.

## Trạng thái

Đã hiện thực: cô lập OS, phát hiện module, cầu nối kiến trúc, đọc token và chứng
thư, chain building, CRL/OCSP, kiểm hiệu lực, ký số (CMS) với cổng kiểm hợp lệ
trước khi ký, kiểm chữ ký, lưu bằng chứng, daemon và giao diện web, đóng gói ba
OS.

Chờ văn bản chính thức: điền Phụ lục I và II, hướng dẫn kỹ thuật Cổng eSign, và
nạp chứng thư NEAC cùng các CA công cộng vào `data/trust_store/`. Đến khi đó các
chức năng liên quan giữ trạng thái fail-closed. Bảng chi tiết ở
`docs/compliance/README.md`.

## Giấy phép

[MIT](LICENSE).
