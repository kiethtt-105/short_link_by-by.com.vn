# Rút gọn link tự làm trên Vercel

Vercel (Node) + Neon Postgres (nguồn dữ liệu chính) + Google Sheet (bản sao log, xem bằng mắt).
Mọi thao tác (tạo link, click, quét QR, xem thống kê, đổi cài đặt, lỗi, bị chặn) đều ghi vào bảng `logs`
và thêm một dòng trong Sheet.

## Cấu hình: chia làm hai nhóm

**Quan trọng → biến môi trường Vercel** (Settings → Environment Variables, đổi xong bấm Redeploy):

| Biến | Dùng cho |
|---|---|
| `DATABASE_URL` | kết nối Neon (Vercel tự điền) |
| `ADMIN_KEY` | mật khẩu vào `/admin`, `/api/settings`, `/api/logs` |
| `SHEET_WEBHOOK_URL`, `SHEET_TOKEN` | ghi log sang Google Sheet |
| `API_KEY` (tuỳ chọn) | khoá API tạo link, trống = mở cho mọi người |
| `BASE_URL` (tuỳ chọn) | tên miền ngắn riêng |

**Không quan trọng → trang `/admin`** (nhập `ADMIN_KEY` để mở khoá, lưu trong database, có hiệu lực ngay):
màu / kích thước / viền / mức sửa lỗi / định dạng QR, giới hạn tạo link mỗi IP mỗi phút, danh sách tên miền bị chặn.
Mỗi mục hiện nguồn giá trị (đã chỉnh ở đây, từ biến Vercel, hay mặc định) và có nút "Đặt lại".
Biến môi trường cùng tên (`QR_SIZE`, `RATE_LIMIT_PER_MIN`...) vẫn dùng được như giá trị khởi tạo,
nhưng giá trị chỉnh ở `/admin` luôn được ưu tiên.

Nhập sai mật khẩu quá 10 lần trong 10 phút thì IP đó bị khoá tạm thời, và mỗi lần sai đều được ghi log.

## Triển khai

1. Đẩy thư mục này lên GitHub, rồi vào vercel.com → Add New → Project → chọn repo.
2. Trong project: Storage / Marketplace → thêm **Neon Postgres**. Vercel tự tạo `DATABASE_URL`.
3. Google Sheet:
   - Tạo Sheet mới → Tiện ích mở rộng → Apps Script → dán `apps-script/Code.gs`.
   - Project Settings → Script properties → thêm `TOKEN` = một chuỗi ngẫu nhiên.
   - Deploy → New deployment → Web app → Execute as **Me**, Who has access **Anyone** → copy URL `/exec`.
4. Vercel → Environment Variables: thêm `ADMIN_KEY`, `SHEET_WEBHOOK_URL`, `SHEET_TOKEN`.
5. Deploy. Bảng tự tạo ở request đầu tiên. Mở `https://<domain>/admin` để chỉnh các cài đặt còn lại.

Chạy thử local: `npm i -g vercel && npm i && vercel dev` (kéo biến về bằng `vercel env pull`).

## Dùng

```bash
# Tạo link (thêm -H "x-api-key: ..." nếu bạn đặt API_KEY)
curl -X POST https://<domain>/api/shorten -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/abc","alias":"abc"}'

# Thống kê công khai (không lộ IP)
curl "https://<domain>/api/stats?code=abc"

# Trích log (chỉ admin): lọc theo action, code, thời gian; thêm format=csv để tải file
curl -H "x-admin-key: <ADMIN_KEY>" "https://<domain>/api/logs?action=click&code=abc&limit=500"
curl -H "x-admin-key: <ADMIN_KEY>" "https://<domain>/api/logs?from=2026-11-01&format=csv" -o logs.csv

# Xem / đổi cài đặt bằng API (null = đặt lại)
curl -H "x-admin-key: <ADMIN_KEY>" https://<domain>/api/settings
curl -X PUT -H "x-admin-key: <ADMIN_KEY>" -H "Content-Type: application/json" \
  -d '{"qr_size":"768","qr_foreground":"#1d4ed8","blocked_domains":"bad.com"}' https://<domain>/api/settings
```

Các `action` trong log: `create`, `create_failed`, `blocked_domain`, `rate_limited`, `auth_failed`, `click`, `scan`,
`not_found`, `stats_view`, `qr_view`, `qr_failed`, `settings_update`, `admin_auth_failed`.

## Mã QR

Mỗi link tạo ra có `qr_url` trong phản hồi:

```
https://<domain>/api/qr?code=abc                       # theo cài đặt ở /admin
https://<domain>/api/qr?code=abc&format=png&download=1  # tải PNG
```

QR trỏ tới `<domain>/<code>?src=qr`, nên lượt quét được tính riêng: log có action `scan`, bảng `links` có cột `scans`,
`/api/stats` trả thêm `scans`. Chỉ tạo QR cho link đã tồn tại. Nếu log chỉ ra `click` mà không bao giờ có `scan`,
kiểm tra rewrite trong `vercel.json` có giữ query `src` hay không.

## Hệ thống mở, không giới hạn

Mặc định ai cũng tạo được link, không cần key, không giới hạn tốc độ. Vì vậy cần biết:

- Link rút gọn miễn phí rất hay bị dùng cho lừa đảo và spam. Domain có thể bị trình duyệt gắn cờ,
  và Vercel có thể khoá project vi phạm. Log IP/URL trong DB giúp bạn truy vết; khi thấy tên miền xấu,
  thêm vào "Tên miền bị chặn" ở `/admin`.
- Siết khi cần: giới hạn theo IP ở `/admin`, hoặc đặt `API_KEY` để chỉ người có key mới tạo được.
- Gói Vercel/Neon miễn phí có hạn mức riêng; "không giới hạn" ở đây chỉ là code không tự chặn.
- Log chứa IP người bấm link. Nếu có người dùng ở nước ngoài, nên có thông báo về dữ liệu thu thập.
