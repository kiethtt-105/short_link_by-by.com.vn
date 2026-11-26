# Chuyển sang Google Sheet 100% (bỏ Neon)

## File trong gói (chép đè vào dự án)
- `api/index.js`, `lib/core.js`, `lib/tele.js`, `lib/store.js` (mới), `terms.html`
- `apps-script/Code.gs`: dán vào Apps Script của Google Sheet, **thay toàn bộ script đồng bộ cũ**

## Các bước
1. **Sheet**: mở Google Sheet hiện có (đang có tab links, logs) → Extensions → Apps Script → xoá code cũ, dán `Code.gs`.
2. Project Settings → Script properties → thêm `TOKEN` = một chuỗi bí mật dài (có thể dùng lại SHEET_TOKEN hiện tại).
3. Chọn hàm `caiDat` → Run → cấp quyền. (Tự xoá lịch đồng bộ cũ, tạo các tab mới, dựng lại tab tong_hop.)
4. Deploy → New deployment → Web app → Execute as **Me**, Who has access **Anyone** → Deploy → copy URL kết thúc bằng `/exec`.
   Sửa code sau này phải Deploy → Manage deployments → Edit → New version (giữ nguyên URL).
5. **Vercel** → Settings → Environment Variables:
   - thêm `SHEET_URL` = URL `/exec` ở bước 4
   - `SHEET_TOKEN` = đúng giá trị `TOKEN` ở bước 2
   - xoá `DATABASE_URL` (và có thể gỡ `@neondatabase/serverless` khỏi package.json)
6. Redeploy. Mở `/health` phải trả `{"ok":true,"db":true}`.

## Dữ liệu cũ
- Tab `links` và `logs` đang có được dùng tiếp (dòng log mới nối tiếp id cũ, số lượt cộng tiếp từ số trong Sheet).
- Số lượt trong tab `links` là số ở lần đồng bộ cuối trước khi Neon hết hạn mức; lượt từ lúc đó đến nay không có.
- Link **có mật khẩu** từ bản cũ không còn mã băm trong Sheet nên bị khoá (410). Tạo lại link, hoặc vào /admin → Sửa → gỡ mật khẩu.
- Tab `settings` cũ không còn dùng (cài đặt nằm ở tab `config`). Cài đặt đã chỉnh trong /admin trước đây nằm ở Neon nên cần chỉnh lại.

## Lưu ý vận hành
- Chuyển hướng: hỏi Sheet lần đầu mất khoảng 0.5-2 giây, sau đó Vercel nhớ link 20 giây. Trang chờ 1.5 giây che phần này.
- Cộng lượt và ghi nhật ký chạy nền; link có giới hạn lượt thì cộng lượt trước khi chuyển (chính xác).
- Giới hạn tốc độ nằm trong RAM từng instance Vercel (không còn bảng rate_hits).
- Nhật ký mặc định giữ vĩnh viễn (Sheet chứa khoảng 600.000 dòng). Cài đặt "Số ngày lưu nhật ký" > 0 sẽ xoá dòng cũ khỏi Sheet.
- Admin: đăng nhập và phiên lưu ở tab `sessions`; không xoá hay sửa tay các tab (trừ khi biết rõ).
