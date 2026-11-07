// Gắn vào Google Sheet: Tiện ích mở rộng → Apps Script → dán code này.
// Project Settings → Script properties → thêm TOKEN (trùng SHEET_TOKEN trên Vercel, nên dài và ngẫu nhiên).
// Deploy → New deployment → Web app → Execute as: Me, Who has access: Anyone.
// Sửa code xong phải Deploy → Manage deployments → Edit → New version thì Vercel mới nhận bản mới.
const HEADERS = ["time", "action", "code", "ip", "user_agent", "referrer", "status", "detail"];
const MAX_CELL = 2000;

const out = (s) => ContentService.createTextOutput(s);

// Vercel gửi giờ dạng UTC ISO; đổi sang giờ Việt Nam cho dễ đọc
function toVnTime(s) {
  const d = new Date(s);
  return isNaN(d) ? s : Utilities.formatDate(d, "Asia/Ho_Chi_Minh", "yyyy-MM-dd HH:mm:ss");
}

function doPost(e) {
  let body;
  try {
    body = JSON.parse(e.postData.contents);
  } catch (_) {
    return out("bad request");
  }
  const token = PropertiesService.getScriptProperties().getProperty("TOKEN");
  if (!token || !body || body.token !== token) return out("forbidden");
  if (!Array.isArray(body.row) || body.row.length !== HEADERS.length) return out("bad row");

  const row = body.row.map((v) => (v === null || v === undefined ? "" : String(v).slice(0, MAX_CELL)));
  row[0] = toVnTime(row[0]);

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(20000)) return out("busy");
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sh = ss.getSheetByName("logs") || ss.insertSheet("logs");
    if (sh.getLastRow() === 0) {
      sh.appendRow(HEADERS);
      sh.setFrozenRows(1);
    }
    // Định dạng ô là văn bản thuần ("@"): Sheet không tự đổi chuỗi thành ngày/số
    // và không chạy công thức nếu nội dung bắt đầu bằng = + - @ (nên không cần thêm dấu ').
    const r = sh.getLastRow() + 1;
    sh.getRange(r, 1, 1, HEADERS.length).setNumberFormat("@").setValues([row]);
  } finally {
    lock.releaseLock();
  }
  return out("ok");
}

// Chạy THỬ trong trình soạn thảo: chọn hàm testLog ở ô cạnh nút "Chạy" (đừng chạy doPost trực tiếp,
// vì doPost chỉ chạy khi có request từ Vercel). Thành công thì tab "logs" có 1 dòng "ping".
function testLog() {
  const e = { postData: { contents: JSON.stringify({
    token: PropertiesService.getScriptProperties().getProperty("TOKEN"),
    row: [new Date().toISOString(), "ping", "", "", "", "", "200", "hello"],
  }) } };
  Logger.log(doPost(e).getContent());
}
