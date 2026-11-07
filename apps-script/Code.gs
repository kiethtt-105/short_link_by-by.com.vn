// Gắn vào Google Sheet: Tiện ích mở rộng → Apps Script → dán code này.
// Project Settings → Script properties → thêm TOKEN (trùng SHEET_TOKEN trên Vercel).
// Deploy → New deployment → Web app → Execute as: Me, Who has access: Anyone.
function doPost(e) {
  const props = PropertiesService.getScriptProperties();
  const body = JSON.parse(e.postData.contents);
  if (!props.getProperty("TOKEN") || body.token !== props.getProperty("TOKEN")) {
    return ContentService.createTextOutput("forbidden");
  }
  // Chặn công thức độc hại: ô bắt đầu bằng = + - @ sẽ được thêm dấu ' phía trước
  const row = body.row.map((v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /^[=+\-@]/.test(s) ? "'" + s : s;
  });

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sh = ss.getSheetByName("logs") || ss.insertSheet("logs");
    if (sh.getLastRow() === 0) {
      sh.appendRow(["time", "action", "code", "ip", "user_agent", "referrer", "status", "detail"]);
    }
    sh.appendRow(row);
  } finally {
    lock.releaseLock();
  }
  return ContentService.createTextOutput("ok");
}
