// Kho dữ liệu = Google Sheet, qua Apps Script web app (apps-script/Code.gs).
// Cần biến môi trường: SHEET_URL (địa chỉ /exec của web app) và SHEET_TOKEN (trùng TOKEN trong Script properties).
const READ_OPS = new Set(["ping", "link_get", "links_list", "links_all", "links_by_codes", "logs_list", "stats", "spark", "reports",
  "settings_get", "recovery_get", "session_check"]); // chỉ thao tác đọc mới được gọi lại khi lỗi mạng (ghi lại có thể bị cộng đôi)

export async function store(op, args = {}) {
  const url = (process.env.SHEET_URL || "").trim(), token = (process.env.SHEET_TOKEN || "").trim();
  if (!url || !token) throw new Error("Thiếu biến môi trường SHEET_URL hoặc SHEET_TOKEN");
  let last;
  for (let i = 0; i < (READ_OPS.has(op) ? 2 : 1); i++) {
    try {
      // Apps Script trả 302 sang script.googleusercontent.com: fetch tự theo; text/plain tránh preflight
      const r = await fetch(url, { method: "POST", redirect: "follow", signal: AbortSignal.timeout(20000),
        headers: { "Content-Type": "text/plain;charset=utf-8" }, body: JSON.stringify({ token, op, args }) });
      const text = await r.text();
      let d;
      try { d = JSON.parse(text); } catch { throw new Error(`Apps Script không trả JSON (HTTP ${r.status}): kiểm tra SHEET_URL và quyền "Anyone"`); }
      if (d && d.error) throw Object.assign(new Error("Sheet: " + d.error), { fatal: true });
      return d;
    } catch (e) { last = e; if (e.fatal) break; }
  }
  throw last;
}
