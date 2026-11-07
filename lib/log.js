import { sql, init } from "./db.js";

export function clientInfo(req) {
  const fwd = req.headers["x-forwarded-for"];
  const ip = (Array.isArray(fwd) ? fwd[0] : fwd || "").split(",")[0].trim() ||
    req.headers["x-real-ip"] || null;
  return {
    ip,
    ua: (req.headers["user-agent"] || "").slice(0, 300),
    ref: (req.headers["referer"] || "").slice(0, 500),
  };
}

async function toSheet(row) {
  const url = process.env.SHEET_WEBHOOK_URL;
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: process.env.SHEET_TOKEN, row }),
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    // Sheet chỉ là bản sao; DB mới là nguồn dữ liệu chính
  }
}

// Ghi 1 thao tác vào DB và Google Sheet. Gọi qua waitUntil() để không làm chậm phản hồi.
export async function logOp(req, { action, code = null, status = 200, detail = "" }) {
  const { ip, ua, ref } = clientInfo(req);
  try {
    await init();
    await sql`INSERT INTO logs(action, code, ip, user_agent, referrer, status, detail)
              VALUES (${action}, ${code}, ${ip}, ${ua}, ${ref}, ${status}, ${String(detail).slice(0, 2000)})`;
  } catch (e) {
    console.error("logOp DB lỗi:", e.message);
  }
  await toSheet([new Date().toISOString(), action, code, ip, ua, ref, status, String(detail).slice(0, 2000)]);
}
