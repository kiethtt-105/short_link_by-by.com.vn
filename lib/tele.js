// Telegram: toàn bộ phần gửi tin nằm ở file này.
//  • teleOp(): được logOp (core.js) gọi cho MỌI thao tác ghi nhật ký → mỗi thao tác một tin.
//  • alertOnce/claimAlert/notify: các cảnh báo riêng (hết lượt, đột biến, báo cáo, tổng hợp hằng ngày) dùng chung.
// Cần biến môi trường TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID. Tắt bớt thao tác ồn ào: Cài đặt → «Telegram: thao tác KHÔNG báo».
import { sql, init, getSettings } from "./core.js";

export const telegramOn = () => !!((process.env.TELEGRAM_BOT_TOKEN || "").trim() && (process.env.TELEGRAM_CHAT_ID || "").trim());

export async function notify(text) {
  if (!telegramOn()) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN.trim()}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(4000),
      body: JSON.stringify({ chat_id: process.env.TELEGRAM_CHAT_ID.trim(), text: String(text).slice(0, 3500), disable_web_page_preview: true }),
    });
    return r.ok;
  } catch { console.error("telegram lỗi"); return false; } // không in lỗi gốc: URL chứa token
}

// "Giành quyền" gửi cảnh báo (link, loại): true nếu trong `cooldownHours` vừa qua chưa gửi. Upsert có điều kiện nên hai lượt chạy song song không gửi trùng.
export async function claimAlert(code, kind, cooldownHours = 87600) {
  if (!telegramOn()) return false;
  try {
    await init();
    const r = await sql`INSERT INTO alerts(code, kind) VALUES (${code}, ${kind})
      ON CONFLICT (code, kind) DO UPDATE SET ts = now()
      WHERE alerts.ts < now() - make_interval(hours => ${cooldownHours}::int) RETURNING 1`;
    return r.length > 0;
  } catch (e) { console.error("claimAlert lỗi:", e.message); return false; }
}
// Gửi Telegram thất bại thì trả lại quyền để lần sau còn được báo (trước đây mất cảnh báo vĩnh viễn)
export async function releaseAlert(code, kind) {
  try { await sql`DELETE FROM alerts WHERE code = ${code} AND kind = ${kind}`; } catch {}
}
// Gửi tối đa một lần cho mỗi (link, loại) trong `cooldownHours`.
export async function alertOnce(code, kind, text, cooldownHours = 87600) {
  if (!(await claimAlert(code, kind, cooldownHours))) return false;
  const ok = await notify(text);
  if (!ok) await releaseAlert(code, kind);
  return ok;
}

/* ───────── Báo mọi thao tác ───────── */
const OPS = {
  create: ["🆕", "Tạo link mới"], click: ["👆", "Lượt bấm link"], scan: ["📷", "Lượt quét QR"], bot_click: ["🤖", "Bot / xem trước link"],
  not_found: ["❓", "Mở link không tồn tại"], expired_click: ["⌛", "Mở link hết hạn / hết lượt"], disabled_click: ["🔒", "Mở link đã khoá"],
  wrong_password: ["🔑", "Nhập sai mật khẩu link"], create_failed: ["⚠️", "Tạo link thất bại"], rate_limited: ["🚦", "Vượt giới hạn tạo link"],
  captcha_failed: ["🧩", "Xác minh chống spam thất bại"], blocked_domain: ["⛔", "Tên miền bị chặn"], unsafe_url: ["☣️", "Link không an toàn (đã chặn)"],
  auth_failed: ["🔐", "API key không hợp lệ"], qr_failed: ["⚠️", "Tạo mã QR thất bại"],
  admin_login: ["✅", "Đăng nhập quản trị"], admin_auth_failed: ["🚨", "Đăng nhập quản trị SAI mật khẩu"], admin_revoke_all: ["🚨", "Đã đăng xuất MỌI phiên quản trị"],
  link_delete: ["🗑️", "Xoá link"], link_disable: ["🔒", "Khoá link"], link_enable: ["🔓", "Mở khoá link"], link_update: ["✏️", "Sửa link"],
  settings_update: ["⚙️", "Cập nhật cài đặt"], purge: ["🧹", "Dọn nhật ký"], sync_create: ["🔁", "Tạo mã khôi phục"], sync_restore: ["♻️", "Khôi phục lịch sử"],
};
// report và watch đã có tin riêng (🚩 báo cáo, 📋 tổng hợp hằng ngày) nên không báo lại ở đây
const SELF_NOTIFIED = new Set(["report", "watch"]);
// Chống dội tin: tối đa 15 tin / phút / instance cho thao tác thường; thao tác quản trị & bảo mật luôn được gửi
const CRITICAL = new Set(["admin_login", "admin_auth_failed", "admin_revoke_all", "auth_failed", "link_delete", "link_disable", "link_enable", "link_update", "settings_update", "unsafe_url"]);
let win = { t: 0, n: 0 };
function allow(action) {
  if (CRITICAL.has(action)) return true;
  const now = Date.now();
  if (now - win.t > 60000) win = { t: now, n: 0 };
  return ++win.n <= 15;
}

export async function teleOp(c, { action, code = null, status = 200, detail = "" }) {
  try {
    if (!telegramOn() || SELF_NOTIFIED.has(action)) return false;
    const skip = (await getSettings()).tele_skip.split(",");
    if (skip.includes(action) || !allow(action)) return false;
    const [icon, label] = OPS[action] || ["•", action];
    const m = c.meta || {};
    const base = (process.env.BASE_URL || "").trim().replace(/\/+$/, "") || (m.host ? `https://${m.host}` : "");
    const place = [c.city, c.country].filter(Boolean).join(", ");
    const dev = [c.device, c.browser, c.os].filter(Boolean).join(" · ");
    const lines = [`${icon} ${label}`,
      code && `Link: ${base}/${code}`,
      detail && `Chi tiết: ${String(detail).slice(0, 300)}`,
      c.ip && `IP: ${c.ip}${place ? " (" + place + ")" : ""}`,
      dev && `Thiết bị: ${dev}`,
      `Mã: ${status} · ${new Date().toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh" })}`];
    return await notify(lines.filter(Boolean).join("\n"));
  } catch (e) { console.error("teleOp lỗi:", e.message); return false; }
}
