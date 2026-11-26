// Gộp từ log.js + util.js + admin.js + settings.js. Dữ liệu nằm 100% trong Google Sheet (xem store.js, apps-script/Code.gs).
import { timingSafeEqual, createHash, randomBytes } from "node:crypto";
import { waitUntil } from "@vercel/functions";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { teleOp, telegramOn } from "./tele.js"; // Telegram nằm riêng ở tele.js
import { store } from "./store.js";
export { store };

/* ───────── Tiện ích ───────── */
export function baseUrl(req) {
  // trim: biến môi trường dán vào hay dính khoảng trắng/xuống dòng ở cuối
  const b = (process.env.BASE_URL || "").trim();
  if (b) return b.replace(/\/+$/, "");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `https://${host}`;
}

// So theo độ dài BYTE (so theo số ký tự sẽ làm timingSafeEqual ném lỗi khi có ký tự không phải ASCII)
export const same = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/* ───────── Giới hạn tốc độ (RAM của từng instance Vercel: không cần database, nhưng chỉ chặn được trong phạm vi một instance) ───────── */
const hits = new Map();
const trim = (a, now, win) => { while (a.length && now - a[0] >= win) a.shift(); return a; };
// Ghi một lượt gọi và trả true nếu `ip` đã vượt `limit` lượt trong `windowMs` (mặc định 1 phút) ở nhóm `bucket`.
export function hit(bucket, ip, limit, windowMs = 60000) {
  if (!ip || !(limit > 0)) return false;
  const now = Date.now(), k = bucket + "|" + ip, a = trim(hits.get(k) || [], now, windowMs);
  a.push(now); hits.set(k, a);
  if (hits.size > 5000) for (const [kk, v] of hits) if (!v.length || now - v[v.length - 1] > 600000) hits.delete(kk);
  return a.length > limit;
}
export const hitCount = (bucket, ip, windowMs = 60000) => trim(hits.get(bucket + "|" + ip) || [], Date.now(), windowMs).length;

/* ───────── Đọc link (có nhớ ngắn trong RAM để chuyển hướng nhanh) ───────── */
const LINKS = new Map(), MISS = new Map();
// fresh: bỏ qua bộ nhớ; neg: nhớ 10 giây kết quả "không tồn tại" (chống quét mã bịa làm nghẽn Sheet)
export async function getLink(code, o = {}) {
  const now = Date.now();
  if (!o.fresh) {
    const c = LINKS.get(code);
    if (c && now - c.t < 20000) return c.l;
    if (o.neg && now - (MISS.get(code) || 0) < 10000) return null;
  }
  const { link } = await store("link_get", { code });
  if (link) { LINKS.set(code, { t: now, l: link }); MISS.delete(code); if (LINKS.size > 500) LINKS.delete(LINKS.keys().next().value); }
  else if (o.neg) { MISS.set(code, now); if (MISS.size > 500) MISS.delete(MISS.keys().next().value); }
  return link;
}
export const dropLink = (code) => { LINKS.delete(code); MISS.delete(code); };

/* ───────── Chống bot (Cloudflare Turnstile) và link độc hại (Google Safe Browsing) ───────── */
export const turnstileOn = () => !!(process.env.TURNSTILE_SECRET || "").trim();

export async function verifyTurnstile(token, ip) {
  const secret = (process.env.TURNSTILE_SECRET || "").trim();
  if (!secret) return true;
  if (typeof token !== "string" || !token || token.length > 2048) return false;
  try {
    const body = new URLSearchParams({ secret, response: token });
    if (ip) body.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST", body, signal: AbortSignal.timeout(4000),
    });
    return (await r.json()).success === true;
  } catch (e) {
    console.error("turnstile lỗi:", e.message);
    return false;
  }
}

// Trả về loại mối đe doạ (vd "SOCIAL_ENGINEERING") hoặc null. Lỗi mạng/quota thì cho qua để không chặn nhầm người dùng.
export async function unsafeThreat(url) {
  const key = (process.env.SAFE_BROWSING_KEY || "").trim();
  if (!key) return null;
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(3000),
      body: JSON.stringify({
        client: { clientId: "short-link", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }],
        },
      }),
    });
    if (!r.ok) { console.error("safe browsing HTTP", r.status); return null; }
    const d = await r.json();
    return d.matches?.[0]?.threatType || null;
  } catch (e) {
    console.error("safe browsing lỗi:", e.message);
    return null;
  }
}

/* ───────── Nhật ký ───────── */
// Nhận diện thiết bị / trình duyệt / bot từ User-Agent (không cần thư viện ngoài)
export function parseUA(ua = "") {
  const is_bot = !ua || /(?<!cu)bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|discord|slack|curl|wget|python-requests|python-urllib|axios|node-fetch|go-http|java\/|okhttp|headless|lighthouse|pingdom|uptime|scrapy|httpclient/i.test(ua);
  const os = /windows/i.test(ua) ? "Windows" : /android/i.test(ua) ? "Android" : /iphone|ipad|ipod/i.test(ua) ? "iOS"
    : /mac os x|macintosh/i.test(ua) ? "macOS" : /cros/i.test(ua) ? "ChromeOS" : /linux/i.test(ua) ? "Linux" : "";
  const browser = /fban|fbav/i.test(ua) ? "Facebook (in-app)" : /instagram/i.test(ua) ? "Instagram (in-app)" : /zalo/i.test(ua) ? "Zalo (in-app)"
    : /edg(e|a|ios)?\//i.test(ua) ? "Edge" : /opr\/|opera/i.test(ua) ? "Opera" : /coc_coc/i.test(ua) ? "Cốc Cốc"
    : /samsungbrowser/i.test(ua) ? "Samsung Internet" : /firefox|fxios/i.test(ua) ? "Firefox"
    : /chrome|crios/i.test(ua) ? "Chrome" : /safari/i.test(ua) ? "Safari" : "";
  const device = is_bot ? "Bot" : /ipad|tablet/i.test(ua) ? "Tablet" : /mobi|iphone|android/i.test(ua) ? "Mobile" : "Desktop";
  return { is_bot, os, browser, device };
}

// Mọi thông tin máy chủ thấy được trong request: IP, vị trí (header của Vercel), thiết bị, ngôn ngữ, client hints, đường dẫn, mã request...
export function clientInfo(req) {
  const hd = req.headers || {};
  const one = (k, n = 200) => String(Array.isArray(hd[k]) ? hd[k][0] : hd[k] ?? "").slice(0, n);
  const dec = (v) => { try { return decodeURIComponent(v); } catch { return v; } };
  const ip = one("x-forwarded-for").split(",")[0].trim() || one("x-real-ip") || null;
  const ua = one("user-agent", 300);
  const meta = {
    lang: one("accept-language", 100), region: one("x-vercel-ip-country-region", 20), tz: one("x-vercel-ip-timezone", 60),
    lat: one("x-vercel-ip-latitude", 20), lon: one("x-vercel-ip-longitude", 20),
    ch_ua: one("sec-ch-ua"), ch_platform: one("sec-ch-ua-platform", 30), ch_mobile: one("sec-ch-ua-mobile", 5),
    fetch_site: one("sec-fetch-site", 20), fetch_mode: one("sec-fetch-mode", 20), fetch_dest: one("sec-fetch-dest", 20),
    host: one("x-forwarded-host", 100) || one("host", 100), proto: one("x-forwarded-proto", 10), method: req.method,
    path: String(req.url || "").slice(0, 500), dnt: one("dnt", 3), req_id: one("x-vercel-id", 100),
  };
  for (const k of Object.keys(meta)) if (!meta[k]) delete meta[k];
  return { ip, ua, ref: one("referer", 500), country: one("x-vercel-ip-country", 2) || null,
    city: dec(one("x-vercel-ip-city", 100)) || null, ...parseUA(ua), meta };
}

// Dòng nhật ký gửi sang Sheet
export function logRow(req, { action, code = null, status = 200, detail = "" }) {
  const c = clientInfo(req);
  return { ts: new Date().toISOString(), action, code, ip: c.ip, user_agent: c.ua, referrer: c.ref, status, detail: String(detail).slice(0, 2000),
    country: c.country, city: c.city, device: c.device, browser: c.browser, os: c.os, is_bot: c.is_bot, meta: c.meta };
}
export async function logOp(req, o) {
  const c = clientInfo(req);
  console.log(JSON.stringify({ action: o.action, code: o.code ?? null, status: o.status ?? 200, ip: c.ip, country: c.country, device: c.device, bot: c.is_bot })); // hiện ở Vercel → Logs
  try { await store("log_add", { log: logRow(req, o) }); } catch (e) { console.error("logOp Sheet lỗi:", e.message); }
  if (telegramOn()) waitUntil(teleOp(c, { action: o.action, code: o.code ?? null, status: o.status ?? 200, detail: o.detail ?? "" }));
}
// Gọi không chặn phản hồi
export const log = (req, o) => waitUntil(logOp(req, o));
export const bg = (p) => waitUntil(p); // việc phụ chạy sau khi đã trả lời

/* ───────── Quản trị: ADMIN_KEY qua header x-admin-key, phiên lưu ở tab sessions ───────── */
export const ADMIN_MAX_SESSIONS = 2; // số thiết bị được đăng nhập cùng lúc
const SESSION_DAYS = 30;
// Sai quá 10 lần / 10 phút từ cùng IP thì tạm khoá IP đó (đếm trong RAM của instance).
export async function requireAdmin(req, res) {
  res.setHeader("Cache-Control", "no-store"); // dữ liệu quản trị (IP, nhật ký) không được cache
  const admin = (process.env.ADMIN_KEY || "").trim();
  if (!admin) {
    res.status(503).json({ error: "Hệ thống chưa được cấu hình mật khẩu quản trị" });
    return false;
  }
  const sess = String(req.headers["x-admin-session"] || "");
  if (sess) {
    const r = await store("session_check", { id: sha256(sess), days: SESSION_DAYS });
    if (r.ok) return true;
    if (r.expired) res.status(401).json({ error: "Phiên đăng nhập đã hết hạn (30 ngày), hãy đăng nhập lại.", code: "session_expired" });
    else res.status(401).json({ error: "Phiên đăng nhập không còn hiệu lực (đã đăng xuất hoặc bị đăng xuất tất cả). Hãy đăng nhập lại.", code: "session_replaced" });
    return false;
  }
  const { ip } = clientInfo(req);
  if (ip && hitCount("admin_fail", ip, 600000) >= 10) {
    res.status(429).json({ error: "Nhập sai quá nhiều lần, thử lại sau 10 phút" });
    return false;
  }
  if (!same(String(req.headers["x-admin-key"] || ""), admin)) {
    hit("admin_fail", ip, 1e9, 600000);
    log(req, { action: "admin_auth_failed", status: 401 });
    res.status(401).json({ error: "Sai mật khẩu" });
    return false;
  }
  // Đăng nhập mới (kèm x-admin-login): tối đa ADMIN_MAX_SESSIONS phiên. Lần thứ 3 (khi đã đủ) → đăng xuất TẤT CẢ, kể cả lần này.
  if (req.headers["x-admin-login"] === "1") {
    const token = randomBytes(32).toString("hex"), ua = clientInfo(req).ua;
    const r = await store("session_login", { id: sha256(token), ip, ua, max: ADMIN_MAX_SESSIONS, days: SESSION_DAYS });
    if (r.full) {
      await logOp(req, { action: "admin_revoke_all", status: 409, detail: `Đăng nhập thứ ${ADMIN_MAX_SESSIONS + 1}: đã đăng xuất mọi phiên` });
      res.status(409).json({ error: `Đã có ${ADMIN_MAX_SESSIONS} thiết bị đang đăng nhập. Để an toàn, tất cả phiên (kể cả lần này) đã bị đăng xuất. Hãy đăng nhập lại.`, code: "sessions_full" });
      return false;
    }
    res.setHeader("x-admin-session", token);
    log(req, { action: "admin_login", status: 200 });
  }
  return true;
}
export const sha256 = (t) => createHash("sha256").update(t).digest("hex");

/* ───────── Cài đặt (Sheet, tab config > biến môi trường > mặc định) ───────── */
// Cài đặt QUAN TRỌNG (SHEET_URL, SHEET_TOKEN, ADMIN_KEY, API_KEY, BASE_URL) chỉ nằm ở biến môi trường Vercel.
const isHex = (v) => /^#[0-9a-f]{6}$/.test(v);
const isInt = (min, max) => (v) => /^\d+$/.test(v) && Number(v) >= min && Number(v) <= max;
const oneOf = (...o) => (v) => o.includes(v);
const domainList = (v) =>
  v.length <= 2000 && v.split(",").filter(Boolean).every((d) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d));

export const SCHEMA = {
  qr_foreground: {
    env: "QR_FOREGROUND", def: "#000000", type: "color", label: "Màu mã QR",
    norm: (v) => v.toLowerCase(), check: isHex,
  },
  qr_background: {
    env: "QR_BACKGROUND", def: "#ffffff", type: "color", label: "Màu nền QR",
    norm: (v) => v.toLowerCase(), check: isHex,
  },
  qr_size: {
    env: "QR_SIZE", def: "512", type: "int", min: 128, max: 2048, label: "Kích thước QR (px)",
    norm: (v) => v, check: isInt(128, 2048), cast: Number,
  },
  qr_margin: {
    env: "QR_MARGIN", def: "4", type: "int", min: 0, max: 10, label: "Viền quanh mã QR (số ô)",
    hint: "Nên để 4. Viền hẹp hơn dễ bị khung ảnh che, làm mã khó quét",
    norm: (v) => v, check: isInt(0, 10), cast: Number,
  },
  qr_error_level: {
    env: "QR_ERROR_LEVEL", def: "M", type: "enum", options: ["L", "M", "Q", "H"],
    label: "Mức sửa lỗi QR", hint: "Mức H quét được cả khi mã bị trầy xước, nhưng mã sẽ dày đặc hơn",
    norm: (v) => v.toUpperCase(), check: oneOf("L", "M", "Q", "H"),
  },
  qr_format: {
    env: "QR_FORMAT", def: "svg", type: "enum", options: ["svg", "png"], label: "Định dạng QR mặc định",
    norm: (v) => v.toLowerCase(), check: oneOf("svg", "png"),
  },
  code_length: {
    env: "CODE_LENGTH", def: "5", type: "int", min: 4, max: 10, label: "Độ dài mã link ngắn",
    hint: "Chỉ áp dụng cho link tạo sau này. Chỉ 5 ký tự đã có hơn 650 triệu mã khác nhau",
    norm: (v) => v, check: isInt(4, 10), cast: Number,
  },
  rate_limit_per_min: {
    env: "RATE_LIMIT_PER_MIN", def: "30", type: "int", min: 0, max: 10000,
    label: "Số link tối đa mỗi IP mỗi phút", hint: "0 = không giới hạn",
    norm: (v) => v, check: isInt(0, 10000), cast: Number,
  },
  log_retention_days: {
    env: "LOG_RETENTION_DAYS", def: "0", type: "int", min: 0, max: 3650,
    label: "Số ngày lưu nhật ký", hint: "0 = giữ vĩnh viễn (khuyên dùng). Sheet chứa tối đa khoảng 600.000 dòng nhật ký. Tự dọn mỗi ngày (cần Vercel Cron)",
    norm: (v) => v, check: isInt(0, 3650), cast: Number,
  },
  redirect_delay_ms: {
    env: "REDIRECT_DELAY_MS", def: "1500", type: "int", min: 0, max: 5000, label: "Trang chờ trước khi chuyển hướng (ms)",
    hint: "Người bấm link thấy trang chờ rồi tự chuyển đến đích. 0 = chuyển ngay, không có trang chờ. Nên để 1000-2000",
    norm: (v) => v, check: isInt(0, 5000), cast: Number,
  },
  tele_skip: {
    env: "TELE_SKIP", def: "bot_click,not_found,click,scan,rate_limited,captcha_failed,wrong_password", type: "text", label: "Telegram: báo những thao tác nào",
    hint: "Danh sách thao tác KHÔNG báo (trang quản trị hiện dạng ô tick). none = báo tất cả",
    norm: (v) => v.toLowerCase().split(/[\s,]+/).filter(Boolean).join(","), check: (v) => v.length <= 500 && /^[a-z_,]*$/.test(v),
    cast: (v) => v,
  },
  alert_expiring_min_days: {
    env: "ALERT_EXPIRING_MIN_DAYS", def: "30", type: "int", min: 0, max: 365,
    label: "Báo sắp hết hạn: chỉ link có hạn từ N ngày trở lên",
    hint: "0 = tắt. Link hạn ngắn (1 giờ, 1 ngày, 7 ngày) do người dùng tự đặt sẽ không báo để khỏi nhiễu. Cần Telegram",
    norm: (v) => v, check: isInt(0, 365), cast: Number,
  },
  alert_spike_clicks: {
    env: "ALERT_SPIKE_CLICKS", def: "50", type: "int", min: 0, max: 100000,
    label: "Báo đột biến khi một link có từng này lượt trong 10 phút",
    hint: "0 = tắt. Cần đặt TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID trong biến môi trường",
    norm: (v) => v, check: isInt(0, 100000), cast: Number,
  },
  blocked_domains: {
    env: "BLOCKED_DOMAINS", def: "bit.ly,tinyurl.com,t.co,goo.gl,cutt.ly,is.gd,rebrand.ly,ow.ly,shorturl.at,rb.gy", type: "text", label: "Tên miền bị chặn",
    hint: "Cách nhau bằng dấu phẩy, vd: bad.com, spam.net (chặn cả tên miền phụ)",
    norm: (v) => v.toLowerCase().split(/[\s,]+/).filter(Boolean).join(","), check: domainList,
    cast: (v) => v,
  },
};

let cache = { at: 0, rows: null };
async function rows() {
  if (cache.rows && Date.now() - cache.at < 60000) return cache.rows;
  cache = { at: Date.now(), rows: (await store("settings_get")).settings || {} };
  return cache.rows;
}

function resolve(key, db) {
  const s = SCHEMA[key];
  for (const [source, raw] of [["db", db[key]], ["env", process.env[s.env]]]) {
    if (raw === undefined || raw === null || String(raw).trim() === "") continue;
    const v = s.norm(String(raw).trim());
    if (s.check(v)) return { value: v, source };
  }
  return { value: s.def, source: "default" };
}

// Giá trị dùng trong code (đã ép kiểu)
export async function getSettings() {
  const db = await rows();
  const out = {};
  for (const [k, s] of Object.entries(SCHEMA)) {
    const { value } = resolve(k, db);
    out[k] = s.cast ? s.cast(value) : value;
  }
  return out;
}

// Dùng cho trang /admin
export async function describeSettings() {
  cache.rows = null;
  const db = await rows();
  const out = {};
  for (const [k, s] of Object.entries(SCHEMA)) {
    const { value, source } = resolve(k, db);
    out[k] = {
      label: s.label, hint: s.hint || "", type: s.type, options: s.options, min: s.min, max: s.max,
      value, source, default: s.def,
    };
  }
  return out;
}

// patch: { key: "giá trị" | null }. null hoặc chuỗi rỗng = xoá khỏi Sheet (quay về env/mặc định).
export async function saveSettings(patch) {
  const errors = [], out = {};
  for (const [k, raw] of Object.entries(patch)) {
    const s = SCHEMA[k];
    if (!s) { errors.push(`Không có cài đặt "${k}"`); continue; }
    if (raw === null || String(raw).trim() === "") { out[k] = null; continue; }
    const v = s.norm(String(raw).trim());
    if (!s.check(v)) { errors.push(`Giá trị không hợp lệ cho "${s.label}"`); continue; }
    out[k] = v;
  }
  if (errors.length) return { errors, changed: {} };
  await store("settings_set", { patch: out });
  cache = { at: 0, rows: null };
  return { errors: [], changed: out };
}

/* ───────── Lấy nội dung trang ngoài, chống SSRF ───────── */
// Chặn IP nội bộ / loopback / link-local / CGNAT / multicast. Địa chỉ lạ thì chặn luôn.
export function isPrivateIp(ip) {
  const v = isIP(ip);
  if (v === 4) {
    const [a, b, c] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0 && c === 0) ||
      (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === "::" || s === "::1") return true;
    if (s.startsWith("::ffff:")) { const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); return m ? isPrivateIp(m[1]) : true; }
    return /^(fc|fd|fe[89ab]|ff)/.test(s) || s.startsWith("64:ff9b:") || s.startsWith("2002:");
  }
  return true;
}

// Phân giải DNS rồi kiểm tra NGAY tại bước kết nối: địa chỉ đã kiểm tra chính là địa chỉ được dùng (chống DNS rebinding)
function guardedLookup(host, opts, cb) {
  const o = opts && typeof opts === "object" ? opts : {};
  dns.lookup(host, { ...o, all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) return cb(new Error("Địa chỉ nội bộ bị chặn"));
    if (o.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

// GET một URL công khai: chỉ http/https, cổng 80/443, theo tối đa `redirects` lần chuyển hướng (kiểm tra lại từng bước),
// đọc tối đa `maxBytes`, tổng thời gian không quá `timeoutMs`. Trả {status, body}.
export function safeGet(href, { maxBytes = 65536, timeoutMs = 4000, redirects = 3, deadline } = {}) {
  deadline ??= Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(href); } catch { return reject(new Error("URL không hợp lệ")); }
    if (!["http:", "https:"].includes(u.protocol)) return reject(new Error("Giao thức không được phép"));
    if (u.username || u.password) return reject(new Error("URL chứa tài khoản"));
    if (!["", "80", "443"].includes(u.port)) return reject(Object.assign(new Error("Cổng không được phép"), { skip: true })); // skip: không phải link chết, chỉ là không kiểm tra được
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) && isPrivateIp(host)) return reject(new Error("Địa chỉ nội bộ bị chặn")); // IP thẳng thì lookup không được gọi
    const left = deadline - Date.now();
    if (left <= 0) return reject(new Error("Hết thời gian"));
    let done = false;
    const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); fn(v); };
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, {
      method: "GET", lookup: guardedLookup,
      headers: { "user-agent": "Mozilla/5.0 (compatible; LinkCheck/1.0)", accept: "text/html,*/*;q=0.5", "accept-encoding": "identity" },
    }, (res) => {
      const st = res.statusCode;
      if ([301, 302, 303, 307, 308].includes(st) && res.headers.location) {
        res.resume();
        if (redirects <= 0) return finish(reject, new Error("Quá nhiều chuyển hướng"));
        let next; try { next = new URL(res.headers.location, u).href; } catch { return finish(reject, new Error("Chuyển hướng lỗi")); }
        return safeGet(next, { maxBytes, timeoutMs, redirects: redirects - 1, deadline }).then((r) => finish(resolve, r), (e) => finish(reject, e));
      }
      const chunks = []; let n = 0;
      const end = () => finish(resolve, { status: st, body: Buffer.concat(chunks).toString("utf8") });
      res.on("data", (c) => { n += c.length; if (n <= maxBytes) chunks.push(c); else { chunks.push(c.subarray(0, Math.max(0, c.length - (n - maxBytes)))); res.destroy(); } });
      res.on("end", end); res.on("close", end); res.on("error", end);
    });
    const timer = setTimeout(() => req.destroy(new Error("Hết thời gian")), left);
    req.on("error", (e) => finish(reject, e));
    req.end();
  });
}

/* ───────── Dọn nhật ký quá hạn ───────── */
export async function purgeLogs() {
  const { log_retention_days: d } = await getSettings();
  return (await store("purge", { days: d })).deleted || 0;
}
