// Gộp từ db.js + log.js + util.js + admin.js + settings.js
import { timingSafeEqual, createHash, randomBytes } from "node:crypto";
import { neon } from "@neondatabase/serverless";
import { waitUntil } from "@vercel/functions";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { teleOp, telegramOn } from "./tele.js"; // Telegram nằm riêng ở tele.js

/* ───────── Database ───────── */
const dbUrl = (process.env.DATABASE_URL || "").trim();
// Thiếu DATABASE_URL: không sập lúc import, chỉ báo lỗi rõ ở lần gọi đầu tiên
export const sql = dbUrl ? neon(dbUrl) : Object.assign(() => { throw new Error("Thiếu biến môi trường DATABASE_URL"); }, { transaction: () => { throw new Error("Thiếu biến môi trường DATABASE_URL"); } });

// Migration có phiên bản: mỗi bước chỉ chạy MỘT lần (ghi vào schema_migrations).
// Khởi động nguội chỉ tốn 1 lượt gọi mạng và không còn ALTER TABLE (khoá bảng) mỗi lần.
const MIGRATIONS = [
  [1, () => [
    sql`CREATE TABLE IF NOT EXISTS links (
      code TEXT PRIMARY KEY, url TEXT NOT NULL,
      clicks BIGINT NOT NULL DEFAULT 0, scans BIGINT NOT NULL DEFAULT 0,
      created_ip TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
    sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS scans BIGINT NOT NULL DEFAULT 0`,
    sql`CREATE TABLE IF NOT EXISTS logs (
      id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      action TEXT NOT NULL, code TEXT, ip TEXT, user_agent TEXT, referrer TEXT, status INT, detail TEXT)`,
    sql`ALTER TABLE logs ADD COLUMN IF NOT EXISTS country TEXT, ADD COLUMN IF NOT EXISTS city TEXT,
      ADD COLUMN IF NOT EXISTS device TEXT, ADD COLUMN IF NOT EXISTS browser TEXT, ADD COLUMN IF NOT EXISTS os TEXT,
      ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false, ADD COLUMN IF NOT EXISTS meta JSONB`,
    sql`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
    sql`CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC)`,
    sql`CREATE INDEX IF NOT EXISTS idx_logs_code ON logs(code, action, ts)`,
    sql`CREATE INDEX IF NOT EXISTS idx_logs_ip_action ON logs(ip, action, ts)`,
  ]],
  // v2: khoá link (disabled) + bảng đếm giới hạn tốc độ nhỏ gọn, tách khỏi logs
  [2, () => [
    sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false`,
    sql`CREATE TABLE IF NOT EXISTS rate_hits (bucket TEXT NOT NULL, ip TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL DEFAULT now())`,
    sql`CREATE INDEX IF NOT EXISTS idx_rate_hits ON rate_hits(bucket, ip, ts)`,
  ]],
  // v3: hết hạn, giới hạn lượt, mật khẩu cho link (mật khẩu lưu dạng scrypt + salt)
  [3, () => [
    sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS max_clicks BIGINT,
      ADD COLUMN IF NOT EXISTS pass_hash TEXT, ADD COLUMN IF NOT EXISTS pass_salt TEXT`,
  ]],
  // v4: mã khôi phục lịch sử (chỉ lưu băm của mã), chống gửi trùng cảnh báo, theo dõi link đích chết
  [4, () => [
    sql`CREATE TABLE IF NOT EXISTS recoveries (
      id TEXT PRIMARY KEY, codes JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
    sql`CREATE TABLE IF NOT EXISTS alerts (
      code TEXT NOT NULL, kind TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (code, kind))`,
    sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS last_check TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS last_status INT,
      ADD COLUMN IF NOT EXISTS fail_count INT NOT NULL DEFAULT 0`,
  ]],
];

let ready;
export function init() {
  ready ??= (async () => {
    // Một lượt: tạo bảng phiên bản (nếu chưa có) và đọc phiên bản hiện tại
    const [, [{ v }]] = await sql.transaction([
      sql`CREATE TABLE IF NOT EXISTS schema_migrations (version INT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
      sql`SELECT COALESCE(max(version), 0)::int AS v FROM schema_migrations`,
    ]);
    for (const [version, build] of MIGRATIONS) {
      if (version <= v) continue;
      await sql.transaction([...build(), sql`INSERT INTO schema_migrations(version) VALUES (${version}) ON CONFLICT DO NOTHING`]);
    }
  })().catch((e) => { ready = undefined; throw e; });
  return ready;
}

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

/* ───────── Giới hạn tốc độ (bảng rate_hits riêng, nhẹ hơn đếm trong logs) ───────── */
// Ghi một lượt gọi và trả true nếu IP đã vượt `limit` lượt / phút trong nhóm `bucket`.
export async function hit(bucket, ip, limit) {
  if (!ip || !(limit > 0)) return false;
  const [{ n }] = await sql`WITH i AS (INSERT INTO rate_hits(bucket, ip) VALUES (${bucket}, ${ip}) RETURNING 1)
    SELECT count(*)::int + 1 AS n FROM rate_hits
    WHERE bucket = ${bucket} AND ip = ${ip} AND ts > now() - interval '1 minute'`;
  return n > limit;
}

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

export async function logOp(req, { action, code = null, status = 200, detail = "" }) {
  const c = clientInfo(req);
  console.log(JSON.stringify({ action, code, status, ip: c.ip, country: c.country, device: c.device, bot: c.is_bot })); // hiện ở Vercel → Logs
  try {
    await init();
    await sql`INSERT INTO logs(action, code, ip, user_agent, referrer, status, detail, country, city, device, browser, os, is_bot, meta)
              VALUES (${action}, ${code}, ${c.ip}, ${c.ua}, ${c.ref}, ${status}, ${String(detail).slice(0, 2000)},
                      ${c.country}, ${c.city}, ${c.device}, ${c.browser}, ${c.os}, ${c.is_bot}, ${JSON.stringify(c.meta)}::jsonb)`;
  } catch (e) {
    console.error("logOp DB lỗi:", e.message);
  }
  if (telegramOn()) waitUntil(teleOp(c, { action, code, status, detail })); // mọi thao tác đều đi qua đây → báo Telegram, không chặn phản hồi
}
// Gọi không chặn phản hồi
export const log = (req, o) => waitUntil(logOp(req, o));
export const bg = (p) => waitUntil(p); // việc phụ chạy sau khi đã trả lời

/* ───────── Quản trị: ADMIN_KEY qua header x-admin-key ───────── */
// Sai quá 10 lần / 10 phút từ cùng IP thì tạm khoá IP đó.
export async function requireAdmin(req, res) {
  res.setHeader("Cache-Control", "no-store"); // dữ liệu quản trị (IP, nhật ký) không được cache
  const admin = (process.env.ADMIN_KEY || "").trim();
  if (!admin) {
    res.status(503).json({ error: "Hệ thống chưa được cấu hình mật khẩu quản trị" });
    return false;
  }
  await init();
  const { ip } = clientInfo(req);
  if (ip) {
    const [{ n }] = await sql`SELECT count(*)::int AS n FROM logs
      WHERE ip = ${ip} AND action = 'admin_auth_failed' AND ts > now() - interval '10 minutes'`;
    if (n >= 10) {
      res.status(429).json({ error: "Nhập sai quá nhiều lần, thử lại sau 10 phút" });
      return false;
    }
  }
  // Phiên đăng nhập: không hết hạn theo thời gian, chỉ bị thay khi có máy khác đăng nhập (DB chỉ giữ MỘT phiên)
  const sess = String(req.headers["x-admin-session"] || "");
  if (sess) {
    const [r] = await sql`SELECT value, updated_at FROM settings WHERE key = 'admin_session'`;
    if (r && same(sha256(sess), r.value)) {
      if (Date.now() - new Date(r.updated_at) < 30 * 864e5) return true; // phiên sống 30 ngày kể từ lần đăng nhập
      res.status(401).json({ error: "Phiên đăng nhập đã hết hạn (30 ngày), hãy đăng nhập lại.", code: "session_expired" });
      return false;
    }
    res.status(401).json({ error: "Phiên đăng nhập đã kết thúc vì tài khoản được đăng nhập ở máy khác.", code: "session_replaced" });
    return false;
  }
  if (!same(String(req.headers["x-admin-key"] || ""), admin)) {
    await logOp(req, { action: "admin_auth_failed", status: 401 }); // đợi ghi xong: gửi song song nhiều lần không né được giới hạn
    res.status(401).json({ error: "Sai mật khẩu" });
    return false;
  }
  // Đăng nhập mới (kèm x-admin-login): tạo phiên mới, phiên của máy trước tự vô hiệu
  if (req.headers["x-admin-login"] === "1") {
    const token = randomBytes(32).toString("hex");
    await sql`INSERT INTO settings(key, value) VALUES ('admin_session', ${sha256(token)})
              ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`;
    res.setHeader("x-admin-session", token);
    await logOp(req, { action: "admin_login", status: 200 });
  }
  return true;
}
export const sha256 = (t) => createHash("sha256").update(t).digest("hex");

/* ───────── Cài đặt (DB > biến môi trường > mặc định) ───────── */
// Cài đặt QUAN TRỌNG (DATABASE_URL, ADMIN_KEY, API_KEY, SHEET_*, BASE_URL) chỉ nằm ở biến môi trường Vercel.
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
    env: "LOG_RETENTION_DAYS", def: "180", type: "int", min: 0, max: 3650,
    label: "Số ngày lưu nhật ký", hint: "0 = giữ vĩnh viễn. Tự dọn mỗi ngày (cần Vercel Cron)",
    norm: (v) => v, check: isInt(0, 3650), cast: Number,
  },
  tele_skip: {
    env: "TELE_SKIP", def: "bot_click,not_found,click,scan,rate_limited,captcha_failed,wrong_password", type: "text", label: "Telegram: thao tác KHÔNG báo",
    hint: "Mặc định đã tắt các thao tác ồn (bot_click, not_found, click, scan, rate_limited, captcha_failed, wrong_password). Ghi mã thao tác cách nhau dấu phẩy để đổi danh sách",
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
    env: "BLOCKED_DOMAINS", def: "", type: "text", label: "Tên miền bị chặn",
    hint: "Cách nhau bằng dấu phẩy, vd: bad.com, spam.net (chặn cả tên miền phụ)",
    norm: (v) => v.toLowerCase().split(/[\s,]+/).filter(Boolean).join(","), check: domainList,
    cast: (v) => v,
  },
};

let cache = { at: 0, rows: null };
async function rows() {
  if (cache.rows && Date.now() - cache.at < 15000) return cache.rows;
  await init();
  const r = await sql`SELECT key, value FROM settings`;
  cache = { at: Date.now(), rows: Object.fromEntries(r.map((x) => [x.key, x.value])) };
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

// patch: { key: "giá trị" | null }. null hoặc chuỗi rỗng = xoá khỏi DB (quay về env/mặc định).
export async function saveSettings(patch) {
  const errors = [];
  const ops = [];
  for (const [k, raw] of Object.entries(patch)) {
    const s = SCHEMA[k];
    if (!s) { errors.push(`Không có cài đặt "${k}"`); continue; }
    if (raw === null || String(raw).trim() === "") { ops.push({ k, del: true }); continue; }
    const v = s.norm(String(raw).trim());
    if (!s.check(v)) { errors.push(`Giá trị không hợp lệ cho "${s.label}"`); continue; }
    ops.push({ k, v });
  }
  if (errors.length) return { errors, changed: {} };

  await init();
  const changed = {};
  for (const op of ops) {
    if (op.del) {
      await sql`DELETE FROM settings WHERE key = ${op.k}`;
      changed[op.k] = null;
    } else {
      await sql`INSERT INTO settings(key, value) VALUES (${op.k}, ${op.v})
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`;
      changed[op.k] = op.v;
    }
  }
  cache = { at: 0, rows: null };
  return { errors: [], changed };
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
  await init();
  await sql`DELETE FROM rate_hits WHERE ts < now() - interval '1 day'`;
  await sql`DELETE FROM alerts WHERE kind = 'spike' AND ts < now() - interval '1 day'`;
  const { log_retention_days: d } = await getSettings();
  if (!d) return 0;
  const [{ n }] = await sql`WITH x AS (DELETE FROM logs WHERE ts < now() - make_interval(days => ${d}::int) RETURNING 1)
                            SELECT count(*)::int AS n FROM x`;
  return n;
}
