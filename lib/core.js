// Gộp từ db.js + log.js + util.js + admin.js + settings.js
import { timingSafeEqual } from "node:crypto";
import { neon } from "@neondatabase/serverless";
import { waitUntil } from "@vercel/functions";

/* ───────── Database ───────── */
export const sql = neon(process.env.DATABASE_URL);

let ready;
export function init() {
  ready ??= (async () => {
    await sql`CREATE TABLE IF NOT EXISTS links (
      code TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      clicks BIGINT NOT NULL DEFAULT 0,
      scans BIGINT NOT NULL DEFAULT 0,
      created_ip TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
    await sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS scans BIGINT NOT NULL DEFAULT 0`;
    await sql`CREATE TABLE IF NOT EXISTS logs (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      action TEXT NOT NULL,
      code TEXT,
      ip TEXT,
      user_agent TEXT,
      referrer TEXT,
      status INT,
      detail TEXT
    )`;
    await sql`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_code ON logs(code)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_ip_action ON logs(ip, action, ts)`;
  })().catch((e) => {
    ready = undefined;
    throw e;
  });
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

/* ───────── Nhật ký ───────── */
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
  const url = (process.env.SHEET_WEBHOOK_URL || "").trim();
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: (process.env.SHEET_TOKEN || "").trim(), row }),
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    // Sheet chỉ là bản sao; DB mới là nguồn dữ liệu chính
  }
}

export async function logOp(req, { action, code = null, status = 200, detail = "" }) {
  const { ip, ua, ref } = clientInfo(req);
  console.log(JSON.stringify({ action, code, status })); // hiện ở Vercel → Logs để lọc/tìm
  try {
    await init();
    await sql`INSERT INTO logs(action, code, ip, user_agent, referrer, status, detail)
              VALUES (${action}, ${code}, ${ip}, ${ua}, ${ref}, ${status}, ${String(detail).slice(0, 2000)})`;
  } catch (e) {
    console.error("logOp DB lỗi:", e.message);
  }
  await toSheet([new Date().toISOString(), action, code, ip, ua, ref, status, String(detail).slice(0, 2000)]);
}
// Gọi không chặn phản hồi
export const log = (req, o) => waitUntil(logOp(req, o));

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
  if (!same(String(req.headers["x-admin-key"] || ""), admin)) {
    log(req, { action: "admin_auth_failed", status: 401 });
    res.status(401).json({ error: "Sai mật khẩu" });
    return false;
  }
  return true;
}

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
    env: "QR_MARGIN", def: "2", type: "int", min: 0, max: 10, label: "Viền trắng QR (ô)",
    norm: (v) => v, check: isInt(0, 10), cast: Number,
  },
  qr_error_level: {
    env: "QR_ERROR_LEVEL", def: "M", type: "enum", options: ["L", "M", "Q", "H"],
    label: "Mức sửa lỗi QR", hint: "H chịu hỏng tốt nhất nhưng mã dày hơn",
    norm: (v) => v.toUpperCase(), check: oneOf("L", "M", "Q", "H"),
  },
  qr_format: {
    env: "QR_FORMAT", def: "svg", type: "enum", options: ["svg", "png"], label: "Định dạng QR mặc định",
    norm: (v) => v.toLowerCase(), check: oneOf("svg", "png"),
  },
  rate_limit_per_min: {
    env: "RATE_LIMIT_PER_MIN", def: "0", type: "int", min: 0, max: 10000,
    label: "Giới hạn tạo link / IP / phút", hint: "0 = không giới hạn",
    norm: (v) => v, check: isInt(0, 10000), cast: Number,
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
