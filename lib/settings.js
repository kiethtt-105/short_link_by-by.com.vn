// Cài đặt KHÔNG quan trọng: lưu trong DB, sửa ở /admin (cần mật khẩu ADMIN_KEY).
// Thứ tự ưu tiên: giá trị trong DB, rồi biến môi trường cùng tên (giá trị khởi tạo), rồi mặc định.
// Cài đặt QUAN TRỌNG (DATABASE_URL, ADMIN_KEY, API_KEY, SHEET_*, BASE_URL) chỉ nằm ở biến môi trường Vercel.
import { sql, init } from "./db.js";

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
  cache.rows = null; // đọc mới nhất
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
