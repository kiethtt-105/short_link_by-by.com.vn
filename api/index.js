// Một function duy nhất cho toàn bộ API. vercel.json rewrite các đường dẫn cũ về đây:
//   /api/shorten /api/stats /api/qr /api/links /api/logs /api/settings  → ?op=<tên>
//   /<code>                                                              → ?op=r&code=<code>
import { randomInt } from "node:crypto";
import QRCode from "qrcode";
import {
  sql, init, log, clientInfo, baseUrl, same,
  requireAdmin, getSettings, describeSettings, saveSettings,
} from "../lib/core.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALIAS_RE = /^[A-Za-z0-9_-]{3,32}$/;
const RESERVED = new Set(["api", "index", "favicon", "robots", "admin", "style", "icons", "manifest", "apple-touch-icon", "sitemap"]);
const newCode = () => Array.from({ length: 7 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
// Ô bắt đầu bằng = + - @ (hoặc tab/CR) có thể chạy như công thức khi mở CSV bằng Excel → thêm dấu ' phía trước
const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replaceAll('"', '""')}"`;
};

/* ───────── Công khai ───────── */

// POST /api/shorten {url, alias?}
async function shorten(req, res) {
  const fail = (status, error, action = "create_failed") => {
    log(req, { action, status, detail: error });
    return res.status(status).json({ error });
  };
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });

  const key = (process.env.API_KEY || "").trim();
  // Form trên chính site này (trình duyệt tự gắn sec-fetch-site) không cần key; gọi từ nơi khác thì cần x-api-key
  const sameSite = req.headers["sec-fetch-site"] === "same-origin";
  if (key && !sameSite && !same(String(req.headers["x-api-key"] || ""), key)) {
    return fail(401, "API key không hợp lệ", "auth_failed");
  }

  // Chỉ nhận chuỗi (số/mảng/object từng làm lỗi 500)
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const input = typeof body.url === "string" ? body.url.trim() : "";
  const alias = typeof body.alias === "string" ? body.alias.trim() : "";
  let u;
  try {
    u = new URL(input);
    if (!["http:", "https:"].includes(u.protocol) || input.length > 2048) throw new Error();
  } catch {
    return fail(400, "URL phải là http:// hoặc https:// và tối đa 2048 ký tự");
  }
  // Lưu dạng đã mã hoá (u.href): link có tiếng Việt như /đường-đi nếu lưu thô sẽ làm header Location lỗi 500
  const url = u.href;
  const ownHosts = new Set([(req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase()]);
  try { ownHosts.add(new URL(baseUrl(req)).host.toLowerCase()); } catch {}
  if (ownHosts.has(u.host.toLowerCase())) return fail(400, "Không rút gọn link của chính hệ thống này");
  if (alias && (!ALIAS_RE.test(alias) || RESERVED.has(alias.toLowerCase()))) {
    return fail(400, "Alias gồm 3-32 ký tự chữ, số, _ hoặc - (không dùng từ dành riêng)");
  }

  await init();
  const { ip } = clientInfo(req);
  const cfg = await getSettings();

  const host = u.hostname.toLowerCase();
  const blocked = cfg.blocked_domains.split(",").filter(Boolean);
  if (blocked.some((d) => host === d || host.endsWith("." + d))) {
    return fail(403, "Tên miền này bị chặn", "blocked_domain");
  }

  const limit = cfg.rate_limit_per_min;
  if (limit > 0 && ip) {
    const [{ n }] = await sql`SELECT count(*)::int AS n FROM logs
      WHERE ip = ${ip} AND action = 'create' AND ts > now() - interval '1 minute'`;
    if (n >= limit) return fail(429, "Tạo link quá nhanh, thử lại sau", "rate_limited");
  }

  let code = alias || null;
  if (code) {
    const r = await sql`INSERT INTO links(code, url, created_ip) VALUES (${code}, ${url}, ${ip})
                        ON CONFLICT DO NOTHING RETURNING code`;
    if (!r.length) return fail(409, "Alias đã tồn tại");
  } else {
    for (let i = 0; i < 10 && !code; i++) {
      const c = newCode();
      const r = await sql`INSERT INTO links(code, url, created_ip) VALUES (${c}, ${url}, ${ip})
                          ON CONFLICT DO NOTHING RETURNING code`;
      if (r.length) code = c;
    }
    if (!code) return fail(500, "Không sinh được mã ngắn");
  }

  log(req, { action: "create", code, status: 201, detail: url });
  const base = baseUrl(req);
  res.status(201).json({ code, short_url: `${base}/${code}`, qr_url: `${base}/api/qr?code=${code}`, url });
}

// GET /api/stats?code=abc — công khai, không trả IP
async function stats(req, res) {
  const code = String(req.query.code || "");
  await init();
  const [link] = await sql`SELECT code, url, clicks, scans, created_at FROM links WHERE code = ${code}`;
  if (!link) return res.status(404).json({ error: "Không tìm thấy link" });

  // Gom theo ngày giờ Việt Nam
  const by_day = await sql`SELECT (ts AT TIME ZONE 'Asia/Ho_Chi_Minh')::date AS day, count(*)::int AS clicks
    FROM logs WHERE action IN ('click', 'scan') AND code = ${code}
      AND ts >= (SELECT created_at FROM links WHERE code = ${code})
    GROUP BY day ORDER BY day DESC LIMIT 30`;
  const top_referrers = await sql`SELECT COALESCE(NULLIF(referrer, ''), '(trực tiếp)') AS referrer,
    count(*)::int AS clicks FROM logs WHERE action IN ('click', 'scan') AND code = ${code}
      AND ts >= (SELECT created_at FROM links WHERE code = ${code})
    GROUP BY 1 ORDER BY clicks DESC LIMIT 10`;

  log(req, { action: "stats_view", code, status: 200 });
  res.json({ ...link, by_day, top_referrers });
}

// GET /api/qr?code=abc&format=png|svg&download=1
async function qr(req, res) {
  const code = String(req.query.code || "");
  if (!ALIAS_RE.test(code)) return res.status(400).json({ error: "code không hợp lệ" });

  await init();
  const [link] = await sql`SELECT code FROM links WHERE code = ${code}`;
  if (!link) return res.status(404).json({ error: "Không tìm thấy link" });

  const cfg = await getSettings();
  const fmt = ["png", "svg"].includes(req.query.format) ? req.query.format : cfg.qr_format;
  const target = `${baseUrl(req)}/${code}?src=qr`; // ?src=qr để phân biệt lượt quét với lượt bấm
  const opts = {
    width: cfg.qr_size,
    margin: cfg.qr_margin,
    errorCorrectionLevel: cfg.qr_error_level,
    color: { dark: cfg.qr_foreground, light: cfg.qr_background },
  };

  try {
    let body;
    if (fmt === "png") {
      body = await QRCode.toBuffer(target, { ...opts, type: "png" });
      res.setHeader("Content-Type", "image/png");
    } else {
      body = await QRCode.toString(target, { ...opts, type: "svg" });
      res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    }
    if (req.query.download) res.setHeader("Content-Disposition", `attachment; filename="${code}.${fmt}"`);
    res.setHeader("Cache-Control", "private, max-age=300");
    log(req, { action: "qr_view", code, status: 200, detail: fmt });
    return res.status(200).send(body);
  } catch (e) {
    log(req, { action: "qr_failed", code, status: 500, detail: e.message });
    return res.status(500).json({ error: "Không tạo được QR" });
  }
}

// GET /<code> — chuyển hướng + đếm lượt
async function redirect(req, res) {
  const code = String(req.query.code || "");
  await init();
  res.setHeader("Cache-Control", "no-store"); // mỗi lượt bấm đều đi qua server

  // HEAD (bot xem trước, kiểm tra link) chỉ trả đích, không đếm
  if (req.method === "HEAD") {
    const [l] = await sql`SELECT url FROM links WHERE code = ${code}`;
    return l ? res.redirect(302, l.url) : res.status(404).end();
  }

  const fromQr = req.query.src === "qr";
  const rows = await sql`UPDATE links SET clicks = clicks + 1, scans = scans + ${fromQr ? 1 : 0}
                          WHERE code = ${code} RETURNING url`;
  if (!rows.length) {
    log(req, { action: "not_found", code, status: 404 });
    return res.status(404).send("Link không tồn tại");
  }
  log(req, { action: fromQr ? "scan" : "click", code, status: 302, detail: rows[0].url });
  res.redirect(302, rows[0].url);
}

/* ───────── Quản trị (cần x-admin-key) ───────── */

// GET /api/links?q=&limit=50   DELETE /api/links?code=abc
async function links(req, res) {
  if (!(await requireAdmin(req, res))) return;
  await init();

  if (req.method === "DELETE") {
    const code = String(req.query.code || "");
    const r = await sql`DELETE FROM links WHERE code = ${code} RETURNING url`;
    if (!r.length) return res.status(404).json({ error: "Không tìm thấy link" });
    log(req, { action: "link_delete", code, status: 200, detail: r[0].url });
    return res.json({ ok: true });
  }
  if (req.method !== "GET") return res.status(405).json({ error: "Chỉ hỗ trợ GET hoặc DELETE" });

  const q = String(req.query.q || "").slice(0, 100);
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  const like = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
  const rows = await sql`SELECT code, url, clicks, scans, created_at FROM links
    WHERE (${q} = '' OR code ILIKE ${like} OR url ILIKE ${like})
    ORDER BY created_at DESC LIMIT ${limit}`;
  const [t] = await sql`SELECT count(*)::int AS total, COALESCE(sum(clicks), 0)::int AS clicks,
    COALESCE(sum(scans), 0)::int AS scans FROM links`;
  res.json({ ...t, links: rows });
}

// GET /api/logs?limit=100&action=click&code=abc&from=2026-11-01&format=csv
// Apps Script kéo log tăng dần: GET /api/logs?after_id=123&limit=1000 + header x-sheet-token (chỉ đọc log)
async function logs(req, res) {
  const st = (process.env.SHEET_TOKEN || "").trim();
  const viaSheet = !!st && same(String(req.headers["x-sheet-token"] || ""), st);
  if (viaSheet) res.setHeader("Cache-Control", "no-store");
  else if (!(await requireAdmin(req, res))) return;

  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 5000);
  const action = req.query.action || null;
  const code = req.query.code || null;
  // from sai định dạng thì bỏ qua (trước đây gây lỗi 500)
  const from = req.query.from && !Number.isNaN(Date.parse(req.query.from)) ? req.query.from : null;
  const afterId = /^\d+$/.test(String(req.query.after_id ?? "")) ? String(req.query.after_id) : null;

  await init();
  const rows = afterId !== null
    ? await sql`SELECT id, ts, action, code, ip, user_agent, referrer, status, detail
        FROM logs WHERE id > ${afterId}::bigint
          AND (${action}::text IS NULL OR action = ${action})
          AND (${code}::text IS NULL OR code = ${code})
        ORDER BY id ASC LIMIT ${limit}`
    : await sql`SELECT id, ts, action, code, ip, user_agent, referrer, status, detail
        FROM logs
        WHERE (${action}::text IS NULL OR action = ${action})
          AND (${code}::text IS NULL OR code = ${code})
          AND (${from}::timestamptz IS NULL OR ts >= ${from}::timestamptz)
        ORDER BY id DESC LIMIT ${limit}`;

  if (req.query.format === "csv") {
    const head = ["id", "ts", "action", "code", "ip", "user_agent", "referrer", "status", "detail"];
    const body = rows.map((r) => head.map((h) => csvCell(r[h])).join(","));
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="logs.csv"');
    return res.send("\ufeff" + [head.join(","), ...body].join("\n"));
  }
  res.json({ count: rows.length, logs: rows });
}

// GET /api/settings   PUT /api/settings {key: value | null}
async function settings(req, res) {
  if (!(await requireAdmin(req, res))) return;

  if (req.method === "GET") return res.json({ settings: await describeSettings() });
  if (req.method === "PUT" || req.method === "POST") {
    const patch = req.body;
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
      return res.status(400).json({ error: "Body phải là object JSON" });
    }
    const r = await saveSettings(patch);
    if (r.errors.length) return res.status(400).json({ errors: r.errors });
    log(req, { action: "settings_update", status: 200, detail: JSON.stringify(r.changed) });
    return res.json({ ok: true, settings: await describeSettings() });
  }
  res.status(405).json({ error: "Chỉ hỗ trợ GET hoặc PUT" });
}

/* ───────── Router ───────── */
const routes = { shorten, stats, qr, r: redirect, links, logs, settings };

export default async function handler(req, res) {
  const op = req.query.op;
  // hasOwn: tránh op=constructor/toString... lấy nhầm hàm của Object (request treo, không có phản hồi)
  if (typeof op !== "string" || !Object.hasOwn(routes, op)) return res.status(404).json({ error: "Không tìm thấy" });
  const fn = routes[op];
  try {
    await fn(req, res);
  } catch (e) {
    console.error(op, e);
    if (!res.headersSent) res.status(500).json({ error: "Lỗi máy chủ" });
  }
}
