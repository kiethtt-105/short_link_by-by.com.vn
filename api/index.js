// Một function duy nhất cho toàn bộ API. vercel.json rewrite các đường dẫn cũ về đây:
//   /api/shorten /api/stats /api/qr /api/links /api/logs /api/settings  → ?op=<tên>
//   /<code>                                                              → ?op=r&code=<code>
import { randomInt } from "node:crypto";
import QRCode from "qrcode";
import {
  sql, init, log, logOp, clientInfo, baseUrl, same, purgeLogs,
  requireAdmin, getSettings, describeSettings, saveSettings,
  hit, turnstileOn, verifyTurnstile, unsafeThreat,
} from "../lib/core.js";

// Bỏ ký tự dễ nhầm khi đọc/gõ (0 O 1 l I); link cũ có các ký tự này vẫn hoạt động bình thường
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const ALIAS_RE = /^[A-Za-z0-9_-]{3,32}$/;
const RESERVED = new Set(["api", "index", "favicon", "robots", "admin", "style", "icons", "manifest", "apple-touch-icon", "sitemap"]);
const newCode = (len = 5) => Array.from({ length: len }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
// Ô bắt đầu bằng = + - @ (hoặc tab/CR) có thể chạy như công thức khi mở CSV bằng Excel → thêm dấu ' phía trước
const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replaceAll('"', '""')}"`;
};

/* ───────── Công khai ───────── */

// POST /api/shorten {url, alias?, turnstile?}
async function shorten(req, res) {
  // Đợi ghi log xong rồi mới trả lời: các thống kê/giới hạn đọc từ DB không được trễ
  const fail = async (status, error, action = "create_failed") => {
    await logOp(req, { action, status, detail: error });
    return res.status(status).json({ error });
  };
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });

  await init();
  const { ip } = clientInfo(req);
  const cfg = await getSettings();

  // Giới hạn tốc độ đặt NGAY ĐẦU: mọi lượt gọi (kể cả sai) đều được tính, trước khi tốn tài nguyên xác minh
  if (await hit("create", ip, cfg.rate_limit_per_min)) return fail(429, "Tạo link quá nhanh, thử lại sau", "rate_limited");

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
  if (u.username || u.password) return fail(400, "Link không được chứa tài khoản hoặc mật khẩu (user:pass@)");
  const hn = u.hostname.toLowerCase();
  if (!hn.includes(".") || hn.endsWith(".local") || hn.endsWith(".internal") ||
      /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(hn)) {
    return fail(400, "Không rút gọn link nội bộ (localhost, IP riêng, tên máy trong mạng LAN)");
  }
  const ownHosts = new Set([(req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase()]);
  try { ownHosts.add(new URL(baseUrl(req)).host.toLowerCase()); } catch {}
  if (ownHosts.has(u.host.toLowerCase())) return fail(400, "Không rút gọn link của chính hệ thống này");
  if (alias && (!ALIAS_RE.test(alias) || RESERVED.has(alias.toLowerCase()))) {
    return fail(400, "Alias gồm 3-32 ký tự chữ, số, _ hoặc - (không dùng từ dành riêng)");
  }

  // Xác thực. Header x-sec-fetch-site do client tự đặt được nên KHÔNG còn dùng để miễn key:
  //  • có x-api-key đúng → qua (gọi từ máy chủ / ứng dụng khác)
  //  • không có key → cần token Turnstile (form trên web). Chưa cấu hình Turnstile thì dùng cách cũ (same-origin) để không gãy hệ thống.
  const apiKey = (process.env.API_KEY || "").trim();
  const sentKey = String(req.headers["x-api-key"] || "");
  const keyOk = !!apiKey && !!sentKey && same(sentKey, apiKey);
  if (apiKey && sentKey && !keyOk) return fail(401, "API key không hợp lệ", "auth_failed");
  if (!keyOk) {
    if (turnstileOn()) {
      if (!(await verifyTurnstile(body.turnstile, ip))) {
        return fail(403, "Xác minh chống spam không thành công, hãy tải lại trang rồi thử lại", "captcha_failed");
      }
    } else if (apiKey && req.headers["sec-fetch-site"] !== "same-origin") {
      return fail(401, "API key không hợp lệ", "auth_failed");
    }
  }

  const blocked = cfg.blocked_domains.split(",").filter(Boolean);
  if (blocked.some((d) => hn === d || hn.endsWith("." + d))) {
    return fail(403, "Tên miền này bị chặn", "blocked_domain");
  }

  // Link độc hại (phishing, mã độc) theo Google Safe Browsing. Bỏ qua nếu chưa đặt SAFE_BROWSING_KEY.
  const threat = await unsafeThreat(url);
  if (threat) return fail(400, "Link này bị đánh dấu là không an toàn nên không thể rút gọn", "unsafe_url");

  let code = alias || null;
  if (code) {
    const r = await sql`INSERT INTO links(code, url, created_ip) VALUES (${code}, ${url}, ${ip})
                        ON CONFLICT DO NOTHING RETURNING code`;
    if (!r.length) return fail(409, "Alias đã tồn tại");
  } else {
    for (let i = 0; i < 10 && !code; i++) {
      const c = newCode(cfg.code_length);
      const r = await sql`INSERT INTO links(code, url, created_ip) VALUES (${c}, ${url}, ${ip})
                          ON CONFLICT DO NOTHING RETURNING code`;
      if (r.length) code = c;
    }
    if (!code) return fail(500, "Không sinh được mã ngắn");
  }

  await logOp(req, { action: "create", code, status: 201, detail: url });
  const base = baseUrl(req);
  res.status(201).json({ code, short_url: `${base}/${code}`, qr_url: `${base}/api/qr?code=${code}`, url });
}

// GET /api/stats?code=abc
//  • Công khai: chỉ trả tổng lượt (đủ cho nút "Xem số liệu" ở trang chủ), có giới hạn tốc độ.
//  • Kèm x-admin-key: trả đủ phân tích (ngày, nguồn, quốc gia, thiết bị...). Tất cả gộp bằng SQL, 1 lượt gọi mạng.
const STATS_LIMIT = Number(process.env.STATS_RATE_LIMIT_PER_MIN) || 60;
async function stats(req, res) {
  const code = String(req.query.code || "");
  if (!ALIAS_RE.test(code)) return res.status(404).json({ error: "Không tìm thấy link" });
  res.setHeader("Cache-Control", "no-store");

  const isAdmin = !!(req.headers["x-admin-key"] || req.headers["x-admin-session"]);
  if (isAdmin && !(await requireAdmin(req, res))) return;
  await init();
  if (!isAdmin && (await hit("stats", clientInfo(req).ip, STATS_LIMIT))) {
    return res.status(429).json({ error: "Xem số liệu quá nhanh, thử lại sau" });
  }

  const [link] = await sql`SELECT code, url, clicks, scans, created_at FROM links WHERE code = ${code}`;
  if (!link) return res.status(404).json({ error: "Không tìm thấy link" });
  if (!isAdmin) return res.json(link);

  // Gom theo ngày giờ Việt Nam; nguồn truy cập gom theo TÊN MIỀN (bỏ www./m./l.) thay vì URL đầy đủ
  const [by_day, top_referrers, dim, [{ bots }]] = await sql.transaction([
    sql`SELECT (ts AT TIME ZONE 'Asia/Ho_Chi_Minh')::date AS day, count(*)::int AS clicks
      FROM logs WHERE action IN ('click', 'scan') AND code = ${code}
        AND ts >= (SELECT created_at FROM links WHERE code = ${code})
      GROUP BY day ORDER BY day DESC LIMIT 30`,
    sql`SELECT COALESCE(NULLIF(regexp_replace(lower(substring(referrer from '^[A-Za-z]+://([^/:?#]+)')), '^(www|m|l|lm|mobile)\\.', ''), ''), '(trực tiếp)') AS referrer,
      count(*)::int AS clicks FROM logs WHERE action IN ('click', 'scan') AND code = ${code}
        AND ts >= (SELECT created_at FROM links WHERE code = ${code})
      GROUP BY 1 ORDER BY clicks DESC LIMIT 10`,
    // Quốc gia / thiết bị / trình duyệt / hệ điều hành (chỉ người thật; bot ghi riêng), đếm toàn bộ thay vì 20.000 dòng gần nhất
    sql`WITH base AS (SELECT country, device, browser, os FROM logs
          WHERE action IN ('click', 'scan') AND code = ${code}
            AND ts >= (SELECT created_at FROM links WHERE code = ${code}))
        SELECT 'country' AS k, COALESCE(NULLIF(country, ''), '(không rõ)') AS name, count(*)::int AS clicks FROM base GROUP BY 2
        UNION ALL SELECT 'device', COALESCE(NULLIF(device, ''), '(không rõ)'), count(*)::int FROM base GROUP BY 2
        UNION ALL SELECT 'browser', COALESCE(NULLIF(browser, ''), '(không rõ)'), count(*)::int FROM base GROUP BY 2
        UNION ALL SELECT 'os', COALESCE(NULLIF(os, ''), '(không rõ)'), count(*)::int FROM base GROUP BY 2`,
    sql`SELECT count(*)::int AS bots FROM logs WHERE action = 'bot_click' AND code = ${code}`,
  ]);
  const top = (k) => dim.filter((r) => r.k === k).sort((a, b) => b.clicks - a.clicks).slice(0, 8)
    .map(({ name, clicks }) => ({ name, clicks }));

  res.json({ ...link, by_day, top_referrers, by_country: top("country"), by_device: top("device"),
    by_browser: top("browser"), by_os: top("os"), bot_clicks: bots });
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
    return res.status(200).send(body);
  } catch (e) {
    log(req, { action: "qr_failed", code, status: 500, detail: e.message });
    return res.status(500).json({ error: "Không tạo được QR" });
  }
}

const page = (title, big, msg) => `<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#06050f;color:#eaf2ff;font:16px system-ui,sans-serif;text-align:center">
<main><h1 style="font-size:64px;margin:0;color:#22f3ff;text-shadow:0 0 24px #22f3ff">${big}</h1><p>${msg}</p>
<p><a href="/" style="color:#ff2bd6">Tạo link mới</a> · <a href="https://by.com.vn/" rel="noopener" style="color:#22f3ff">Design by Tuankiet</a></p></main></body></html>`;
const notFoundPage = () => page("Link không tồn tại", "404", "Link này không tồn tại hoặc đã bị xoá.");
const disabledPage = () => page("Link đã bị khoá", "410", "Link này đã bị khoá nên không thể truy cập.");

// GET /<code> — chuyển hướng + đếm lượt
async function redirect(req, res) {
  const code = String(req.query.code || "");
  await init();
  res.setHeader("Cache-Control", "no-store"); // mỗi lượt bấm đều đi qua server

  // HEAD (bot xem trước, kiểm tra link) chỉ trả đích, không đếm; link bị khoá thì 410
  if (req.method === "HEAD") {
    const [l] = await sql`SELECT url, disabled FROM links WHERE code = ${code}`;
    if (!l) return res.status(404).end();
    return l.disabled ? res.status(410).end() : res.redirect(302, l.url);
  }

  const fromQr = req.query.src === "qr";
  const { is_bot } = clientInfo(req);
  // Bot / trình xem trước link (Facebook, Slack, Zalo...) chỉ được chuyển hướng, KHÔNG cộng lượt; ghi riêng 'bot_click'
  let rows = is_bot
    ? await sql`SELECT url, disabled FROM links WHERE code = ${code}`
    : await sql`UPDATE links SET clicks = clicks + 1, scans = scans + ${fromQr ? 1 : 0}
                WHERE code = ${code} AND NOT disabled RETURNING url, disabled`;
  // UPDATE không trúng dòng nào: hoặc link không có, hoặc link đang bị khoá → tra lại để phân biệt
  if (!rows.length && !is_bot) rows = await sql`SELECT url, disabled FROM links WHERE code = ${code}`;
  if (!rows.length) {
    log(req, { action: "not_found", code, status: 404 });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(404).send(notFoundPage());
  }
  if (rows[0].disabled) {
    log(req, { action: "disabled_click", code, status: 410 });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(410).send(disabledPage());
  }
  log(req, { action: is_bot ? "bot_click" : fromQr ? "scan" : "click", code, status: 302, detail: rows[0].url });
  res.redirect(302, rows[0].url);
}

/* ───────── Quản trị (cần x-admin-key) ───────── */

// Cho phép đọc bằng ADMIN_KEY, hoặc bằng SHEET_TOKEN (header x-sheet-token) nhưng chỉ với GET.
// Token của Sheet không sửa/xoá được gì.
async function adminOrSheet(req, res) {
  const st = (process.env.SHEET_TOKEN || "").trim();
  if (st && req.method === "GET" && same(String(req.headers["x-sheet-token"] || ""), st)) {
    res.setHeader("Cache-Control", "no-store");
    return { ok: true, viaSheet: true };
  }
  return { ok: await requireAdmin(req, res), viaSheet: false };
}

// GET /api/links?q=&limit=50   PATCH /api/links?code=abc {disabled}   DELETE /api/links?code=abc
async function links(req, res) {
  const auth = await adminOrSheet(req, res);
  if (!auth.ok) return;
  await init();

  if (req.method === "DELETE") {
    const code = String(req.query.code || "");
    const r = await sql`DELETE FROM links WHERE code = ${code} RETURNING url`;
    if (!r.length) return res.status(404).json({ error: "Không tìm thấy link" });
    log(req, { action: "link_delete", code, status: 200, detail: r[0].url });
    return res.json({ ok: true });
  }
  if (req.method === "PATCH") { // khoá / mở khoá link (không mất số liệu)
    if (auth.viaSheet) return res.status(403).json({ error: "Không đủ quyền" });
    const code = String(req.query.code || "");
    const b = req.body && typeof req.body === "object" ? req.body : {};
    if (typeof b.disabled !== "boolean") return res.status(400).json({ error: "disabled phải là true hoặc false" });
    const r = await sql`UPDATE links SET disabled = ${b.disabled} WHERE code = ${code} RETURNING disabled`;
    if (!r.length) return res.status(404).json({ error: "Không tìm thấy link" });
    log(req, { action: b.disabled ? "link_disable" : "link_enable", code, status: 200 });
    return res.json({ ok: true, disabled: r[0].disabled });
  }
  if (req.method !== "GET") return res.status(405).json({ error: "Chỉ hỗ trợ GET, PATCH hoặc DELETE" });

  const q = String(req.query.q || "").slice(0, 100);
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), auth.viaSheet ? 20000 : 200);
  const like = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
  const rows = await sql`SELECT code, url, clicks, scans, created_at, created_ip, disabled FROM links
    WHERE (${q} = '' OR code ILIKE ${like} OR url ILIKE ${like})
    ORDER BY created_at DESC LIMIT ${limit}`;
  const [t] = await sql`SELECT count(*)::int AS total, COALESCE(sum(clicks), 0)::int AS clicks,
    COALESCE(sum(scans), 0)::int AS scans FROM links`;
  res.json({ ...t, links: rows });
}

// GET /api/logs?limit=100&action=click&code=abc&from=2026-11-01&format=csv
// Apps Script kéo log tăng dần: GET /api/logs?after_id=123&limit=1000 + header x-sheet-token (chỉ đọc log)
async function logs(req, res) {
  if (!(await adminOrSheet(req, res)).ok) return;

  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 5000);
  const action = req.query.action || null;
  const code = req.query.code || null;
  // from sai định dạng thì bỏ qua (trước đây gây lỗi 500)
  const from = req.query.from && !Number.isNaN(Date.parse(req.query.from)) ? new Date(req.query.from).toISOString() : null;
  const afterId = /^\d+$/.test(String(req.query.after_id ?? "")) ? String(req.query.after_id) : null;

  await init();
  const rows = afterId !== null
    ? await sql`SELECT id, ts, action, code, ip, user_agent, referrer, status, detail, country, city, device, browser, os, is_bot, meta
        FROM logs WHERE id > ${afterId}::bigint
          AND (${action}::text IS NULL OR action = ${action})
          AND (${code}::text IS NULL OR code = ${code})
        ORDER BY id ASC LIMIT ${limit}`
    : await sql`SELECT id, ts, action, code, ip, user_agent, referrer, status, detail, country, city, device, browser, os, is_bot, meta
        FROM logs
        WHERE (${action}::text IS NULL OR action = ${action})
          AND (${code}::text IS NULL OR code = ${code})
          AND (${from}::timestamptz IS NULL OR ts >= ${from}::timestamptz)
        ORDER BY id DESC LIMIT ${limit}`;

  if (req.query.format === "csv") {
    const head = ["id", "ts", "action", "code", "ip", "country", "city", "device", "browser", "os", "is_bot", "user_agent", "referrer", "status", "detail", "meta"];
    const body = rows.map((r) => head.map((h) => csvCell(h === "meta" ? JSON.stringify(r.meta ?? {}) : r[h])).join(","));
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="logs.csv"');
    return res.send("\ufeff" + [head.join(","), ...body].join("\n"));
  }
  res.json({ count: rows.length, logs: rows });
}

// GET /api/settings   PUT /api/settings {key: value | null}
async function settings(req, res) {
  if (!(await adminOrSheet(req, res)).ok) return;

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
// GET /api/cleanup — Vercel Cron (Authorization: Bearer CRON_SECRET) hoặc admin: xoá nhật ký quá hạn
async function cleanup(req, res) {
  const cs = (process.env.CRON_SECRET || "").trim();
  const isCron = cs && same(String(req.headers.authorization || ""), `Bearer ${cs}`);
  if (!isCron && !(await requireAdmin(req, res))) return;
  const n = await purgeLogs();
  log(req, { action: "purge", status: 200, detail: `deleted ${n}` });
  res.json({ ok: true, deleted: n });
}
const routes = { shorten, stats, qr, r: redirect, links, logs, settings, cleanup };

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
