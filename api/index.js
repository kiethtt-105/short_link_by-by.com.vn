// Một function duy nhất cho toàn bộ API. vercel.json rewrite các đường dẫn cũ về đây:
//   /api/shorten /api/stats /api/qr /api/links /api/logs /api/settings  → ?op=<tên>
//   /<code>                                                              → ?op=r&code=<code>
// Dữ liệu nằm 100% trong Google Sheet (lib/store.js → apps-script/Code.gs), không còn database nào khác.
import { randomInt, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import QRCode from "qrcode";
import {
  store, getLink, dropLink, logRow, logOp, log, clientInfo, baseUrl, same, purgeLogs,
  requireAdmin, getSettings, describeSettings, saveSettings,
  hit, turnstileOn, verifyTurnstile, unsafeThreat,
  sha256, bg, safeGet,
} from "../lib/core.js";
import { telegramOn, notify, alertOnce, claimAlert, releaseAlert, teleOp } from "../lib/tele.js";

// Bỏ ký tự dễ nhầm khi đọc/gõ (0 O 1 l I); link cũ có các ký tự này vẫn hoạt động bình thường
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const ALIAS_RE = /^[A-Za-z0-9_-]{3,32}$/;
const RESERVED = new Set(["api", "index", "favicon", "robots", "admin", "style", "icons", "manifest", "apple-touch-icon", "sitemap", "health", "terms", "privacy", "report", "status"]);
const newCode = (len = 5) => Array.from({ length: len }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
// Ô bắt đầu bằng = + - @ (hoặc tab/CR) có thể chạy như công thức khi mở CSV bằng Excel → thêm dấu ' phía trước
const csvCell = (v) => {
  let s = v instanceof Date ? v.toISOString() : String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replaceAll('"', '""')}"`;
};

// Một đường path cho cả mã QR; mỗi ô là hình vuông / chấm tròn / vuông bo góc / bo góc chỉ ở phía ngoài cụm
const SHAPES = ["square", "dot", "round", "smooth"];
const rrect = (x, y, tl, tr, br, bl) =>
  `M${x + tl} ${y}H${x + 1 - tr}${tr ? `a${tr} ${tr} 0 0 1 ${tr} ${tr}` : ""}V${y + 1 - br}${br ? `a${br} ${br} 0 0 1 -${br} ${br}` : ""}` +
  `H${x + bl}${bl ? `a${bl} ${bl} 0 0 1 -${bl} -${bl}` : ""}V${y + tl}${tl ? `a${tl} ${tl} 0 0 1 ${tl} -${tl}` : ""}z`;
function shapedSvg(text, { size, margin, level, dark, light, shape }) {
  const m = QRCode.create(text, { errorCorrectionLevel: level }).modules, n = m.size;
  const on = (r, c) => r >= 0 && c >= 0 && r < n && c < n && !!m.get(r, c);
  const finder = (r, c) => (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7); // ba mắt định vị luôn giữ dạng ô để dễ quét
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
    if (!on(r, c)) continue;
    const x = c + margin, y = r + margin;
    if (shape === "dot" && !finder(r, c)) d += `M${x + .05} ${y + .5}a.45 .45 0 1 0 .9 0a.45 .45 0 1 0 -.9 0`;
    else if (shape === "round" || shape === "dot") d += rrect(x, y, .3, .3, .3, .3);
    else if (shape === "smooth") {
      const u = on(r - 1, c), dn = on(r + 1, c), l = on(r, c - 1), rt = on(r, c + 1);
      d += rrect(x, y, !u && !l ? .5 : 0, !u && !rt ? .5 : 0, !dn && !rt ? .5 : 0, !dn && !l ? .5 : 0);
    } else d += `M${x} ${y}h1v1h-1z`;
  }
  const t = n + margin * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${t} ${t}" width="${size}" height="${size}"><rect width="${t}" height="${t}" fill="${light}"/><path d="${d}" fill="${dark}"/></svg>`;
}

const hashPw = (pw, salt) => scryptSync(pw, salt, 32);
const checkPw = (pw, l) => {
  const a = hashPw(pw, l.pass_salt), b = Buffer.from(l.pass_hash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
};
// Số nguyên trong [lo, hi]; rỗng → null; sai → NaN
const intIn = (v, lo, hi) => {
  if (v == null || v === "") return null;
  const n = Number(v); return Number.isInteger(n) && n >= lo && n <= hi ? n : NaN;
};

/* ───────── Công khai ───────── */

// GET /api/index?op=check&alias=abc → {available, reason?}  (kiểm tra tên riêng khi gõ)
async function check(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const alias = String(req.query.alias || "");
  if (!ALIAS_RE.test(alias)) return res.json({ available: false, reason: "Cần 3-32 ký tự chữ, số, _ hoặc -" });
  if (RESERVED.has(alias.toLowerCase())) return res.json({ available: false, reason: "Từ này được dành riêng" });
  if (hit("check", clientInfo(req).ip, 60)) return res.status(429).json({ error: "Kiểm tra quá nhanh, thử lại sau" });
  res.json((await getLink(alias, { fresh: true })) ? { available: false, reason: "Đã có người dùng" } : { available: true });
}

// POST /api/shorten {url, alias?, turnstile?}
async function shorten(req, res) {
  const fail = (status, error, action = "create_failed") => {
    log(req, { action, status, detail: error }); // ghi nền: giới hạn tốc độ nằm trong RAM nên không cần đợi
    return res.status(status).json({ error });
  };
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });

  const { ip } = clientInfo(req);
  const cfg = await getSettings();

  // Giới hạn tốc độ đặt NGAY ĐẦU: mọi lượt gọi (kể cả sai) đều được tính, trước khi tốn tài nguyên xác minh
  if (hit("create", ip, cfg.rate_limit_per_min)) return fail(429, "Tạo link quá nhanh, thử lại sau", "rate_limited");
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
  const hn = u.hostname.toLowerCase().replace(/\.+$/, ""); // "localhost." (dấu chấm cuối) từng lọt qua kiểm tra nội bộ
  if (!hn.includes(".") || hn.endsWith(".localhost") || hn.endsWith(".local") || hn.endsWith(".internal") ||
      /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(hn)) {
    return fail(400, "Không rút gọn link nội bộ (localhost, IP riêng, tên máy trong mạng LAN)");
  }
  const ownHosts = new Set([(req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase()]);
  try { ownHosts.add(new URL(baseUrl(req)).host.toLowerCase()); } catch {}
  if (ownHosts.has(u.host.toLowerCase())) return fail(400, "Không rút gọn link của chính hệ thống này");
  if (alias && (!ALIAS_RE.test(alias) || RESERVED.has(alias.toLowerCase()))) {
    return fail(400, "Alias gồm 3-32 ký tự chữ, số, _ hoặc - (không dùng từ dành riêng)");
  }

  const hours = intIn(body.expires_in, 1, 8760), maxc = intIn(body.max_clicks, 1, 10000000);
  if (Number.isNaN(hours) || Number.isNaN(maxc)) return fail(400, "Thời hạn hoặc số lượt tối đa không hợp lệ");
  const pw = typeof body.password === "string" ? body.password : "";
  const noCheck = body.no_check === true;
  if (pw && (pw.length < 4 || pw.length > 64)) return fail(400, "Mật khẩu link gồm 4-64 ký tự");

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

  const expiresAt = hours ? new Date(Date.now() + hours * 3600e3).toISOString() : null;
  const salt = pw ? randomBytes(16).toString("hex") : null;
  const passHash = pw ? hashPw(pw, salt).toString("hex") : null;
  const rec = { url, created_ip: ip, expires_at: expiresAt, max_clicks: maxc, pass_hash: passHash, pass_salt: salt, no_check: noCheck };
  const base = baseUrl(req);
  let code = null;
  if (alias) {
    if ((await store("link_create", { ...rec, code: alias, short_url: `${base}/${alias}` })).conflict) return fail(409, "Alias đã tồn tại");
    code = alias;
  } else {
    for (let i = 0; i < 10 && !code; i++) {
      const c = newCode(cfg.code_length);
      if (!(await store("link_create", { ...rec, code: c, short_url: `${base}/${c}` })).conflict) code = c;
    }
    if (!code) return fail(500, "Không sinh được mã ngắn");
  }
  dropLink(code);

  log(req, { action: "create", code, status: 201, detail: url });
  res.status(201).json({ code, short_url: `${base}/${code}`, qr_url: `${base}/api/qr?code=${code}`, url,
    expires_at: expiresAt, max_clicks: maxc, protected: !!pw, no_check: noCheck });
}

// GET /api/stats?code=abc
//  • Công khai: chỉ trả tổng lượt (đủ cho nút "Xem số liệu" ở trang chủ), có giới hạn tốc độ.
//  • Kèm x-admin-key / phiên admin: trả đủ phân tích (ngày, nguồn, quốc gia, thiết bị...), tính từ tab logs.
const STATS_LIMIT = Number(process.env.STATS_RATE_LIMIT_PER_MIN) || 60;
async function stats(req, res) {
  const code = String(req.query.code || "");
  if (!ALIAS_RE.test(code)) return res.status(404).json({ error: "Không tìm thấy link" });
  res.setHeader("Cache-Control", "no-store");

  const isAdmin = !!(req.headers["x-admin-key"] || req.headers["x-admin-session"]);
  if (isAdmin && !(await requireAdmin(req, res))) return;
  if (!isAdmin && hit("stats", clientInfo(req).ip, STATS_LIMIT)) {
    return res.status(429).json({ error: "Xem số liệu quá nhanh, thử lại sau" });
  }

  const l = await getLink(code, { fresh: true });
  if (!l) return res.status(404).json({ error: "Không tìm thấy link" });
  const link = { code: l.code, url: l.url, clicks: l.clicks, scans: l.scans, created_at: l.created_at };
  if (!isAdmin) { const { url: _hidden, ...pub } = link; return res.json(pub); } // link có mật khẩu: không được lộ đích đến cho người ngoài
  const d = await store("stats", { code });
  if (d.notfound) return res.status(404).json({ error: "Không tìm thấy link" });
  res.json({ ...link, ...d });
}

// GET /api/qr?code=abc&format=png|svg&download=1
async function qr(req, res) {
  const code = String(req.query.code || "");
  if (!ALIAS_RE.test(code)) return res.status(400).json({ error: "code không hợp lệ" });

  if (!(await getLink(code))) return res.status(404).json({ error: "Không tìm thấy link" });

  const cfg = await getSettings();
  const fmt = ["png", "svg"].includes(req.query.format) ? req.query.format : cfg.qr_format;
  const target = `${baseUrl(req)}/${code}?src=qr`; // ?src=qr để phân biệt lượt quét với lượt bấm
  const hex = (v, def) => (/^[0-9a-fA-F]{6}$/.test(String(v || "")) ? "#" + v : def); // ?fg=000000&bg=ffffff
  const opts = {
    width: cfg.qr_size,
    margin: cfg.qr_margin,
    errorCorrectionLevel: cfg.qr_error_level,
    color: { dark: hex(req.query.fg, cfg.qr_foreground), light: hex(req.query.bg, cfg.qr_background) },
  };

  try {
    let body;
    const shape = SHAPES.includes(req.query.shape) ? req.query.shape : "square";
    if (fmt === "svg" && shape !== "square") {
      body = shapedSvg(target, { size: cfg.qr_size, margin: cfg.qr_margin, level: cfg.qr_error_level, dark: opts.color.dark, light: opts.color.light, shape });
      res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    } else if (fmt === "png") { // PNG luôn là kiểu vuông; kiểu khác do trình duyệt tự vẽ lại từ SVG
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
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const REASONS = { phishing: "Lừa đảo / giả mạo", malware: "Mã độc / virus", illegal: "Nội dung bị cấm", spam: "Spam", other: "Lý do khác" };
const head = (title) => `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex"><meta name="theme-color" content="#07080f" media="(prefers-color-scheme: dark)"><meta name="theme-color" content="#f4f6fc" media="(prefers-color-scheme: light)"><title>${title}</title><link rel="icon" href="/icons/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css?v=16"></head>`;
// Các trang này dùng chung style.css với trang chủ (tự đổi sáng/tối, cùng font, cùng kích thước nút). Form báo cáo vẫn là form HTML thuần, không cần JavaScript.
const tail = `<p class="gfoot"><a href="/terms.html">Điều khoản</a> · <a href="https://by.com.vn/" target="_blank" rel="noopener">Design by Tuankiet</a></p></main></body></html>`;
const reportForm = (code) => `<details class="greport"><summary>Báo cáo link này</summary>
<form method="post" action="/api/index?op=report"><input type="hidden" name="code" value="${esc(code)}"><input name="website" tabindex="-1" autocomplete="off" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0">
<select class="fld" name="reason" aria-label="Lý do">${Object.entries(REASONS).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
<input class="fld" name="note" maxlength="300" placeholder="Ghi chú (không bắt buộc)" aria-label="Ghi chú">
<button class="b p">Gửi báo cáo</button></form></details>`;
const page = (title, big, msg, code) => `${head(title)}<body class="gate"><main><h1>${big}</h1><p>${msg}</p>
<p><a class="go" href="/">Tạo link mới</a></p>${code ? reportForm(code) : ""}${tail}`;
const notFoundPage = () => page("Link không tồn tại", "404", "Link này không tồn tại hoặc đã bị xoá. Hãy kiểm tra lại cách gõ, hoặc tạo một link mới.");
const expiredPage = (code) => page("Link đã hết hạn", "410", "Link này đã hết hạn hoặc hết lượt truy cập. Hãy liên hệ người gửi để xin link mới.", code);
const passPage = (msg = "", code = "") => `${head("Link được bảo vệ")}<body class="gate"><main><h1 class="sm">Link được bảo vệ bằng mật khẩu</h1>
<form method="post" action=""><input class="fld" type="password" name="password" required autofocus autocomplete="off" placeholder="Nhập mật khẩu" aria-label="Mật khẩu">
<button class="go">Mở link</button></form>
<p class="err" role="alert">${msg}</p>${code ? reportForm(code) : ""}${tail}`;
// Trang chờ 1-2 giây trước khi chuyển đến đích: hiện tên miền đích để người mở link biết mình sắp đi đâu
const waitPage = (url, ms, code) => {
  let host = ""; try { host = new URL(url).hostname.replace(/^www\./, ""); } catch {}
  const sec = Math.max(1, Math.round(ms / 1000));
  const js = JSON.stringify(url).replace(/</g, "\\u003c");
  return head("Đang chuyển hướng").replace("</head>", `<noscript><meta http-equiv="refresh" content="${sec};url=${esc(url)}"></noscript></head>`) +
    `<body class="gate"><main><h1 class="sm">Đang chuyển bạn đến</h1><p class="goto"><b>${esc(host)}</b></p>
<div class="loadbar" aria-hidden="true"><i style="animation-duration:${ms}ms"></i></div>
<p><a class="go" href="${esc(url)}" rel="noopener noreferrer">Đi ngay</a></p>${reportForm(code)}${tail.replace("</body>", `<script>setTimeout(function(){location.replace(${js})},${ms})</script></body>`)}`;
};
const disabledPage = (code) => page("Link đã bị khoá", "410", "Link này đã bị khoá nên không thể truy cập.", code);

// GET /<code> — chuyển hướng + đếm lượt. Link có mật khẩu: GET hiện form, POST kiểm tra rồi chuyển hướng (303)
// Đường nóng: đọc link (RAM 20 giây, nếu không có thì hỏi Sheet) → chuyển hướng ngay; cộng lượt + ghi nhật ký chạy nền (một lần gọi Sheet).
// Link có giới hạn lượt thì cộng lượt TRƯỚC khi chuyển (Sheet kiểm tra lại dưới khoá nên không vượt số lượt tối đa).
async function redirect(req, res) {
  const code = String(req.query.code || "");
  res.setHeader("Cache-Control", "no-store"); // mỗi lượt bấm đều đi qua server
  const html = (st, p) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.status(st).send(p); };
  // Đường dẫn rác (/wp-login.php, /.env, mã quá dài...) trả 404 ngay: không hỏi Sheet, không ghi nhật ký
  if (!["GET", "HEAD", "POST"].includes(req.method)) { res.setHeader("Allow", "GET, HEAD, POST"); return res.status(405).end(); } // OPTIONS/PUT/DELETE không được tính lượt
  if (!ALIAS_RE.test(code)) return req.method === "HEAD" ? res.status(404).end() : html(404, notFoundPage());

  const [l, cfg] = await Promise.all([getLink(code, { neg: true }), getSettings()]);
  const gone = l && ((l.expires_at && Date.parse(l.expires_at) <= Date.now()) || (l.max_clicks && l.clicks >= l.max_clicks));

  // HEAD (bot xem trước, kiểm tra link) chỉ trả đích, không đếm; khoá/hết hạn thì 410
  if (req.method === "HEAD") {
    if (!l) return res.status(404).end();
    if (l.disabled || gone) return res.status(410).end();
    return l.protected ? res.status(200).end() : res.redirect(302, l.url);
  }
  if (!l) { // quét web (/wp-admin, /phpmyadmin...) chỉ ghi tối đa 10 lần / phút / IP để không làm đầy tab logs
    if (!hit("notfound", clientInfo(req).ip, 10)) log(req, { action: "not_found", code, status: 404 });
    return html(404, notFoundPage());
  }
  if (l.disabled) { log(req, { action: "disabled_click", code, status: 410 }); return html(410, disabledPage(code)); }
  if (gone) { log(req, { action: "expired_click", code, status: 410 }); return html(410, expiredPage(code)); }

  const fromQr = req.query.src === "qr";
  const { ip, is_bot } = clientInfo(req);
  if (l.protected) {
    // Link có mật khẩu nhưng không còn mã băm (chuyển từ bản cũ chỉ có cờ "có mật khẩu"): không thể xác thực nên khoá lại
    if (!l.pass_hash) { log(req, { action: "disabled_click", code, status: 410 }); return html(410, disabledPage(code)); }
    if (req.method !== "POST" || is_bot) return html(200, passPage("", code));
    if (hit("unlock", ip, 10)) return html(429, passPage("Thử quá nhiều lần, hãy đợi một lát.", code));
    const pw = req.body && typeof req.body.password === "string" ? req.body.password.slice(0, 64) : "";
    if (!checkPw(pw, l)) { log(req, { action: "wrong_password", code, status: 403 }); return html(403, passPage("Mật khẩu không đúng.", code)); }
  }
  // Bot / trình xem trước link chỉ được chuyển hướng, KHÔNG cộng lượt; ghi riêng 'bot_click'
  if (is_bot) { log(req, { action: "bot_click", code, status: 302, detail: l.url }); return res.redirect(302, l.url); }

  const action = fromQr ? "scan" : "click";
  const entry = logRow(req, { action, code, status: 302, detail: l.url });
  const count = () => store("click", { code, qr: fromQr, log: entry });
  if (l.max_clicks) {
    const r = await count();
    dropLink(code);
    if (!r.ok) { log(req, { action: "expired_click", code, status: 410 }); return html(410, expiredPage(code)); }
    bg(afterClick(req, code, l.url, r, action));
  } else {
    bg(count().then((r) => { dropLink(code); return afterClick(req, code, l.url, r, action); }).catch((e) => console.error("click lỗi:", e.message)));
  }
  const ms = cfg.redirect_delay_ms;
  if (ms > 0) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.status(200).send(waitPage(l.url, ms, code)); }
  res.redirect(req.method === "POST" ? 303 : 302, l.url);
}
// Sau khi đã cộng lượt: báo Telegram (nền): thao tác, chạm giới hạn lượt, hoặc đột biến (chỉ kiểm tra mỗi 10 lượt)
async function afterClick(req, code, url, r, action) {
  if (!r.ok || !telegramOn()) return;
  await teleOp(clientInfo(req), { action, code, status: 302, detail: url });
  const clicks = Number(r.clicks), cap = r.max_clicks ? Number(r.max_clicks) : 0, base = baseUrl(req), to = dest(url);
  if (cap && clicks >= cap) await alertOnce(code, "limit", `⛔ Link đã hết lượt mở\n${base}/${code} → ${to}\nĐã đủ ${cap} lượt nên link tự ngừng hoạt động. Muốn mở lại: /admin → Sửa → tăng giới hạn lượt.`);
  else if (clicks % 10 === 0) await checkSpike(code, base, to);
}
// Tên miền đích rút gọn để tin Telegram dễ đọc
const dest = (u) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return String(u).slice(0, 60); } };
async function checkSpike(code, base, to) {
  try {
    const th = (await getSettings()).alert_spike_clicks;
    if (!th) return;
    const { logs } = await store("logs_list", { code, actions: ["click", "scan"], from: new Date(Date.now() - 600e3).toISOString(), limit: 5000 });
    const n = logs.length;
    if (n >= th) await alertOnce(code, "spike", `📈 Link tăng lượt đột biến\n${base}/${code} → ${to}\n${n} lượt trong 10 phút qua (ngưỡng báo: ${th}). Nếu không phải bạn chạy quảng cáo, hãy kiểm tra xem link có bị lạm dụng không.`, 1);
  } catch (e) { console.error("checkSpike lỗi:", e.message); }
}

/* ───────── Quản trị (cần x-admin-key hoặc phiên admin) ───────── */

// GET /api/links?q=&limit=50   PATCH /api/links?code=abc {disabled...}   DELETE /api/links?code=abc
async function links(req, res) {
  if (!(await requireAdmin(req, res))) return;

  if (req.method === "DELETE") {
    const code = String(req.query.code || "");
    const r = await store("link_delete", { code });
    dropLink(code);
    if (r.notfound) return res.status(404).json({ error: "Không tìm thấy link" });
    log(req, { action: "link_delete", code, status: 200, detail: r.url });
    return res.json({ ok: true });
  }
  if (req.method === "PATCH") { // khoá/mở khoá, đổi hạn, đổi giới hạn lượt, gỡ mật khẩu (không mất số liệu)
    const code = String(req.query.code || "");
    const b = req.body && typeof req.body === "object" ? req.body : {};
    const has = (k) => Object.hasOwn(b, k);
    const bad = (m) => res.status(400).json({ error: m });
    if (has("disabled") && typeof b.disabled !== "boolean") return bad("disabled phải là true hoặc false");
    if (has("no_check") && typeof b.no_check !== "boolean") return bad("no_check phải là true hoặc false");
    if (has("clear_password") && b.clear_password !== true) return bad("clear_password chỉ nhận true");
    // null = bỏ hạn / bỏ giới hạn; số = đặt mới (hạn tính từ lúc này)
    const hours = has("expires_in") ? (b.expires_in === null ? null : intIn(b.expires_in, 1, 87600)) : null;
    const maxc = has("max_clicks") ? (b.max_clicks === null ? null : intIn(b.max_clicks, 1, 10000000)) : null;
    if (Number.isNaN(hours) || Number.isNaN(maxc)) return bad("Thời hạn hoặc số lượt tối đa không hợp lệ");
    if (!["disabled", "expires_in", "max_clicks", "clear_password", "no_check"].some(has)) return bad("Không có gì để cập nhật");
    const patch = {};
    if (has("disabled")) patch.disabled = b.disabled;
    if (has("expires_in")) patch.expires_at = hours ? new Date(Date.now() + hours * 3600e3).toISOString() : null;
    if (has("max_clicks")) patch.max_clicks = maxc;
    if (has("no_check")) patch.no_check = b.no_check;
    if (b.clear_password === true) patch.clear_password = true;
    const r = await store("link_update", { code, patch });
    dropLink(code);
    if (r.notfound) return res.status(404).json({ error: "Không tìm thấy link" });
    if (has("expires_in") || has("max_clicks")) await store("alert_delete", { code, kinds: ["limit", "expiring"] });
    const onlyLock = has("disabled") && Object.keys(b).length === 1;
    log(req, { action: onlyLock ? (b.disabled ? "link_disable" : "link_enable") : "link_update", code, status: 200,
      detail: onlyLock ? "" : JSON.stringify(b) });
    const l = r.link;
    return res.json({ ok: true, disabled: l.disabled, expires_at: l.expires_at, max_clicks: l.max_clicks, no_check: l.no_check, protected: l.protected });
  }
  if (req.method !== "GET") return res.status(405).json({ error: "Chỉ hỗ trợ GET, PATCH hoặc DELETE" });

  const q = String(req.query.q || "").slice(0, 100);
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  res.json(await store("links_list", { q, limit }));
}

// GET /api/logs?limit=100&action=click&code=abc&from=2026-11-01&format=csv
async function logs(req, res) {
  if (!(await requireAdmin(req, res))) return;

  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 5000);
  const action = req.query.action ? String(req.query.action) : null; // ?action=a&action=b từng làm lỗi 500
  const code = req.query.code ? String(req.query.code) : null;
  // from sai định dạng thì bỏ qua (trước đây gây lỗi 500)
  const from = req.query.from && !Number.isNaN(Date.parse(req.query.from)) ? new Date(req.query.from).toISOString() : null;
  const ip = req.query.ip ? String(req.query.ip).slice(0, 45) : null;

  const rows = (await store("logs_list", { action, code, ip, from, limit })).logs;

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

/* ───────── Tiện ích mới (đồng bộ, gợi ý tên, sparkline, báo cáo, giám sát) ───────── */
const bodyOf = (req) => (req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {});
const cleanCodes = (a) => [...new Set((Array.isArray(a) ? a : []).filter((c) => typeof c === "string" && ALIAS_RE.test(c)))].slice(0, 200);

// Mã khôi phục: 16 ký tự (80 bit), chỉ lưu SHA-256 của mã. Ai có mã thì xem được danh sách link, nên không dùng cho việc nào khác.
const RC_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const rcFmt = (v) => v.match(/.{4}/g).join("-");
// POST /api/index?op=sync {action: create|save|restore, recovery?, codes?, remove?}
async function sync(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });
  const { ip } = clientInfo(req), b = bodyOf(req);
  if (hit("sync", ip, 30)) return res.status(429).json({ error: "Thao tác quá nhanh, thử lại sau" });

  if (b.action === "create") {
    if (hit("sync_create", ip, 5)) return res.status(429).json({ error: "Tạo mã quá nhanh, thử lại sau" });
    const rc = Array.from({ length: 16 }, () => RC_ALPHA[randomInt(RC_ALPHA.length)]).join("");
    await store("recovery_create", { id: sha256(rc), codes: cleanCodes(b.codes) });
    log(req, { action: "sync_create", status: 200 }); // không ghi mã vào nhật ký
    return res.json({ recovery: rcFmt(rc) });
  }
  const rc = String(b.recovery || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (rc.length !== 16) return res.status(400).json({ error: "Mã khôi phục không hợp lệ" });
  const id = sha256(rc);
  const row = await store("recovery_get", { id });
  if (!row.found) return res.status(404).json({ error: "Không tìm thấy mã khôi phục" });
  const stored = cleanCodes(row.codes);

  if (b.action === "save") { // gộp (không ghi đè): máy nào thêm link cũng không làm mất link của máy khác; xoá phải nêu rõ trong `remove`
    const remove = new Set(cleanCodes(b.remove));
    const merged = cleanCodes([...cleanCodes(b.codes), ...stored]).filter((c) => !remove.has(c));
    await store("recovery_set", { id, codes: merged });
    return res.json({ ok: true, count: merged.length });
  }
  if (b.action === "restore") {
    const found = stored.length ? (await store("links_by_codes", { codes: stored })).links : [];
    const links = found.map((l) => ({ code: l.code, url: l.protected ? "" : l.url, created_at: l.created_at, expires_at: l.expires_at,
      max_clicks: l.max_clicks, disabled: l.disabled, protected: l.protected })).sort((x, y) => String(y.created_at).localeCompare(String(x.created_at)));
    if (links.length !== stored.length) { // link đã bị xoá thì bỏ khỏi mã
      await store("recovery_set", { id, codes: links.map((l) => l.code) });
    }
    log(req, { action: "sync_restore", status: 200, detail: `${links.length} link` });
    const base = baseUrl(req);
    return res.json({ recovery: rcFmt(rc), links: links.map((l) => ({ ...l, short_url: `${base}/${l.code}`, qr_url: `${base}/api/qr?code=${l.code}` })) });
  }
  res.status(400).json({ error: "action không hợp lệ" });
}

// Tiêu đề trang → tên riêng không dấu, tối đa 32 ký tự, cắt ở ranh giới từ
const slugify = (t) => {
  let s = String(t).normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/đ/gi, "d").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (s.length > 32) { const cut = s.lastIndexOf("-", 32); s = s.slice(0, cut >= 8 ? cut : 32).replace(/-+$/, ""); }
  return s.length >= 3 ? s : "";
};
const decodeEntities = (t) => t.replace(/&(#x?[0-9a-f]+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
  const k = e.toLowerCase();
  if (k[0] === "#") { const n = k[1] === "x" ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10); return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ""; }
  return { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " }[k];
});
const pageTitle = (html) => {
  const og = html.match(/<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']+)["']/i) || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]*property=["']og:title["']/i);
  const raw = og ? og[1] : (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "";
  return decodeEntities(raw).replace(/\s+/g, " ").trim().slice(0, 150);
};
// GET /api/index?op=suggest&url=... → {title, alias}. Server tải trang đích nên phải qua safeGet (chống SSRF) và có giới hạn tốc độ.
async function suggest(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (hit("suggest", clientInfo(req).ip, 15)) return res.status(429).json({ error: "Gợi ý quá nhanh, thử lại sau" });
  let u;
  try { u = new URL(String(req.query.url || "")); if (!["http:", "https:"].includes(u.protocol)) throw new Error(); }
  catch { return res.status(400).json({ error: "Link không hợp lệ" }); }
  let title = "";
  try { title = pageTitle((await safeGet(u.href, { maxBytes: 65536, timeoutMs: 4000 })).body); } catch { /* không lấy được thì trả rỗng, không lộ lý do */ }
  const base = slugify(title);
  if (!base) return res.json({ title, alias: null });
  for (let i = 0; i < 5; i++) {
    const cand = i === 0 ? base : base.slice(0, 28).replace(/-+$/, "") + "-" + (i === 1 ? "2" : newCode(3).toLowerCase());
    if (RESERVED.has(cand)) continue;
    if (!(await getLink(cand, { fresh: true }))) return res.json({ title, alias: cand });
  }
  res.json({ title, alias: null });
}

// POST /api/index?op=spark {codes:[...]} → số lượt 7 ngày gần nhất (giờ Việt Nam) cho từng link
async function spark(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });
  if (hit("spark", clientInfo(req).ip, 60)) return res.status(429).json({ error: "Quá nhanh, thử lại sau" });
  const codes = cleanCodes(bodyOf(req).codes).slice(0, 40);
  if (!codes.length) return res.json({ days: [], spark: {} });
  res.json(await store("spark", { codes }));
}

// POST /api/index?op=report (form hoặc JSON): code, reason, note. Ghi vào nhật ký (action "report") và báo Telegram nếu có.
async function report(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });
  const asJson = String(req.headers["content-type"] || "").includes("application/json"), b = bodyOf(req);
  const done = (st, msg) => asJson ? res.status(st).json(st < 400 ? { ok: true } : { error: msg })
    : (res.setHeader("Content-Type", "text/html; charset=utf-8"), res.status(st).send(page(st < 400 ? "Đã nhận báo cáo" : "Có lỗi", st < 400 ? "✓" : "!", esc(msg))));
  if (typeof b.website === "string" && b.website) return done(200, "Cảm ơn bạn. Chúng tôi sẽ xem xét và khoá link nếu vi phạm."); // ô bẫy bot: người thật không thấy nên không điền
  if (hit("report", clientInfo(req).ip, 5)) return done(429, "Gửi quá nhiều báo cáo, hãy thử lại sau.");
  // Chấp nhận cả mã lẫn link ngắn đầy đủ: lấy đoạn cuối của đường dẫn
  const code = String(b.code || "").trim().split(/[?#]/)[0].split("/").filter(Boolean).pop() || "";
  if (!ALIAS_RE.test(code)) return done(400, "Mã link không hợp lệ.");
  const reason = Object.hasOwn(REASONS, b.reason) ? b.reason : "other";
  const note = String(b.note || "").replace(/\s+/g, " ").trim().slice(0, 300);
  const l = await getLink(code, { fresh: true });
  if (l) { // link không tồn tại thì không ghi nhật ký (tránh làm đầy tab logs bằng mã bịa) và báo lỗi cho người gửi
    await logOp(req, { action: "report", code, status: 200, detail: `${REASONS[reason]}${note ? ": " + note : ""}` });
    const n = (await store("logs_list", { code, action: "report", from: new Date(Date.now() - 864e5).toISOString(), limit: 1000 })).logs.length;
    // Gộp: mỗi link chỉ báo Telegram tối đa 1 lần / giờ (mọi báo cáo vẫn nằm trong Nhật ký)
    bg(alertOnce(code, "report", `🚩 Có người báo cáo link vi phạm\n${baseUrl(req)}/${code} → ${l.url}\nLý do: ${REASONS[reason]}${note ? "\nGhi chú: " + note : ""}\nĐây là báo cáo thứ ${n} trong 24 giờ. Nếu đúng vi phạm: /admin → Khoá.`, 1));
  } else return done(404, "Không tìm thấy link với mã này. Hãy kiểm tra lại mã hoặc dán đúng link ngắn."); // trước đây vẫn báo "Cảm ơn" dù không ghi gì, dễ tưởng báo cáo đã được nhận
  done(200, "Cảm ơn bạn. Chúng tôi sẽ xem xét và khoá link nếu vi phạm.");
}

// GET /api/index?op=health (rewrite /health): cho UptimeRobot... biết web và Google Sheet còn sống
async function health(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try { await store("ping"); res.json({ ok: true, db: true, time: new Date().toISOString() }); }
  catch (e) { console.error("health:", e.message); res.status(503).json({ ok: false, db: false }); }
}

// GET /api/index?op=watch — Vercel Cron hằng ngày hoặc admin: báo link sắp hết hạn, kiểm tra link đích còn sống. ?test=1 gửi tin thử, ?n=30 số link kiểm tra mỗi lượt.
async function watch(req, res) {
  const cs = (process.env.CRON_SECRET || "").trim();
  const isCron = cs && same(String(req.headers.authorization || ""), `Bearer ${cs}`);
  if (!isCron && !(await requireAdmin(req, res))) return;
  res.setHeader("Cache-Control", "no-store");
  const base = baseUrl(req);
  if (req.query.test) {
    return res.json({ ok: true, sent: await notify(`✅ Telegram đã kết nối với ${base}\n\nChọn thao tác nào được báo ở /admin → Cài đặt → «Telegram: báo những thao tác nào».`) });
  }

  // Tin tổng hợp: mỗi lượt chạy chỉ gửi TỐI ĐA 1 tin (trước đây mỗi link một tin nên dễ bị dội tin)
  const claimed = [], expList = [], deadList = [];
  const cfg = await getSettings();
  const all = (await store("links_all")).links, now = Date.now();
  // Chỉ báo link có hạn ban đầu >= N ngày: link 1 giờ / 1 ngày do khách tự đặt hết hạn là chuyện bình thường, không cần báo
  const minMs = cfg.alert_expiring_min_days * 864e5;
  const soon = cfg.alert_expiring_min_days ? all.filter((l) => !l.disabled && l.expires_at && Date.parse(l.expires_at) > now &&
    Date.parse(l.expires_at) <= now + 864e5 && Date.parse(l.expires_at) - Date.parse(l.created_at) >= minMs)
    .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at)).slice(0, 50) : [];
  for (const l of soon) {
    if (!(await claimAlert(l.code, "expiring"))) continue;
    claimed.push([l.code, "expiring"]);
    expList.push(`• /${l.code} (${dest(l.url)}), hết hạn ${new Date(l.expires_at).toLocaleString("vi-VN", { timeZone: "Asia/Ho_Chi_Minh", dateStyle: "short", timeStyle: "short" })}`);
  }

  // Link đích "chết" = lỗi mạng, 404, 410 hoặc 5xx, và phải sai 2 lần liên tiếp mới gắn nhãn (tránh báo nhầm khi trang đích chập chờn).
  // 401/403/429 coi như còn sống vì nhiều trang chặn bot.
  const n = Math.min(Math.max(Number(req.query.n) || 25, 1), 40);
  const due = all.filter((l) => !l.disabled && !l.no_check && (!l.expires_at || Date.parse(l.expires_at) > now) &&
    (!l.last_check || Date.parse(l.last_check) < now - 20 * 3600e3))
    .sort((a, b) => (a.last_check ? Date.parse(a.last_check) : 0) - (b.last_check ? Date.parse(b.last_check) : 0)).slice(0, n);
  const results = await Promise.all(due.map(async (l) => {
    let status = 0, skip = false;
    try { status = (await safeGet(l.url, { maxBytes: 2048, timeoutMs: 4000, redirects: 3 })).status; } catch (e) { skip = !!e.skip; } // cổng lạ (:8080...) → không kiểm tra, không coi là chết
    return { ...l, status, skip, bad: !skip && (status === 0 || status === 404 || status === 410 || status >= 500) };
  }));
  if (results.length) {
    await store("link_check_update", { updates: results.map((r) => ({ code: r.code, last_status: r.skip ? null : r.status, fail_count: r.bad ? r.fail_count + 1 : 0 })) });
  }
  let dead = 0;
  for (const r of results) {
    if (r.bad && r.fail_count + 1 >= 2) {
      dead++;
      if (await claimAlert(r.code, "dead")) { claimed.push([r.code, "dead"]); deadList.push(`• /${r.code}: ${r.status ? "HTTP " + r.status : "không kết nối được"} → ${r.url.slice(0, 80)}`); }
    } else if (!r.bad && r.fail_count >= 2) await store("alert_delete", { code: r.code, kinds: ["dead"] });
  }
  const expiring = expList.length;
  if (expiring || deadList.length) {
    const cut = (a) => a.length > 12 ? [...a.slice(0, 12), `… và ${a.length - 12} link khác (xem trong /admin)`] : a;
    const text = [`📋 Tổng hợp hằng ngày · ${base}`,
      expiring && `\n⏳ Sắp hết hạn trong 24 giờ (${expiring}):\n${cut(expList).join("\n")}`,
      deadList.length && `\n💀 Trang đích bị lỗi (${deadList.length}):\n${cut(deadList).join("\n")}`].filter(Boolean).join("\n");
    if (!(await notify(text))) await Promise.all(claimed.map(([c, k]) => releaseAlert(c, k))); // gửi hỏng: lần sau báo lại
  }
  log(req, { action: "watch", status: 200, detail: `expiring ${expiring}, checked ${results.length}, dead ${dead}` });
  res.json({ ok: true, expiring, checked: results.length, dead, remaining_hint: results.length === n ? "còn link chưa kiểm tra, chạy lại để tiếp tục" : "" });
}

/* ───────── Router ───────── */
// GET /api/cleanup — Vercel Cron (Authorization: Bearer CRON_SECRET) hoặc admin: xoá nhật ký quá hạn (chỉ khi đặt số ngày lưu > 0)
async function cleanup(req, res) {
  const cs = (process.env.CRON_SECRET || "").trim();
  const isCron = cs && same(String(req.headers.authorization || ""), `Bearer ${cs}`);
  if (!isCron && !(await requireAdmin(req, res))) return;
  const n = await purgeLogs();
  log(req, { action: "purge", status: 200, detail: `deleted ${n}` });
  res.json({ ok: true, deleted: n });
}
// GET /api/index?op=reports — các link bị báo cáo trong 7 ngày gần nhất (cho tab "Báo cáo" ở /admin)
async function reports(req, res) {
  if (!(await requireAdmin(req, res))) return;
  res.json(await store("reports", { days: 7 }));
}
// POST /api/index?op=logout[&all=1] — đăng xuất phiên hiện tại (giải phóng 1 chỗ trong 2 chỗ), hoặc mọi thiết bị
async function logout(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });
  if (!(await requireAdmin(req, res))) return;
  if (req.query.all === "1") {
    await store("session_delete_all");
    log(req, { action: "admin_revoke_all", status: 200, detail: "Đăng xuất mọi thiết bị (thủ công)" });
  } else {
    await store("session_delete", { id: sha256(String(req.headers["x-admin-session"] || "")) });
  }
  res.json({ ok: true });
}
const routes = { logout, reports, shorten, check, stats, qr, r: redirect, links, logs, settings, cleanup, sync, suggest, spark, report, health, watch };

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
