// ===== BACKEND GOOGLE SHEET: Sheet là database DUY NHẤT của hệ thống rút gọn link =====
// Cài đặt (làm một lần), xem README-chuyen-sheet.md:
//  1) Dán file này vào Apps Script GẮN VỚI Google Sheet (Extensions → Apps Script), thay toàn bộ script cũ.
//  2) Project Settings → Script properties → thêm TOKEN = chuỗi bí mật (trùng SHEET_TOKEN trên Vercel).
//  3) Chọn hàm caiDat → Chạy → cấp quyền.
//  4) Deploy → New deployment → Web app → Execute as: Me, Who has access: Anyone → copy URL (/exec) làm SHEET_URL trên Vercel.
// Các tab: links, logs, config, recoveries, alerts, sessions (+ tong_hop để xem thống kê). Tab "settings" cũ không còn dùng.

const TZ = "Asia/Ho_Chi_Minh";
const MAX_CELL = 2000;

// Giữ nguyên 14 cột đầu như script cũ (tab tong_hop vẫn chạy); cột mới thêm ở cuối
const LINK_H = ["code", "url", "clicks", "scans", "created_at", "created_ip", "disabled", "expires_at", "max_clicks", "protected", "no_check", "dead", "last_status", "short_url", "pass_hash", "pass_salt", "last_check", "fail_count"];
const LOG_H = ["id", "time", "action", "code", "ip", "user_agent", "referrer", "status", "detail", "country", "city", "device", "browser", "os", "is_bot", "meta"];
const TABS = {
  links: LINK_H,
  logs: LOG_H,
  config: ["key", "value", "updated_at"],
  recoveries: ["id", "codes", "created_at", "updated_at"],
  alerts: ["code", "kind", "ts"],
  sessions: ["id", "created_at", "ip", "ua"],
};
const LINK_TEXT_RANGES = (r) => ["A" + r + ":B" + r, "E" + r + ":H" + r, "J" + r + ":L" + r, "N" + r + ":Q" + r];

/* ───────── Tiện ích ───────── */

const _sheets = {};
function sheet(name) {
  if (_sheets[name]) return _sheets[name];
  const headers = TABS[name], ss = SpreadsheetApp.getActiveSpreadsheet();
  const sh = ss.getSheetByName(name) || ss.insertSheet(name);
  if (sh.getLastRow() === 0) {
    sh.getRange(1, 1, 1, headers.length).setValues([headers]).setFontWeight("bold");
    sh.setFrozenRows(1);
  } else if (sh.getRange(1, 1, 1, headers.length).getValues()[0].join("|") !== headers.join("|")) {
    sh.getRange(1, 1, 1, headers.length).setValues([headers]).setFontWeight("bold"); // tab cũ thiếu cột mới
  }
  return (_sheets[name] = sh);
}

const clean = (v) => (v === null || v === undefined ? "" : String(v).slice(0, MAX_CELL));
function vn(d) {
  const x = d instanceof Date ? d : new Date(d);
  return isNaN(x) ? "" : Utilities.formatDate(x, TZ, "yyyy-MM-dd HH:mm:ss");
}
function parseTime(v) {
  if (v === "" || v === null || v === undefined) return null;
  if (v instanceof Date) return v;
  const s = String(v).trim(), m = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$/.exec(s);
  const d = m ? new Date(m[1] + "T" + m[2] + "+07:00") : new Date(s);
  return isNaN(d) ? null : d;
}
const iso = (v) => { const d = parseTime(v); return d ? d.toISOString() : null; };
const tstr = (v) => (v instanceof Date ? vn(v) : String(v)); // chuỗi giờ VN, so sánh được theo thứ tự chữ

function withLock(fn) {
  const lock = LockService.getScriptLock();
  lock.waitLock(25000);
  try { return fn(); } finally { lock.releaseLock(); }
}

const cache = () => CacheService.getScriptCache();
function cget(k) { try { const v = cache().get(k); return v ? JSON.parse(v) : null; } catch (e) { return null; } }
function cput(k, v, sec) { try { const t = JSON.stringify(v); if (t.length < 90000) cache().put(k, t, sec); } catch (e) {} }
function cdel(k) { try { cache().remove(k); } catch (e) {} }

// Tìm dòng (số thứ tự trong Sheet) có ô ở cột `col` bằng đúng `val`; 0 nếu không có
function findRow(sh, col, val) {
  const n = sh.getLastRow();
  if (n < 2) return 0;
  const f = sh.getRange(2, col, n - 1, 1).createTextFinder(String(val)).matchEntireCell(true).matchCase(true).findNext();
  return f ? f.getRow() : 0;
}

/* ───────── Link ───────── */

function linkFromRow(r) {
  const num = (v) => (v === "" || v === null || v === undefined ? null : Number(v));
  return {
    code: String(r[0]), url: String(r[1]), clicks: Number(r[2]) || 0, scans: Number(r[3]) || 0,
    created_at: iso(r[4]), created_ip: r[5] ? String(r[5]) : null,
    disabled: r[6] === "đã khoá", expires_at: iso(r[7]), max_clicks: num(r[8]) || null,
    protected: r[9] === "có mật khẩu", no_check: r[10] === "không kiểm tra", dead: r[11] === "đích lỗi",
    last_status: num(r[12]), short_url: r[13] ? String(r[13]) : "",
    pass_hash: r[14] ? String(r[14]) : null, pass_salt: r[15] ? String(r[15]) : null,
    last_check: iso(r[16]), fail_count: Number(r[17]) || 0,
  };
}
function linkToRow(l) {
  return [l.code, l.url, l.clicks || 0, l.scans || 0, vn(l.created_at), clean(l.created_ip),
    l.disabled ? "đã khoá" : "", l.expires_at ? vn(l.expires_at) : "", l.max_clicks || "",
    l.protected ? "có mật khẩu" : "", l.no_check ? "không kiểm tra" : "", l.dead ? "đích lỗi" : "",
    l.last_status === null || l.last_status === undefined ? "" : l.last_status, l.short_url || "",
    l.pass_hash || "", l.pass_salt || "", l.last_check ? vn(l.last_check) : "", l.fail_count || 0];
}
const pub = (l) => { const o = Object.assign({}, l); delete o.pass_hash; delete o.pass_salt; return o; };
const allLinks = () => {
  const sh = sheet("links"), n = sh.getLastRow();
  return n < 2 ? [] : sh.getRange(2, 1, n - 1, 18).getValues().filter((r) => r[0] !== "").map(linkFromRow);
};
function saveLink(sh, row, l) {
  sh.getRangeList(LINK_TEXT_RANGES(row)).setNumberFormat("@");
  sh.getRange(row, 2, 1, 17).setValues([linkToRow(l).slice(1)]); // không ghi đè cột A (đang là link bấm được)
  cput("l:" + l.code, l, 3600);
}
const readLink = (sh, row) => linkFromRow(sh.getRange(row, 1, 1, 18).getValues()[0]);

function op_link_get(a) {
  const k = "l:" + a.code, hit = cget(k);
  if (hit) return { link: hit };
  const sh = sheet("links"), row = findRow(sh, 1, a.code);
  if (!row) return { link: null };
  const l = readLink(sh, row);
  cput(k, l, 3600);
  return { link: l };
}

function op_link_create(a) {
  return withLock(() => {
    const sh = sheet("links");
    if (findRow(sh, 1, a.code)) return { conflict: true };
    const l = { code: a.code, url: a.url, clicks: 0, scans: 0, created_at: new Date().toISOString(), created_ip: a.created_ip || "",
      disabled: false, expires_at: a.expires_at || null, max_clicks: a.max_clicks || null, protected: !!a.pass_hash,
      no_check: !!a.no_check, dead: false, last_status: null, short_url: a.short_url || "",
      pass_hash: a.pass_hash || null, pass_salt: a.pass_salt || null, last_check: null, fail_count: 0 };
    const row = sh.getLastRow() + 1;
    sh.getRangeList(LINK_TEXT_RANGES(row)).setNumberFormat("@");
    sh.getRange(row, 1, 1, 18).setValues([linkToRow(l)]);
    if (l.short_url) {
      sh.getRange(row, 1).setRichTextValue(SpreadsheetApp.newRichTextValue().setText(l.code).setLinkUrl(l.short_url).build());
    }
    cput("l:" + l.code, l, 3600);
    return { link: l };
  });
}

function op_link_update(a) {
  return withLock(() => {
    const sh = sheet("links"), row = findRow(sh, 1, a.code);
    if (!row) return { notfound: true };
    const l = readLink(sh, row), p = a.patch || {}, has = (k) => Object.prototype.hasOwnProperty.call(p, k);
    if (has("disabled")) l.disabled = p.disabled === true;
    if (has("expires_at")) l.expires_at = p.expires_at || null;
    if (has("max_clicks")) l.max_clicks = p.max_clicks || null;
    if (has("no_check")) l.no_check = p.no_check === true;
    if (p.clear_password === true) { l.pass_hash = null; l.pass_salt = null; l.protected = false; }
    saveLink(sh, row, l);
    return { link: pub(l) };
  });
}

function op_link_delete(a) {
  return withLock(() => {
    const sh = sheet("links"), row = findRow(sh, 1, a.code);
    if (!row) return { notfound: true };
    const url = String(sh.getRange(row, 2).getValue());
    sh.deleteRow(row);
    cdel("l:" + a.code);
    deleteAlerts(a.code, null);
    return { url };
  });
}

function op_links_list(a) {
  const all = allLinks(), q = String(a.q || "").toLowerCase();
  const limit = Math.min(Math.max(Number(a.limit) || 50, 1), 20000);
  const rows = q ? all.filter((l) => l.code.toLowerCase().indexOf(q) >= 0 || l.url.toLowerCase().indexOf(q) >= 0) : all;
  rows.sort((x, y) => (Date.parse(y.created_at) || 0) - (Date.parse(x.created_at) || 0));
  return { total: all.length, clicks: all.reduce((s, l) => s + l.clicks, 0), scans: all.reduce((s, l) => s + l.scans, 0),
    links: rows.slice(0, limit).map(pub) };
}
const op_links_all = () => ({ links: allLinks().map(pub) });
function op_links_by_codes(a) {
  const want = {};
  (a.codes || []).forEach((c) => (want[c] = true));
  return { links: allLinks().filter((l) => want[l.code]).map(pub) };
}

// Cập nhật kết quả kiểm tra link đích: [{code, last_status, fail_count}]
function op_link_check_update(a) {
  return withLock(() => {
    const sh = sheet("links");
    (a.updates || []).forEach((u) => {
      const row = findRow(sh, 1, u.code);
      if (!row) return;
      sh.getRange(row, 12, 1, 2).setValues([[u.fail_count >= 2 ? "đích lỗi" : "", u.last_status === null || u.last_status === undefined ? "" : u.last_status]]);
      sh.getRange(row, 17, 1, 2).setNumberFormat("@").setValues([[vn(new Date()), u.fail_count || 0]]);
      cdel("l:" + u.code);
    });
    return { ok: true };
  });
}

// Cộng lượt + ghi nhật ký trong MỘT lần gọi (đường nóng của chuyển hướng). Kiểm tra lại hạn / giới hạn lượt dưới khoá.
function op_click(a) {
  return withLock(() => {
    const sh = sheet("links"), row = findRow(sh, 1, a.code);
    if (!row) return { ok: false, reason: "notfound" };
    const l = readLink(sh, row);
    if (l.disabled) return { ok: false, reason: "disabled" };
    if (l.expires_at && Date.parse(l.expires_at) <= Date.now()) return { ok: false, reason: "expired" };
    if (l.max_clicks && l.clicks >= l.max_clicks) return { ok: false, reason: "used_up" };
    l.clicks += 1;
    if (a.qr) l.scans += 1;
    sh.getRange(row, 3, 1, 2).setValues([[l.clicks, l.scans]]);
    if (a.log) appendLog(a.log);
    cput("l:" + l.code, l, 3600);
    return { ok: true, url: l.url, clicks: l.clicks, max_clicks: l.max_clicks };
  });
}

/* ───────── Nhật ký ───────── */

function lastLogId(sh) {
  const n = sh.getLastRow();
  if (n < 2) return 0;
  const v = Number(sh.getRange(n, 1).getValue());
  if (v > 0) return v;
  let max = 0; // ô cuối không phải số (Sheet bị sắp xếp lại): quét cả cột
  sh.getRange(2, 1, n - 1, 1).getValues().forEach((r) => { const x = Number(r[0]); if (x > max) max = x; });
  return max;
}
function appendLog(l) {
  const sh = sheet("logs"), id = lastLogId(sh) + 1, row = sh.getLastRow() + 1;
  const vals = [id, vn(l.ts ? new Date(l.ts) : new Date()), l.action, l.code, l.ip, l.user_agent, l.referrer, l.status, l.detail,
    l.country, l.city, l.device, l.browser, l.os, l.is_bot ? "true" : "false", l.meta ? JSON.stringify(l.meta) : ""].map(clean);
  sh.getRange(row, 1, 1, 16).setNumberFormat("@").setValues([vals]); // ô văn bản thuần: không tự chạy công thức
  return id;
}
function logFromRow(r) {
  let meta = null;
  try { meta = r[15] ? JSON.parse(r[15]) : null; } catch (e) {}
  return { id: Number(r[0]), ts: iso(r[1]), action: String(r[2]), code: r[3] ? String(r[3]) : null, ip: r[4] ? String(r[4]) : null,
    user_agent: String(r[5]), referrer: String(r[6]), status: r[7] === "" ? null : Number(r[7]), detail: String(r[8]),
    country: r[9] ? String(r[9]) : null, city: r[10] ? String(r[10]) : null, device: String(r[11]), browser: String(r[12]),
    os: String(r[13]), is_bot: String(r[14]) === "true", meta: meta };
}
// Đọc log từ mới đến cũ theo từng khối; fn trả false để dừng
function scanLogs(maxRows, fn) {
  const sh = sheet("logs"), t0 = Date.now();
  let end = sh.getLastRow(), scanned = 0;
  while (end >= 2 && scanned < maxRows && Date.now() - t0 < 25000) {
    const start = Math.max(2, end - 1999), vals = sh.getRange(start, 1, end - start + 1, 16).getValues();
    for (let i = vals.length - 1; i >= 0; i--) if (fn(vals[i]) === false) return;
    scanned += vals.length;
    end = start - 1;
  }
}

function op_log_add(a) { return withLock(() => ({ id: appendLog(a.log) })); }

function op_logs_list(a) {
  const limit = Math.min(Math.max(Number(a.limit) || 100, 1), 5000), out = [];
  const acts = a.actions || (a.action ? [a.action] : null), fromT = a.from ? Date.parse(a.from) : 0;
  scanLogs(50000, (r) => {
    if (fromT) { const t = parseTime(r[1]); if (t && t.getTime() < fromT) return false; }
    if (acts && acts.indexOf(String(r[2])) < 0) return;
    if (a.code && String(r[3]) !== a.code) return;
    if (a.ip && String(r[4]) !== a.ip) return;
    out.push(logFromRow(r));
    if (out.length >= limit) return false;
  });
  return { logs: out };
}

// Số liệu chi tiết của một link (chỉ admin gọi), tính từ nhật ký kể từ lúc link được tạo
function op_stats(a) {
  const key = "st:" + a.code, hit = cget(key);
  if (hit) return hit;
  const sh = sheet("links"), row = findRow(sh, 1, a.code);
  if (!row) return { notfound: true };
  const since = vn(readLink(sh, row).created_at);
  const day = {}, ref = {}, dim = { country: {}, device: {}, browser: {}, os: {} };
  let bots = 0;
  const add = (o, k) => { k = k || "(không rõ)"; o[k] = (o[k] || 0) + 1; };
  scanLogs(100000, (r) => {
    if (tstr(r[1]) < since) return false;
    if (String(r[3]) !== a.code) return;
    const act = String(r[2]);
    if (act === "bot_click") { bots++; return; }
    if (act !== "click" && act !== "scan") return;
    add(day, tstr(r[1]).slice(0, 10));
    const m = /^[A-Za-z]+:\/\/([^\/:?#]+)/.exec(String(r[6]));
    add(ref, m ? m[1].toLowerCase().replace(/^(www|m|l|lm|mobile)\./, "") || "(trực tiếp)" : "(trực tiếp)");
    add(dim.country, r[9] ? String(r[9]) : ""); add(dim.device, r[11] ? String(r[11]) : "");
    add(dim.browser, r[12] ? String(r[12]) : ""); add(dim.os, r[13] ? String(r[13]) : "");
  });
  const top = (o, n, kName, vName) => Object.keys(o).map((k) => ({ [kName]: k, clicks: o[k] })).sort((x, y) => y.clicks - x.clicks).slice(0, n);
  const out = {
    by_day: Object.keys(day).sort().reverse().slice(0, 30).map((d) => ({ day: d, clicks: day[d] })),
    top_referrers: top(ref, 10, "referrer"), by_country: top(dim.country, 8, "name"), by_device: top(dim.device, 8, "name"),
    by_browser: top(dim.browser, 8, "name"), by_os: top(dim.os, 8, "name"), bot_clicks: bots,
  };
  cput(key, out, 120);
  return out;
}

// Số lượt 7 ngày gần nhất (giờ VN) cho từng link, nhớ 5 phút
function op_spark(a) {
  const codes = (a.codes || []).slice(0, 40), days = [];
  for (let i = 6; i >= 0; i--) days.push(Utilities.formatDate(new Date(Date.now() - i * 864e5), TZ, "yyyy-MM-dd"));
  const out = {}, todo = {};
  codes.forEach((c) => { const h = cget("sp:" + c); if (h && h.d === days[6]) out[c] = h.v; else { out[c] = days.map(() => 0); todo[c] = true; } });
  if (Object.keys(todo).length) {
    const oldest = days[0];
    scanLogs(30000, (r) => {
      if (tstr(r[1]).slice(0, 10) < oldest) return false;
      const act = String(r[2]), c = String(r[3]);
      if ((act === "click" || act === "scan") && todo[c]) { const i = days.indexOf(tstr(r[1]).slice(0, 10)); if (i >= 0) out[c][i]++; }
    });
    Object.keys(todo).forEach((c) => cput("sp:" + c, { d: days[6], v: out[c] }, 300));
  }
  return { days, spark: out };
}

// Link bị báo cáo trong N ngày gần nhất
function op_reports(a) {
  const cutoff = vn(new Date(Date.now() - (Number(a.days) || 7) * 864e5)), by = {};
  scanLogs(50000, (r) => {
    if (tstr(r[1]) < cutoff) return false;
    if (String(r[2]) !== "report") return;
    const c = String(r[3]), o = by[c] || (by[c] = { code: c, n: 0, last: iso(r[1]), reasons: [] });
    o.n++;
    if (r[8] && o.reasons.indexOf(String(r[8])) < 0) o.reasons.push(String(r[8]));
  });
  const sh = sheet("links");
  const reports = Object.keys(by).map((c) => by[c]).sort((x, y) => y.n - x.n || String(y.last).localeCompare(String(x.last))).slice(0, 50).map((o) => {
    const row = findRow(sh, 1, o.code), l = row ? readLink(sh, row) : null;
    return { code: o.code, n: o.n, last: o.last, reasons: o.reasons, url: l ? l.url : null, disabled: l ? l.disabled : null };
  });
  return { reports };
}

// Dọn dẹp: log cũ (days > 0), cảnh báo đột biến cũ, phiên quản trị quá hạn
function op_purge(a) {
  return withLock(() => {
    let deleted = 0;
    const days = Number(a.days) || 0, lsh = sheet("logs"), n = lsh.getLastRow();
    if (days > 0 && n >= 2) {
      const cutoff = vn(new Date(Date.now() - days * 864e5)), ts = lsh.getRange(2, 2, n - 1, 1).getValues();
      let k = 0;
      while (k < ts.length && tstr(ts[k][0]) < cutoff) k++;
      if (k > 0) { lsh.deleteRows(2, k); deleted = k; }
    }
    pruneRows(sheet("alerts"), 3, (r) => String(r[1]) === "spike" && parseTime(r[2]) && Date.now() - parseTime(r[2]) > 864e5);
    pruneRows(sheet("sessions"), 4, (r) => parseTime(r[1]) && Date.now() - parseTime(r[1]) > 30 * 864e5);
    return { deleted };
  });
}
function pruneRows(sh, width, test) {
  const n = sh.getLastRow();
  if (n < 2) return;
  const vals = sh.getRange(2, 1, n - 1, width).getValues();
  for (let i = vals.length - 1; i >= 0; i--) if (test(vals[i])) sh.deleteRow(i + 2);
}

/* ───────── Cài đặt (ghi đè giá trị mặc định) ───────── */

function op_settings_get() {
  const hit = cget("cfg");
  if (hit) return { settings: hit };
  const sh = sheet("config"), n = sh.getLastRow(), s = {};
  if (n >= 2) sh.getRange(2, 1, n - 1, 2).getValues().forEach((r) => { if (r[0] !== "") s[String(r[0])] = String(r[1]); });
  cput("cfg", s, 300);
  return { settings: s };
}
function op_settings_set(a) {
  return withLock(() => {
    const sh = sheet("config");
    Object.keys(a.patch || {}).forEach((k) => {
      const v = a.patch[k], row = findRow(sh, 1, k);
      if (v === null) { if (row) sh.deleteRow(row); return; }
      const r = row || sh.getLastRow() + 1;
      sh.getRange(r, 1, 1, 3).setNumberFormat("@").setValues([[k, String(v), vn(new Date())]]);
    });
    cdel("cfg");
    return { ok: true };
  });
}

/* ───────── Mã khôi phục lịch sử ───────── */

function op_recovery_create(a) {
  return withLock(() => {
    const sh = sheet("recoveries"), now = vn(new Date()), row = sh.getLastRow() + 1;
    sh.getRange(row, 1, 1, 4).setNumberFormat("@").setValues([[a.id, JSON.stringify(a.codes || []), now, now]]);
    return { ok: true };
  });
}
function op_recovery_get(a) {
  const sh = sheet("recoveries"), row = findRow(sh, 1, a.id);
  if (!row) return { found: false };
  let codes = [];
  try { codes = JSON.parse(String(sh.getRange(row, 2).getValue())) || []; } catch (e) {}
  return { found: true, codes };
}
function op_recovery_set(a) {
  return withLock(() => {
    const sh = sheet("recoveries"), row = findRow(sh, 1, a.id);
    if (!row) return { found: false };
    sh.getRange(row, 2).setNumberFormat("@").setValue(JSON.stringify(a.codes || []));
    sh.getRange(row, 4).setNumberFormat("@").setValue(vn(new Date()));
    return { found: true };
  });
}

/* ───────── Cảnh báo Telegram (chống gửi trùng) ───────── */

function deleteAlerts(code, kinds) {
  const sh = sheet("alerts"), n = sh.getLastRow();
  if (n < 2) return;
  const vals = sh.getRange(2, 1, n - 1, 2).getValues();
  for (let i = vals.length - 1; i >= 0; i--) {
    if (String(vals[i][0]) === code && (!kinds || kinds.indexOf(String(vals[i][1])) >= 0)) sh.deleteRow(i + 2);
  }
}
function op_alert_delete(a) { return withLock(() => { deleteAlerts(a.code, a.kinds || null); return { ok: true }; }); }
// Giành quyền gửi: true nếu trong `cooldownHours` qua chưa gửi (kind, code) này
function op_alert_claim(a) {
  return withLock(() => {
    const sh = sheet("alerts"), n = sh.getLastRow(), cd = (Number(a.cooldownHours) || 87600) * 3600e3;
    const vals = n >= 2 ? sh.getRange(2, 1, n - 1, 3).getValues() : [];
    for (let i = 0; i < vals.length; i++) {
      if (String(vals[i][0]) === a.code && String(vals[i][1]) === a.kind) {
        const t = parseTime(vals[i][2]);
        if (t && Date.now() - t.getTime() < cd) return { claimed: false };
        sh.getRange(i + 2, 3).setNumberFormat("@").setValue(vn(new Date()));
        return { claimed: true };
      }
    }
    sh.getRange(sh.getLastRow() + 1, 1, 1, 3).setNumberFormat("@").setValues([[a.code, a.kind, vn(new Date())]]);
    return { claimed: true };
  });
}

/* ───────── Phiên đăng nhập quản trị ───────── */

function op_session_check(a) {
  const k = "s:" + a.id, hit = cget(k);
  let created = hit && hit.t;
  if (!created) {
    const sh = sheet("sessions"), row = findRow(sh, 1, a.id);
    if (!row) return { none: true };
    const t = parseTime(sh.getRange(row, 2).getValue());
    created = t ? t.getTime() : 0;
    cput(k, { t: created }, 600);
  }
  if (Date.now() - created < (Number(a.days) || 30) * 864e5) return { ok: true };
  op_session_delete({ id: a.id });
  return { expired: true };
}
// Đăng nhập mới: tối đa `max` phiên; đã đủ thì xoá TẤT CẢ và báo full
function op_session_login(a) {
  return withLock(() => {
    const sh = sheet("sessions");
    pruneRows(sh, 4, (r) => parseTime(r[1]) && Date.now() - parseTime(r[1]) > (Number(a.days) || 30) * 864e5);
    if (sh.getLastRow() - 1 >= (Number(a.max) || 2)) { clearSessions(sh); return { full: true }; }
    sh.getRange(sh.getLastRow() + 1, 1, 1, 4).setNumberFormat("@").setValues([[a.id, vn(new Date()), clean(a.ip), clean(a.ua)]]);
    cput("s:" + a.id, { t: Date.now() }, 600);
    return { ok: true };
  });
}
function op_session_delete(a) {
  return withLock(() => {
    const sh = sheet("sessions"), row = findRow(sh, 1, a.id);
    if (row) sh.deleteRow(row);
    cdel("s:" + a.id);
    return { ok: true };
  });
}
function clearSessions(sh) {
  const n = sh.getLastRow();
  if (n < 2) return;
  sh.getRange(2, 1, n - 1, 1).getValues().forEach((r) => cdel("s:" + r[0]));
  sh.deleteRows(2, n - 1);
}
function op_session_delete_all() { return withLock(() => { clearSessions(sheet("sessions")); return { ok: true }; }); }

/* ───────── Web app ───────── */

const OPS = {
  ping: () => ({ ok: true, time: new Date().toISOString() }),
  link_get: op_link_get, link_create: op_link_create, link_update: op_link_update, link_delete: op_link_delete,
  links_list: op_links_list, links_all: op_links_all, links_by_codes: op_links_by_codes, link_check_update: op_link_check_update,
  click: op_click, log_add: op_log_add, logs_list: op_logs_list, stats: op_stats, spark: op_spark, reports: op_reports, purge: op_purge,
  settings_get: op_settings_get, settings_set: op_settings_set,
  recovery_create: op_recovery_create, recovery_get: op_recovery_get, recovery_set: op_recovery_set,
  alert_claim: op_alert_claim, alert_delete: op_alert_delete,
  session_check: op_session_check, session_login: op_session_login, session_delete: op_session_delete, session_delete_all: op_session_delete_all,
};

function doPost(e) {
  Object.keys(_sheets).forEach((k) => delete _sheets[k]);
  let out;
  try {
    const b = JSON.parse(e.postData.contents), token = PropertiesService.getScriptProperties().getProperty("TOKEN");
    if (!token || b.token !== token) out = { error: "unauthorized" };
    else if (!Object.prototype.hasOwnProperty.call(OPS, b.op)) out = { error: "unknown op" };
    else out = OPS[b.op](b.args || {});
  } catch (err) {
    out = { error: String((err && err.message) || err) };
  }
  return ContentService.createTextOutput(JSON.stringify(out)).setMimeType(ContentService.MimeType.JSON);
}
function doGet() { return ContentService.createTextOutput("OK"); }

/* ───────── Cài đặt một lần, tab tổng hợp, menu ───────── */

// Chạy MỘT LẦN: cấp quyền, tạo đủ các tab, xoá lịch tự đồng bộ của script cũ, dựng tab tong_hop
function caiDat() {
  ScriptApp.getProjectTriggers().forEach((t) => {
    if (["syncLogs", "dongBo"].indexOf(t.getHandlerFunction()) >= 0) ScriptApp.deleteTrigger(t);
  });
  if (!PropertiesService.getScriptProperties().getProperty("TOKEN")) throw new Error("Chưa đặt TOKEN trong Script properties");
  Object.keys(TABS).forEach((n) => sheet(n));
  const sl = sheet("links"), sg = sheet("logs");
  [1, 2, 5, 6, 7, 8, 10, 11, 12, 14, 15, 16, 17].forEach((c) => sl.getRange(2, c, Math.max(sl.getMaxRows() - 1, 1), 1).setNumberFormat("@"));
  sg.getRange(2, 1, Math.max(sg.getMaxRows() - 1, 1), 16).setNumberFormat("@");
  buildSummary();
  Logger.log("Xong. Giờ Deploy → Web app (Anyone) và dán URL /exec vào SHEET_URL trên Vercel.");
}

function setF(range, formula) {
  const make = typeof formula === "function" ? formula : () => formula;
  range.setFormula(make(";", "\\")); // Sheet tiếng Việt cần ";" nên thử trước; lỗi cú pháp thì ghi lại kiểu US
  SpreadsheetApp.flush();
  if (/^#(ERROR|NAME|VALUE|REF)/.test(String(range.getDisplayValue()))) range.setFormula(make(",", ","));
}

function buildSummary() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName("tong_hop");
  if (sh) sh.clear(); else sh = ss.insertSheet("tong_hop", 0);
  sh.getRange("A1").setValue("Tổng hợp").setFontSize(16).setFontWeight("bold");
  const stats = [
    ["Tổng số link", "=COUNTA(links!A2:A)"],
    ["Tổng lượt truy cập", "=SUM(links!C2:C)"],
    ["Trong đó từ mã QR", "=SUM(links!D2:D)"],
    ["Tổng số dòng nhật ký", "=COUNTA(logs!A2:A)"],
    ["Link có mật khẩu", (a) => `=COUNTIF(links!J2:J${a}"có mật khẩu")`],
    ["Link có đặt hạn", "=COUNTA(links!H2:H)"],
    ["Link đích bị lỗi", (a) => `=COUNTIF(links!L2:L${a}"đích lỗi")`],
  ];
  stats.forEach((r, i) => {
    sh.getRange(3 + i, 1).setValue(r[0]);
    setF(sh.getRange(3 + i, 2), r[1]);
    sh.getRange(3 + i, 2).setFontWeight("bold").setHorizontalAlignment("left");
  });
  sh.getRange("A10").setValue("Cập nhật lần cuối");
  sh.getRange("B10").setFormula("=NOW()");
  sh.getRange("A11").setValue("Top 10 link nhiều lượt nhất").setFontWeight("bold");
  setF(sh.getRange("A12"),
    (a) => `=IFERROR(QUERY(links!A2:D${a}"select A,B,C,D where A is not null order by C desc limit 10 label A 'Mã', B 'Link gốc', C 'Lượt truy cập', D 'Từ QR'"${a}0)${a}"Chưa có dữ liệu")`);
  sh.getRange("F11").setValue("Số lượng theo loại thao tác").setFontWeight("bold");
  setF(sh.getRange("F12"),
    (a) => `=IFERROR(QUERY(logs!C2:C${a}"select C, count(C) where C is not null group by C order by count(C) desc label C 'Thao tác', count(C) 'Số lượng'"${a}0)${a}"Chưa có dữ liệu")`);
  sh.getRange("A26").setValue("Lượt truy cập 30 ngày gần nhất (bấm link + quét QR)").setFontWeight("bold");
  setF(sh.getRange("A27"),
    (a, c) => `=IFERROR(QUERY({ARRAYFORMULA(LEFT(logs!B2:B${a}10))${c}logs!C2:C}${a}"select Col1, count(Col2) where Col2 matches 'click|scan' group by Col1 order by Col1 desc limit 30 label Col1 'Ngày', count(Col2) 'Lượt'"${a}0)${a}"Chưa có dữ liệu")`);
  sh.setColumnWidth(1, 200);
  sh.setColumnWidth(2, 320);
}

function onOpen() {
  SpreadsheetApp.getUi().createMenu("Rút gọn link")
    .addItem("Dựng lại tab tổng hợp", "menuTongHop")
    .addItem("Kiểm tra backend", "menuKiemTra")
    .addToUi();
}
function menuTongHop() { buildSummary(); SpreadsheetApp.getActive().toast("Đã dựng lại tab tong_hop.", "Rút gọn link", 5); }
function menuKiemTra() {
  try {
    const ok = !!PropertiesService.getScriptProperties().getProperty("TOKEN");
    SpreadsheetApp.getUi().alert((ok ? "TOKEN đã đặt. " : "CHƯA đặt TOKEN. ") + "Links: " + allLinks().length + ", dòng log: " + Math.max(sheet("logs").getLastRow() - 1, 0));
  } catch (e) { SpreadsheetApp.getUi().alert("Lỗi:\n" + e.message); }
}
