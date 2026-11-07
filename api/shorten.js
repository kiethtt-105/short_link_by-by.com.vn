import { randomInt, timingSafeEqual } from "node:crypto";
import { waitUntil } from "@vercel/functions";
import { sql, init } from "../lib/db.js";
import { logOp, clientInfo } from "../lib/log.js";
import { baseUrl } from "../lib/util.js";
import { getSettings } from "../lib/settings.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALIAS_RE = /^[A-Za-z0-9_-]{3,32}$/;
const RESERVED = new Set(["api", "index", "favicon", "robots", "admin"]);

const newCode = () => Array.from({ length: 7 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
const same = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export default async function handler(req, res) {
  const fail = (status, error, action = "create_failed") => {
    waitUntil(logOp(req, { action, status, detail: error }));
    return res.status(status).json({ error });
  };

  if (req.method !== "POST") return res.status(405).json({ error: "Chỉ hỗ trợ POST" });

  const key = process.env.API_KEY;
  if (key && !same(String(req.headers["x-api-key"] || ""), key)) {
    return fail(401, "API key không hợp lệ", "auth_failed");
  }

  const { url, alias } = req.body || {};
  let u;
  try {
    u = new URL(url);
    if (!["http:", "https:"].includes(u.protocol) || String(url).length > 2048) throw new Error();
  } catch {
    return fail(400, "URL phải là http:// hoặc https:// và tối đa 2048 ký tự");
  }
  const ownHost = (req.headers["x-forwarded-host"] || req.headers.host || "").toLowerCase();
  if (u.host.toLowerCase() === ownHost) return fail(400, "Không rút gọn link của chính hệ thống này");
  if (alias && (!ALIAS_RE.test(alias) || RESERVED.has(alias.toLowerCase()))) {
    return fail(400, "Alias gồm 3-32 ký tự chữ, số, _ hoặc -");
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

  waitUntil(logOp(req, { action: "create", code, status: 201, detail: url }));
  const base = baseUrl(req);
  res.status(201).json({
    code,
    short_url: `${base}/${code}`,
    qr_url: `${base}/api/qr?code=${code}`,
    url,
  });
}
