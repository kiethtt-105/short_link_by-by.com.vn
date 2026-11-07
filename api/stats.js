import { waitUntil } from "@vercel/functions";
import { sql, init } from "../lib/db.js";
import { logOp } from "../lib/log.js";

// Công khai, không trả IP. Muốn xem chi tiết từng thao tác thì dùng /api/logs (cần ADMIN_KEY).
export default async function handler(req, res) {
  const code = String(req.query.code || "");
  await init();
  const [link] = await sql`SELECT code, url, clicks, scans, created_at FROM links WHERE code = ${code}`;
  if (!link) return res.status(404).json({ error: "Không tìm thấy link" });

  const by_day = await sql`SELECT ts::date AS day, count(*)::int AS clicks FROM logs
    WHERE action IN ('click', 'scan') AND code = ${code} GROUP BY day ORDER BY day DESC LIMIT 30`;
  const top_referrers = await sql`SELECT COALESCE(NULLIF(referrer, ''), '(trực tiếp)') AS referrer,
    count(*)::int AS clicks FROM logs WHERE action IN ('click', 'scan') AND code = ${code}
    GROUP BY 1 ORDER BY clicks DESC LIMIT 10`;

  waitUntil(logOp(req, { action: "stats_view", code, status: 200 }));
  res.json({ ...link, by_day, top_referrers });
}
