import { sql, init } from "../lib/db.js";
import { requireAdmin } from "../lib/admin.js";

const csvCell = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;

// GET /api/logs?limit=100&action=click&code=abc&from=2026-11-01&format=csv
// Header: x-admin-key
export default async function handler(req, res) {
  if (!(await requireAdmin(req, res))) return;

  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 5000);
  const action = req.query.action || null;
  const code = req.query.code || null;
  const from = req.query.from || null;

  await init();
  const rows = await sql`SELECT id, ts, action, code, ip, user_agent, referrer, status, detail
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
