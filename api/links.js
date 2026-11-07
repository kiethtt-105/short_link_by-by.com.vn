import { waitUntil } from "@vercel/functions";
import { sql, init } from "../lib/db.js";
import { requireAdmin } from "../lib/admin.js";
import { logOp } from "../lib/log.js";

// Admin: GET /api/links?q=&limit=50 (danh sách + tổng), DELETE /api/links?code=abc (xoá link)
export default async function handler(req, res) {
  if (!(await requireAdmin(req, res))) return;
  await init();

  if (req.method === "DELETE") {
    const code = String(req.query.code || "");
    const r = await sql`DELETE FROM links WHERE code = ${code} RETURNING url`;
    if (!r.length) return res.status(404).json({ error: "Không tìm thấy link" });
    waitUntil(logOp(req, { action: "link_delete", code, status: 200, detail: r[0].url }));
    return res.json({ ok: true });
  }
  if (req.method !== "GET") return res.status(405).json({ error: "Chỉ hỗ trợ GET hoặc DELETE" });

  const q = String(req.query.q || "").slice(0, 100);
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const like = `%${q.replace(/[%_\\]/g, "\\$&")}%`;
  const links = await sql`SELECT code, url, clicks, scans, created_at FROM links
    WHERE (${q} = '' OR code ILIKE ${like} OR url ILIKE ${like})
    ORDER BY created_at DESC LIMIT ${limit}`;
  const [t] = await sql`SELECT count(*)::int AS total, COALESCE(sum(clicks), 0)::int AS clicks,
    COALESCE(sum(scans), 0)::int AS scans FROM links`;
  res.json({ ...t, links });
}
