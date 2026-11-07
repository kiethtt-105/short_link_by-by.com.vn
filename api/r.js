import { waitUntil } from "@vercel/functions";
import { sql, init } from "../lib/db.js";
import { logOp } from "../lib/log.js";

export default async function handler(req, res) {
  const code = String(req.query.code || "");
  await init();
  const fromQr = req.query.src === "qr";
  // 1 câu lệnh vừa lấy URL vừa tăng bộ đếm (scans chỉ tăng khi đến từ mã QR)
  const rows = await sql`UPDATE links SET clicks = clicks + 1, scans = scans + ${fromQr ? 1 : 0}
                          WHERE code = ${code} RETURNING url`;

  if (!rows.length) {
    waitUntil(logOp(req, { action: "not_found", code, status: 404 }));
    return res.status(404).send("Link không tồn tại");
  }
  waitUntil(logOp(req, { action: fromQr ? "scan" : "click", code, status: 302, detail: rows[0].url }));
  res.setHeader("Cache-Control", "no-store"); // 302 không cache để mỗi lượt bấm đều được đếm
  res.redirect(302, rows[0].url);
}
