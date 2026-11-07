import { timingSafeEqual } from "node:crypto";
import { waitUntil } from "@vercel/functions";
import { sql, init } from "./db.js";
import { logOp, clientInfo } from "./log.js";

const same = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Mật khẩu = biến ADMIN_KEY trên Vercel, gửi qua header x-admin-key.
// Sai quá 10 lần / 10 phút từ cùng IP thì tạm khoá IP đó.
export async function requireAdmin(req, res) {
  const admin = process.env.ADMIN_KEY;
  if (!admin) {
    res.status(503).json({ error: "Chưa đặt ADMIN_KEY trong biến môi trường Vercel" });
    return false;
  }
  await init();
  const { ip } = clientInfo(req);
  if (ip) {
    const [{ n }] = await sql`SELECT count(*)::int AS n FROM logs
      WHERE ip = ${ip} AND action = 'admin_auth_failed' AND ts > now() - interval '10 minutes'`;
    if (n >= 10) {
      res.status(429).json({ error: "Nhập sai quá nhiều lần, thử lại sau 10 phút" });
      return false;
    }
  }
  if (!same(String(req.headers["x-admin-key"] || ""), admin)) {
    waitUntil(logOp(req, { action: "admin_auth_failed", status: 401 }));
    res.status(401).json({ error: "Sai mật khẩu" });
    return false;
  }
  return true;
}
