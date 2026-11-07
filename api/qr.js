import QRCode from "qrcode";
import { waitUntil } from "@vercel/functions";
import { sql, init } from "../lib/db.js";
import { logOp } from "../lib/log.js";
import { baseUrl } from "../lib/util.js";
import { getSettings } from "../lib/settings.js";

// GET /api/qr?code=abc            → QR theo cài đặt ở /admin
//     &format=png|svg             → ghi đè định dạng
//     &download=1                 → tải về thay vì hiển thị
// Chỉ tạo QR cho link đã có trong hệ thống.
export default async function handler(req, res) {
  const code = String(req.query.code || "");
  if (!/^[A-Za-z0-9_-]{3,32}$/.test(code)) return res.status(400).json({ error: "code không hợp lệ" });

  await init();
  const [link] = await sql`SELECT code FROM links WHERE code = ${code}`;
  if (!link) return res.status(404).json({ error: "Không tìm thấy link" });

  const cfg = await getSettings();
  const fmt = ["png", "svg"].includes(req.query.format) ? req.query.format : cfg.qr_format;
  // ?src=qr để phân biệt lượt quét với lượt bấm link thường
  const target = `${baseUrl(req)}/${code}?src=qr`;
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
    if (req.query.download) {
      res.setHeader("Content-Disposition", `attachment; filename="${code}.${fmt}"`);
    }
    // Chỉ cache ở trình duyệt, để mọi lượt tạo QR vẫn đi qua server và được ghi log
    res.setHeader("Cache-Control", "private, max-age=300");
    waitUntil(logOp(req, { action: "qr_view", code, status: 200, detail: fmt }));
    return res.status(200).send(body);
  } catch (e) {
    waitUntil(logOp(req, { action: "qr_failed", code, status: 500, detail: e.message }));
    return res.status(500).json({ error: "Không tạo được QR" });
  }
}
