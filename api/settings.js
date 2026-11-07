import { waitUntil } from "@vercel/functions";
import { requireAdmin } from "../lib/admin.js";
import { describeSettings, saveSettings } from "../lib/settings.js";
import { logOp } from "../lib/log.js";

// GET  /api/settings              → giá trị hiện tại + nguồn (db/env/default)
// PUT  /api/settings {key: value} → lưu; value = null để quay về mặc định
// Cần header x-admin-key (= ADMIN_KEY trên Vercel).
export default async function handler(req, res) {
  if (!(await requireAdmin(req, res))) return;

  if (req.method === "GET") return res.json({ settings: await describeSettings() });

  if (req.method === "PUT" || req.method === "POST") {
    const patch = req.body;
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
      return res.status(400).json({ error: "Body phải là object JSON" });
    }
    const r = await saveSettings(patch);
    if (r.errors.length) return res.status(400).json({ errors: r.errors });
    waitUntil(logOp(req, { action: "settings_update", status: 200, detail: JSON.stringify(r.changed) }));
    return res.json({ ok: true, settings: await describeSettings() });
  }
  res.status(405).json({ error: "Chỉ hỗ trợ GET hoặc PUT" });
}
