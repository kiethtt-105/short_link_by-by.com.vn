import { neon } from "@neondatabase/serverless";

export const sql = neon(process.env.DATABASE_URL);

let ready;
export function init() {
  ready ??= (async () => {
    await sql`CREATE TABLE IF NOT EXISTS links (
      code TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      clicks BIGINT NOT NULL DEFAULT 0,
      scans BIGINT NOT NULL DEFAULT 0,
      created_ip TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
    await sql`ALTER TABLE links ADD COLUMN IF NOT EXISTS scans BIGINT NOT NULL DEFAULT 0`;
    await sql`CREATE TABLE IF NOT EXISTS logs (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      action TEXT NOT NULL,
      code TEXT,
      ip TEXT,
      user_agent TEXT,
      referrer TEXT,
      status INT,
      detail TEXT
    )`;
    await sql`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_code ON logs(code)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_logs_ip_action ON logs(ip, action, ts)`;
  })().catch((e) => {
    ready = undefined;
    throw e;
  });
  return ready;
}
