-- =====================================================================
-- NetWatch FYP - Supabase / PostgreSQL schema
-- =====================================================================
-- HOW TO USE:
--   1. Open your Supabase project -> SQL Editor -> New query
--   2. Paste this ENTIRE file
--   3. Click "Run"
-- Safe to run more than once (uses CREATE TABLE IF NOT EXISTS).
--
-- Type notes (kept identical to the app's existing SQLite usage so NO Python
-- changes are needed beyond the connection layer):
--   * epoch times are stored as DOUBLE PRECISION (the app writes time.time())
--   * ISO datetime strings are stored as TEXT
--   * boolean-ish flags are INTEGER 0/1 (the app inserts/compares 0 and 1)
--   * auto-increment ids use SERIAL (Postgres) instead of AUTOINCREMENT
-- =====================================================================

-- ---------------------------------------------------------------------
-- MONITORING DATA (used by database.py)
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS traffic_history (
    id                  SERIAL PRIMARY KEY,
    timestamp           DOUBLE PRECISION,
    datetime            TEXT,
    total_mbps_recv     DOUBLE PRECISION,
    total_mbps_sent     DOUBLE PRECISION,
    total_mbps          DOUBLE PRECISION,
    cpu_pct             DOUBLE PRECISION,
    mem_pct             DOUBLE PRECISION,
    disk_pct            DOUBLE PRECISION,
    temperature         DOUBLE PRECISION,
    active_connections  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_datetime  ON traffic_history(datetime);

CREATE TABLE IF NOT EXISTS adapter_traffic (
    id            SERIAL PRIMARY KEY,
    timestamp     DOUBLE PRECISION,
    adapter_name  TEXT,
    mbps_recv     DOUBLE PRECISION,
    mbps_sent     DOUBLE PRECISION,
    bytes_recv    BIGINT,
    bytes_sent    BIGINT
);
CREATE INDEX IF NOT EXISTS idx_adapter_timestamp ON adapter_traffic(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     DOUBLE PRECISION,
    datetime      TEXT,
    alert_type    TEXT,
    severity      TEXT,
    title         TEXT,
    message       TEXT,
    value         DOUBLE PRECISION,
    threshold     DOUBLE PRECISION,
    acknowledged  INTEGER DEFAULT 0,
    resolved      INTEGER DEFAULT 0,
    resolved_at   DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp    ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS process_history (
    id            SERIAL PRIMARY KEY,
    timestamp     DOUBLE PRECISION,
    process_name  TEXT,
    mbps          DOUBLE PRECISION,
    pid           INTEGER
);
CREATE INDEX IF NOT EXISTS idx_process_timestamp ON process_history(timestamp);

CREATE TABLE IF NOT EXISTS daily_summary (
    date           TEXT PRIMARY KEY,
    total_gb_recv  DOUBLE PRECISION,
    total_gb_sent  DOUBLE PRECISION,
    avg_mbps       DOUBLE PRECISION,
    peak_mbps      DOUBLE PRECISION,
    peak_time      DOUBLE PRECISION,
    total_alerts   INTEGER
);

CREATE TABLE IF NOT EXISTS predictions (
    id              SERIAL PRIMARY KEY,
    timestamp       DOUBLE PRECISION,
    predicted_time  DOUBLE PRECISION,
    predicted_mbps  DOUBLE PRECISION,
    confidence      DOUBLE PRECISION,
    actual_mbps     DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON predictions(timestamp);

-- Discovered LAN devices (schema provided for completeness / future use)
CREATE TABLE IF NOT EXISTS devices (
    id           SERIAL PRIMARY KEY,
    mac          TEXT UNIQUE,
    ip           TEXT,
    hostname     TEXT,
    vendor       TEXT,
    device_type  TEXT,
    first_seen   DOUBLE PRECISION,
    last_seen    DOUBLE PRECISION,
    is_online    INTEGER DEFAULT 1,
    is_blocked   INTEGER DEFAULT 0,
    notes        TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ip  ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

-- ---------------------------------------------------------------------
-- AUTH / USERS (used by advanced_auth.py)
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id                   SERIAL PRIMARY KEY,
    user_id              TEXT UNIQUE NOT NULL,
    username             TEXT UNIQUE NOT NULL,
    email                TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    full_name            TEXT,
    role                 TEXT DEFAULT 'viewer',
    is_active            INTEGER DEFAULT 1,
    is_verified          INTEGER DEFAULT 1,
    two_factor_enabled   INTEGER DEFAULT 0,
    two_factor_secret    TEXT,
    created_at           DOUBLE PRECISION,
    updated_at           DOUBLE PRECISION,
    last_login           DOUBLE PRECISION,
    last_ip              TEXT,
    login_count          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id             SERIAL PRIMARY KEY,
    session_id     TEXT UNIQUE NOT NULL,
    user_id        TEXT NOT NULL,
    refresh_token  TEXT NOT NULL,
    device_info    TEXT,
    ip_address     TEXT,
    created_at     DOUBLE PRECISION,
    expires_at     DOUBLE PRECISION,
    is_revoked     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS otp_codes (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    code        TEXT NOT NULL,
    purpose     TEXT DEFAULT 'login',
    expires_at  DOUBLE PRECISION,
    used        INTEGER DEFAULT 0,
    created_at  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_codes(email);

CREATE TABLE IF NOT EXISTS login_attempts (
    id            SERIAL PRIMARY KEY,
    ip_address    TEXT,
    username      TEXT,
    success       INTEGER,
    attempted_at  DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id          SERIAL PRIMARY KEY,
    user_id     TEXT,
    action      TEXT,
    details     TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    timestamp   DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id);

CREATE TABLE IF NOT EXISTS password_resets (
    id          SERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    token       TEXT NOT NULL,
    expires_at  DOUBLE PRECISION,
    used        INTEGER DEFAULT 0
);

-- =====================================================================
-- Done. Your default admin user is created automatically by the app on
-- first startup (advanced_auth.py), so you do NOT need to insert it here.
-- =====================================================================
