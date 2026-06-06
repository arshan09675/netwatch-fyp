"""
NetWatch Database Module - Storage Layer
========================================
Backend-agnostic: talks to Supabase/PostgreSQL or local SQLite depending on
the USE_SUPABASE flag in .env. All connection handling lives in db_core.py;
this module keeps the SAME public function names so the rest of the app
(main.py etc.) works unchanged.

SQLite vs PostgreSQL differences handled here:
  * placeholders ('?' -> '%s')        -> by db_core wrapper
  * AUTOINCREMENT vs SERIAL           -> SQLite tables made here; Postgres
                                         tables made via supabase_setup.sql
  * date/time aggregation functions   -> branched below on IS_POSTGRES
  * INSERT ... RETURNING              -> available via db_core if ever needed
                                         (none of the current inserts read an id)
"""
import time
from typing import List, Dict, Any
from datetime import datetime
from contextlib import contextmanager

from db_core import get_db_connection, USE_SUPABASE, IS_POSTGRES, backend_name


class Database:
    """Storage handler that works against Supabase/PostgreSQL or SQLite."""

    def __init__(self):
        # In Supabase mode, tables are created once via supabase_setup.sql in
        # the Supabase SQL Editor (no DDL on every startup over the pooler).
        # In SQLite mode we auto-create tables for a zero-setup offline demo.
        if USE_SUPABASE:
            print(f"[DB] Storage backend: {backend_name()} (run supabase_setup.sql once)")
        else:
            self._init_sqlite_tables()
            print(f"[DB] Storage backend: {backend_name()}")

    # ------------------------------------------------------------------
    # SQLite-only table bootstrap (offline demo). Postgres uses the .sql file.
    # ------------------------------------------------------------------
    def _init_sqlite_tables(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    datetime TEXT,
                    total_mbps_recv REAL,
                    total_mbps_sent REAL,
                    total_mbps REAL,
                    cpu_pct REAL,
                    mem_pct REAL,
                    disk_pct REAL,
                    temperature REAL,
                    active_connections INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS adapter_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    adapter_name TEXT,
                    mbps_recv REAL,
                    mbps_sent REAL,
                    bytes_recv INTEGER,
                    bytes_sent INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    datetime TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    title TEXT,
                    message TEXT,
                    value REAL,
                    threshold REAL,
                    acknowledged INTEGER DEFAULT 0,
                    resolved INTEGER DEFAULT 0,
                    resolved_at REAL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    process_name TEXT,
                    mbps REAL,
                    pid INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS daily_summary (
                    date TEXT PRIMARY KEY,
                    total_gb_recv REAL,
                    total_gb_sent REAL,
                    avg_mbps REAL,
                    peak_mbps REAL,
                    peak_time REAL,
                    total_alerts INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    predicted_time REAL,
                    predicted_mbps REAL,
                    confidence REAL,
                    actual_mbps REAL
                )
            ''')
            # Indexes created after tables (outside CREATE TABLE)
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_history(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_datetime ON traffic_history(datetime)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        print("[DB] SQLite tables initialized")

    # ------------------------------------------------------------------
    @contextmanager
    def get_connection(self):
        """Context manager yielding a backend-appropriate connection."""
        conn = get_db_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # WRITES
    # ------------------------------------------------------------------
    def save_traffic(self, data: Dict[str, Any]):
        """Save traffic snapshot with all metrics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO traffic_history
                (timestamp, datetime, total_mbps_recv, total_mbps_sent, total_mbps,
                 cpu_pct, mem_pct, disk_pct, temperature, active_connections)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['timestamp'],
                data.get('datetime', datetime.now().isoformat()),
                data['total_mbps_recv'],
                data['total_mbps_sent'],
                data['total_mbps'],
                data['system']['cpu_pct'],
                data['system']['mem_pct'],
                data['system'].get('disk_pct', 0),
                data['system'].get('temperature', 0),
                data.get('active_connections', 0)
            ))

    def save_adapter_traffic(self, timestamp: float, adapter: Dict):
        """Save per-adapter traffic data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO adapter_traffic
                (timestamp, adapter_name, mbps_recv, mbps_sent, bytes_recv, bytes_sent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, adapter['name'],
                adapter['mbps_recv'], adapter['mbps_sent'],
                adapter.get('bytes_recv', 0), adapter.get('bytes_sent', 0)
            ))

    def save_process_history(self, timestamp: float, process_name: str,
                             mbps: float, pid: int = 0):
        """Save a single top-process bandwidth sample."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO process_history (timestamp, process_name, mbps, pid)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, process_name, mbps, pid))

    def save_alert(self, alert_type: str, severity: str, title: str,
                   message: str, value: float, threshold: float = None):
        """Save alert with severity level"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts
                (timestamp, datetime, alert_type, severity, title, message, value, threshold)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                datetime.now().isoformat(),
                alert_type,
                severity,
                title,
                message,
                value,
                threshold
            ))

    def save_prediction(self, predicted_time: float, predicted_mbps: float,
                        confidence: float, actual_mbps: float = None):
        """Save ML prediction for future comparison"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO predictions
                (timestamp, predicted_time, predicted_mbps, confidence, actual_mbps)
                VALUES (?, ?, ?, ?, ?)
            ''', (time.time(), predicted_time, predicted_mbps, confidence, actual_mbps))

    def update_daily_usage(self, date: str, recv_gb: float, sent_gb: float):
        """Upsert daily usage. ON CONFLICT works on both SQLite and Postgres."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO daily_summary (date, total_gb_recv, total_gb_sent)
                VALUES (?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                total_gb_recv = daily_summary.total_gb_recv + excluded.total_gb_recv,
                total_gb_sent = daily_summary.total_gb_sent + excluded.total_gb_sent
            ''', (date, recv_gb, sent_gb))

    # ------------------------------------------------------------------
    # UPDATES
    # ------------------------------------------------------------------
    def acknowledge_alert(self, alert_id: int):
        """Mark alert as acknowledged"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))

    def resolve_alert(self, alert_id: int):
        """Mark alert as resolved"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET resolved = 1, resolved_at = ? WHERE id = ?',
                           (time.time(), alert_id))

    # ------------------------------------------------------------------
    # READS
    # ------------------------------------------------------------------
    def get_alerts(self, limit: int = 100, severity: str = None,
                   acknowledged: bool = None) -> List[Dict]:
        """Get alerts with filters"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if acknowledged is not None:
                query += " AND acknowledged = ?"
                params.append(1 if acknowledged else 0)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_traffic_history(self, hours: int = 24, interval: str = 'minute') -> List[Dict]:
        """Get traffic history with time-bucket aggregation."""
        cutoff = time.time() - (hours * 3600)

        if IS_POSTGRES:
            # epoch (DOUBLE PRECISION) -> timestamp, then date_trunc to the bucket
            unit = {'minute': 'minute', 'hour': 'hour'}.get(interval, 'day')
            group_by = f"date_trunc('{unit}', to_timestamp(timestamp))"
        else:
            # SQLite: the `datetime` column holds ISO-8601 strings; strftime parses them.
            if interval == 'minute':
                group_by = "strftime('%Y-%m-%d %H:%M:00', datetime)"
            elif interval == 'hour':
                group_by = "strftime('%Y-%m-%d %H:00:00', datetime)"
            else:
                group_by = "strftime('%Y-%m-%d', datetime)"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT
                    MIN(timestamp) as timestamp,
                    AVG(total_mbps) as avg_mbps,
                    MAX(total_mbps) as peak_mbps,
                    AVG(cpu_pct) as avg_cpu,
                    AVG(mem_pct) as avg_mem
                FROM traffic_history
                WHERE timestamp > ?
                GROUP BY {group_by}
                ORDER BY timestamp
            ''', (cutoff,))
            return [dict(row) for row in cursor.fetchall()]

    def get_daily_summary(self, days: int = 7) -> List[Dict]:
        """Get daily aggregated summary."""
        if IS_POSTGRES:
            day_expr = "to_char(to_timestamp(timestamp), 'YYYY-MM-DD')"
        else:
            day_expr = "date(timestamp, 'unixepoch')"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT
                    {day_expr} as date,
                    SUM(total_mbps_recv * 3600 / 1000) as total_gb_recv,
                    SUM(total_mbps_sent * 3600 / 1000) as total_gb_sent,
                    AVG(total_mbps) as avg_mbps,
                    MAX(total_mbps) as peak_mbps,
                    COUNT(CASE WHEN total_mbps > 50 THEN 1 END) as high_traffic_minutes
                FROM traffic_history
                WHERE timestamp > ?
                GROUP BY {day_expr}
                ORDER BY date DESC
                LIMIT ?
            ''', (time.time() - (days * 86400), days))
            return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # MAINTENANCE
    # ------------------------------------------------------------------
    def cleanup_old_data(self, days: int = 30):
        """Delete data older than specified days"""
        cutoff = time.time() - (days * 86400)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM traffic_history WHERE timestamp < ?', (cutoff,))
            cursor.execute('DELETE FROM alerts WHERE timestamp < ? AND resolved = 1', (cutoff,))
            cursor.execute('DELETE FROM process_history WHERE timestamp < ?', (cutoff,))
            print(f"[DB] Cleaned up data older than {days} days")


# Singleton instance
db = Database()
