"""
NetWatch DB Core - Backend-agnostic connection layer
=====================================================
ONE place that decides whether the app talks to:
  * Supabase / PostgreSQL  (USE_SUPABASE=true)   -> cloud storage
  * local SQLite           (USE_SUPABASE=false)  -> offline demo fallback

Everything else in the app (database.py, advanced_auth.py) just calls
`get_db_connection()` and writes SQLite-style SQL using `?` placeholders.
For PostgreSQL we transparently:
  - translate `?`  ->  `%s`   (psycopg2 paramstyle)
  - return rows that support BOTH index access (row[0]) AND key access
    (row['col']) and dict(row), so existing code keeps working unchanged.

Credentials are loaded from a gitignored `.env` file via python-dotenv.
NOTHING is hardcoded here.
"""

import os
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Load .env  (search backend/.env first, then project-root/.env)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    _HERE = Path(__file__).resolve().parent
    load_dotenv(_HERE / ".env")            # backend/.env
    load_dotenv(_HERE.parent / ".env")     # <project root>/.env  (no override)
except ImportError:
    # python-dotenv missing -> env vars must already be set in the shell
    print("[DB] python-dotenv not installed; relying on shell environment")


def _as_bool(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# 2. Configuration (from environment)
# ---------------------------------------------------------------------------
USE_SUPABASE = _as_bool(os.getenv("USE_SUPABASE", "false"))
IS_POSTGRES = USE_SUPABASE                      # alias used by aggregation SQL
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
SQLITE_PATH = os.path.join(DATA_DIR, "netwatch.db")

# psycopg2 is only needed in Supabase mode. Import lazily so offline SQLite
# demos work even if psycopg2 isn't installed.
psycopg2 = None
_pg_extras = None
if USE_SUPABASE:
    try:
        import psycopg2 as _pg
        import psycopg2.extras as _pg_extras_mod
        psycopg2 = _pg
        _pg_extras = _pg_extras_mod
    except ImportError as e:
        raise RuntimeError(
            "USE_SUPABASE=true but psycopg2 is not installed.\n"
            "Run:  pip install psycopg2-binary"
        ) from e


# ---------------------------------------------------------------------------
# 3. PostgreSQL compatibility wrappers
# ---------------------------------------------------------------------------
def _translate(sql: str) -> str:
    """SQLite uses '?' placeholders; psycopg2 uses '%s'."""
    return sql.replace("?", "%s")


class _PgCursor:
    """Wraps a psycopg2 cursor so it accepts SQLite-style '?' placeholders."""

    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        return self._cur.execute(_translate(sql), params if params is not None else None)

    def executemany(self, sql, seq):
        return self._cur.executemany(_translate(sql), seq)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size=None):
        return self._cur.fetchmany(size) if size else self._cur.fetchmany()

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        # psycopg2 has no lastrowid; use 'INSERT ... RETURNING id' instead.
        return None

    def __getattr__(self, name):
        return getattr(self._cur, name)

    def __iter__(self):
        return iter(self._cur)


class _PgConnection:
    """Wraps a psycopg2 connection to hand back '?'-aware DictCursors."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        # DictRow supports row[0], row['col'] AND dict(row) -> drop-in for sqlite3.Row
        return _PgCursor(self._conn.cursor(cursor_factory=_pg_extras.DictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


# ---------------------------------------------------------------------------
# 4. Connection factory
# ---------------------------------------------------------------------------
def _connect_postgres():
    """
    Connect to Supabase. Two supported configurations:

    (A) Component vars (RECOMMENDED) -- password passed raw, so a '@' (or any
        special char) in the password NEVER has to be URL-encoded:
            SUPABASE_DB_HOST, SUPABASE_DB_PORT, SUPABASE_DB_USER,
            SUPABASE_DB_PASSWORD, SUPABASE_DB_NAME
    (B) A single DATABASE_URL string (password must be URL-encoded there).
    """
    try:
        if DATABASE_URL:
            return psycopg2.connect(DATABASE_URL, connect_timeout=10, sslmode="require")

        host = os.getenv("SUPABASE_DB_HOST")
        if not host:
            raise RuntimeError(
                "Supabase mode is on but no connection info found. Set either "
                "DATABASE_URL or the SUPABASE_DB_* component vars in .env"
            )
        return psycopg2.connect(
            host=host,
            port=os.getenv("SUPABASE_DB_PORT", "6543"),
            user=os.getenv("SUPABASE_DB_USER"),
            password=os.getenv("SUPABASE_DB_PASSWORD"),   # raw string, no encoding needed
            dbname=os.getenv("SUPABASE_DB_NAME", "postgres"),
            connect_timeout=10,
            sslmode="require",
        )
    except Exception as e:
        # Clear, actionable error instead of a raw psycopg2 traceback
        raise RuntimeError(
            "[DB] Could not connect to Supabase/PostgreSQL.\n"
            f"      Reason: {e}\n"
            "      Checklist:\n"
            "        - Is your internet up / Supabase project unpaused?\n"
            "        - Are the SUPABASE_DB_* values (or DATABASE_URL) in .env correct?\n"
            "        - Using the IPv4 pooler host on port 6543?\n"
            "      To run offline instead, set USE_SUPABASE=false in .env"
        ) from e


def get_db_connection():
    """
    Return a DB connection.
      * Supabase mode -> psycopg2 connection wrapped for '?' placeholders + dict rows
      * SQLite  mode -> sqlite3 connection with Row factory (index + key access)
    The returned object exposes .cursor(), .commit(), .rollback(), .close()
    in both backends, so callers are identical.
    """
    if USE_SUPABASE:
        return _PgConnection(_connect_postgres())

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def backend_name() -> str:
    return "Supabase/PostgreSQL" if USE_SUPABASE else "local SQLite"
