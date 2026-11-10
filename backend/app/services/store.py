"""Persistent settings and anonymous usage counters.

Uses PostgreSQL when DATABASE_URL is configured (recommended on Vercel).
Falls back to SQLite for local development and tests. Raw prompts, responses,
and detected values are never written.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class Store:
    def __init__(self, path: Path, database_url: str | None = None):
        self._lock = threading.Lock()
        self._postgres = bool(database_url or os.getenv("DATABASE_URL"))

        if self._postgres:
            url = database_url or os.environ["DATABASE_URL"]
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "DATABASE_URL is set, but psycopg is not installed. "
                    "Install the backend requirements."
                ) from exc
            self._url = url
            self._db = self._pg_connect()
        else:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(path), check_same_thread=False)

        self._init()

    def _pg_connect(self):
        import psycopg
        # prepare_threshold=None: no server-side prepared statements, required
        # by Supabase transaction-mode poolers (port 6543) used by serverless.
        # autocommit: a failed statement must never leave the shared connection
        # stuck in an aborted transaction.
        try:
            return psycopg.connect(self._url, prepare_threshold=None,
                                   autocommit=True, connect_timeout=10)
        except Exception as exc:
            raise RuntimeError(
                "Could not connect to PostgreSQL using DATABASE_URL "
                f"({type(exc).__name__}). Check the host, port, password "
                "(URL-encode special characters) and that you used the "
                "Supabase pooler connection string.") from None

    def _run(self, sql: str, params=()):
        """Execute one statement. On Postgres, reconnect once if the pooler
        dropped the idle connection (normal on serverless). Caller holds _lock."""
        if not self._postgres:
            return self._db.execute(sql, params)
        import psycopg
        try:
            return self._db.execute(sql, params)
        except (psycopg.OperationalError, psycopg.InterfaceError):
            try:
                self._db.close()
            except Exception:
                pass
            self._db = self._pg_connect()
            return self._db.execute(sql, params)

    def _init(self):
        with self._lock:
            if self._postgres:
                self._run("""
                    CREATE TABLE IF NOT EXISTS settings(
                        key TEXT PRIMARY KEY, value TEXT NOT NULL
                    )
                """)
                self._run("""
                    CREATE TABLE IF NOT EXISTS scans(
                        id BIGSERIAL PRIMARY KEY, ts TEXT NOT NULL,
                        source TEXT NOT NULL, mode TEXT NOT NULL,
                        action TEXT NOT NULL, n_findings INTEGER NOT NULL
                    )
                """)
                self._run("""
                    CREATE TABLE IF NOT EXISTS scan_entities(
                        scan_id BIGINT NOT NULL, entity TEXT NOT NULL,
                        action TEXT NOT NULL
                    )
                """)
            else:
                self._db.executescript("""
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scans(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
                    source TEXT NOT NULL, mode TEXT NOT NULL,
                    action TEXT NOT NULL, n_findings INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS scan_entities(
                    scan_id INTEGER NOT NULL, entity TEXT NOT NULL, action TEXT NOT NULL);
                """)
            if not self._postgres:
                self._db.commit()

    def get_setting(self, key: str):
        sql = "SELECT value FROM settings WHERE key=%s" if self._postgres else \
              "SELECT value FROM settings WHERE key=?"
        with self._lock:
            row = self._run(sql, (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_setting(self, key: str, value) -> None:
        placeholder = "%s" if self._postgres else "?"
        sql = (
            f"INSERT INTO settings(key,value) VALUES({placeholder},{placeholder}) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        with self._lock:
            self._run(sql, (key, json.dumps(value)))
            if not self._postgres:
                self._db.commit()

    def log_scan(self, source: str, mode: str, overall: str, items: list[dict]) -> None:
        """Usage counters are best-effort: a database hiccup must never turn a
        successful scan into an error for the user."""
        try:
            self._log_scan(source, mode, overall, items)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger("sid.store").warning("log_scan failed: %s", type(exc).__name__)

    def _log_scan(self, source: str, mode: str, overall: str, items: list[dict]) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            if self._postgres:
                row = self._run(
                    "INSERT INTO scans(ts,source,mode,action,n_findings) "
                    "VALUES(%s,%s,%s,%s,%s) RETURNING id",
                    (ts, source, mode, overall, len(items)),
                ).fetchone()
                sid = row[0]
                if items:
                    # psycopg3: executemany lives on the cursor, not the connection
                    with self._db.cursor() as cur:
                        cur.executemany(
                            "INSERT INTO scan_entities(scan_id,entity,action) VALUES(%s,%s,%s)",
                            [(sid, it["entity_type"], it["action"]) for it in items],
                        )
            else:
                cur = self._db.execute(
                    "INSERT INTO scans(ts,source,mode,action,n_findings) VALUES(?,?,?,?,?)",
                    (ts, source, mode, overall, len(items)),
                )
                sid = cur.lastrowid
                self._db.executemany(
                    "INSERT INTO scan_entities(scan_id,entity,action) VALUES(?,?,?)",
                    [(sid, it["entity_type"], it["action"]) for it in items],
                )
                self._db.commit()

    def stats(self) -> dict:
        with self._lock:
            q = self._run
            total = q("SELECT COUNT(*) FROM scans").fetchone()[0]
            by_action = dict(q("SELECT action, COUNT(*) FROM scans GROUP BY action").fetchall())
            by_source = dict(q("SELECT source, COUNT(*) FROM scans GROUP BY source").fetchall())
            by_entity = dict(q(
                "SELECT entity, COUNT(*) FROM scan_entities "
                "GROUP BY entity ORDER BY COUNT(*) DESC"
            ).fetchall())
            last = q("SELECT MAX(ts) FROM scans").fetchone()[0]
        return {
            "total_scans": total, "by_action": by_action, "by_source": by_source,
            "by_entity": by_entity, "last_scan": last,
        }

    def reset(self) -> None:
        with self._lock:
            if self._postgres:
                self._run("DELETE FROM scans")
                self._run("DELETE FROM scan_entities")
                self._run("DELETE FROM settings")
            else:
                self._db.executescript(
                    "DELETE FROM scans; DELETE FROM scan_entities; DELETE FROM settings;"
                )
                self._db.commit()
