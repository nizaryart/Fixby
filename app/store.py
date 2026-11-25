import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    product     TEXT NOT NULL,
    cvss_vector TEXT NOT NULL,
    score       REAL NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'reported',
    cve         TEXT,
    reported_on TEXT NOT NULL,
    due_on      TEXT NOT NULL
)
"""

LIST_QUERY = """
SELECT * FROM findings
WHERE (:status IS NULL OR status = :status)
  AND (:overdue_on IS NULL OR (status IN ('reported', 'triaged') AND due_on < :overdue_on))
ORDER BY due_on, id
"""


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(os.getenv("VULNTRACK_DB", "/data/vulntrack.db"))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(SCHEMA)
        with conn:
            yield conn
    finally:
        conn.close()


def ping() -> None:
    with _db() as conn:
        conn.execute("SELECT 1")


def create(finding: dict) -> dict:
    with _db() as conn:
        cursor = conn.execute(
            "INSERT INTO findings (title, product, cvss_vector, score, severity, cve, reported_on, due_on)"
            " VALUES (:title, :product, :cvss_vector, :score, :severity, :cve, :reported_on, :due_on)",
            finding,
        )
        new_id = cursor.lastrowid
    return get(new_id)


def get(finding_id: int) -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return dict(row) if row else None


def list_findings(status: str | None = None, overdue_on: date | None = None) -> list[dict]:
    params = {"status": status, "overdue_on": overdue_on.isoformat() if overdue_on else None}
    with _db() as conn:
        return [dict(row) for row in conn.execute(LIST_QUERY, params)]


def set_status(finding_id: int, status: str) -> dict:
    with _db() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
    return get(finding_id)
