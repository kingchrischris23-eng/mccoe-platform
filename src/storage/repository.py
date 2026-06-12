import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from config import DB_PATH
from src.feeds.models import IOC

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "db" / "schema.sql"


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_iocs(iocs: list[IOC]) -> None:
    with get_connection() as conn:
        for ioc in iocs:
            conn.execute(
                """
                INSERT OR REPLACE INTO iocs
                (ioc_type, value, severity, source, first_seen, tags, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc.ioc_type,
                    ioc.value,
                    ioc.severity,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ";".join(ioc.tags),
                    ioc.description,
                ),
            )


def list_iocs() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM iocs ORDER BY severity DESC, value ASC").fetchall()
    return [dict(row) for row in rows]


def create_log_session(filename: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO log_sessions (filename, uploaded_at) VALUES (?, ?)",
            (filename, datetime.now(timezone.utc).isoformat()),
        )
        return int(cursor.lastrowid)


def save_log_entries(session_id: int, entries: list[dict]) -> None:
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO log_entries
            (session_id, timestamp, source_ip, method, path, status_code, user_agent, raw_line)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    session_id,
                    entry.get("timestamp"),
                    entry.get("source_ip"),
                    entry.get("method"),
                    entry.get("path"),
                    entry.get("status_code"),
                    entry.get("user_agent"),
                    entry["raw_line"],
                )
                for entry in entries
            ],
        )
        conn.execute(
            "UPDATE log_sessions SET line_count = ? WHERE id = ?",
            (len(entries), session_id),
        )


def save_alerts(session_id: int, alerts: list[dict]) -> None:
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO alerts
            (session_id, rule_id, rule_name, severity, source_ip, message, matched_line, remediation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    session_id,
                    alert["rule_id"],
                    alert["rule_name"],
                    alert["severity"],
                    alert.get("source_ip"),
                    alert["message"],
                    alert.get("matched_line"),
                    alert.get("remediation", ""),
                    datetime.now(timezone.utc).isoformat(),
                )
                for alert in alerts
            ],
        )
        conn.execute(
            "UPDATE log_sessions SET alert_count = ? WHERE id = ?",
            (len(alerts), session_id),
        )


def list_log_sessions() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM log_sessions ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_latest_session_id() -> int | None:
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM log_sessions ORDER BY id DESC LIMIT 1").fetchone()
    return int(row["id"]) if row else None


def get_log_entries(session_id: int) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM log_entries WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_alerts(session_id: int | None = None) -> list[dict]:
    query = "SELECT * FROM alerts"
    params: tuple = ()
    if session_id is not None:
        query += " WHERE session_id = ?"
        params = (session_id,)
    query += " ORDER BY id DESC"
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def save_vuln_scan(result: dict) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO vuln_scans (target, scanned_at, open_ports, header_issues, cve_findings, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result["target"],
                datetime.now(timezone.utc).isoformat(),
                json.dumps(result.get("open_ports", [])),
                json.dumps(result.get("header_issues", [])),
                json.dumps(result.get("cve_findings", [])),
                result.get("risk_score", 0),
            ),
        )
        return int(cursor.lastrowid)


def list_vuln_scans() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM vuln_scans ORDER BY id DESC").fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["open_ports"] = json.loads(item["open_ports"])
        item["header_issues"] = json.loads(item["header_issues"])
        item["cve_findings"] = json.loads(item["cve_findings"])
        results.append(item)
    return results


def log_scan_audit(target: str, action: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scan_audit (target, action, timestamp) VALUES (?, ?, ?)",
            (target, action, datetime.now(timezone.utc).isoformat()),
        )


def save_report(metadata: dict) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO reports (filename, generated_at, summary, ioc_count, alert_count, vuln_count)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                metadata["filename"],
                metadata["generated_at"],
                metadata.get("summary", ""),
                metadata.get("ioc_count", 0),
                metadata.get("alert_count", 0),
                metadata.get("vuln_count", 0),
            ),
        )
        return int(cursor.lastrowid)


def list_reports() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_overview_stats() -> dict:
    with get_connection() as conn:
        ioc_count = conn.execute("SELECT COUNT(*) AS c FROM iocs").fetchone()["c"]
        high_iocs = conn.execute(
            "SELECT COUNT(*) AS c FROM iocs WHERE severity IN ('high', 'critical')"
        ).fetchone()["c"]
        alert_count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        vuln_count = conn.execute("SELECT COUNT(*) AS c FROM vuln_scans").fetchone()["c"]
        report_count = conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    return {
        "ioc_count": ioc_count,
        "high_iocs": high_iocs,
        "alert_count": alert_count,
        "vuln_count": vuln_count,
        "report_count": report_count,
    }