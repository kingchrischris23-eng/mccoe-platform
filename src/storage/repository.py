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


def _ioc_filter_clauses(
    severity: str | None = None,
    severities: list[str] | None = None,
    ioc_type: str | None = None,
    ioc_types: list[str] | None = None,
    source: str | None = None,
    search: str | None = None,
    recency_tier: str | None = None,
) -> tuple[str, list]:
    from datetime import datetime, timedelta, timezone

    query = " WHERE 1=1"
    params: list = []

    if severities:
        placeholders = ",".join("?" * len(severities))
        query += f" AND severity IN ({placeholders})"
        params.extend(s.lower() for s in severities)
    elif severity:
        query += " AND severity = ?"
        params.append(severity.lower())

    if ioc_types:
        placeholders = ",".join("?" * len(ioc_types))
        query += f" AND ioc_type IN ({placeholders})"
        params.extend(t.lower() for t in ioc_types)
    elif ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type.lower())

    if source:
        query += " AND source LIKE ?"
        params.append(f"%{source}%")
    if search:
        query += " AND (value LIKE ? OR tags LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%"] * 3)

    if recency_tier:
        now = datetime.now(timezone.utc)
        fresh_cutoff = (now - timedelta(days=7)).isoformat()
        active_cutoff = (now - timedelta(days=30)).isoformat()
        if recency_tier == "fresh":
            query += " AND first_seen >= ?"
            params.append(fresh_cutoff)
        elif recency_tier == "active":
            query += " AND first_seen < ? AND first_seen >= ?"
            params.extend([fresh_cutoff, active_cutoff])
        elif recency_tier == "older":
            query += " AND first_seen < ?"
            params.append(active_cutoff)

    return query, params


def _sort_clause(sort: str) -> str:
    if sort == "oldest":
        return "first_seen ASC, value ASC"
    if sort == "risk":
        return (
            "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, "
            "first_seen DESC, value ASC"
        )
    return "first_seen DESC, value ASC"


def list_iocs(
    limit: int | None = None,
    *,
    sort: str = "newest",
    offset: int = 0,
    severity: str | None = None,
    severities: list[str] | None = None,
    ioc_type: str | None = None,
    ioc_types: list[str] | None = None,
    source: str | None = None,
    search: str | None = None,
    recency_tier: str | None = None,
    recent_days: int | None = None,
) -> list[dict]:
    return list_iocs_filtered(
        severity=severity,
        severities=severities,
        ioc_type=ioc_type,
        ioc_types=ioc_types,
        source=source,
        search=search,
        recency_tier=recency_tier,
        recent_days=recent_days,
        limit=limit,
        offset=offset,
        sort=sort,
    )


def list_iocs_filtered(
    severity: str | None = None,
    severities: list[str] | None = None,
    ioc_type: str | None = None,
    ioc_types: list[str] | None = None,
    source: str | None = None,
    search: str | None = None,
    recency_tier: str | None = None,
    recent_days: int | None = None,
    limit: int | None = None,
    offset: int = 0,
    sort: str = "newest",
) -> list[dict]:
    where, params = _ioc_filter_clauses(
        severity, severities, ioc_type, ioc_types, source, search, recency_tier
    )
    if recent_days is not None:
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(days=recent_days)).isoformat()
        where += " AND first_seen >= ?"
        params.append(cutoff)
    query = f"SELECT * FROM iocs{where} ORDER BY {_sort_clause(sort)}"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def count_iocs_filtered(
    severity: str | None = None,
    severities: list[str] | None = None,
    ioc_type: str | None = None,
    ioc_types: list[str] | None = None,
    source: str | None = None,
    search: str | None = None,
    recency_tier: str | None = None,
    recent_days: int | None = None,
) -> int:
    where, params = _ioc_filter_clauses(
        severity, severities, ioc_type, ioc_types, source, search, recency_tier
    )
    if recent_days is not None:
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(days=recent_days)).isoformat()
        where += " AND first_seen >= ?"
        params.append(cutoff)
    query = f"SELECT COUNT(*) FROM iocs{where}"

    with get_connection() as conn:
        row = conn.execute(query, params).fetchone()
    return int(row[0]) if row else 0


def list_ioc_distinct(field: str) -> list[str]:
    if field not in {"severity", "ioc_type", "source"}:
        raise ValueError(f"Unsupported distinct field: {field}")
    with get_connection() as conn:
        rows = conn.execute(f"SELECT DISTINCT {field} FROM iocs ORDER BY {field}").fetchall()
    return [str(row[0]) for row in rows if row[0]]


def list_ioc_values() -> set[str]:
    """All IOC values for correlation — not subject to display limit."""
    with get_connection() as conn:
        rows = conn.execute("SELECT value FROM iocs").fetchall()
    return {row[0].lower() for row in rows}


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


def save_network_scan(result: dict) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO network_scans
            (target, port_range, scan_type, scanned_at, hosts_up, open_ports, results, json_path, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["target"],
                result["port_range"],
                result["scan_type"],
                result["scanned_at"],
                result.get("hosts_up", 0),
                result.get("open_port_count", 0),
                json.dumps(result.get("results", [])),
                result.get("json_path", ""),
                result.get("summary", ""),
            ),
        )
        return int(cursor.lastrowid)


def list_network_scans(limit: int = 20) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM network_scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["results"] = json.loads(item["results"])
        results.append(item)
    return results


def clear_all_data() -> None:
    from src.storage.data_clear import execute_clear

    execute_clear(["all_user_data"])


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