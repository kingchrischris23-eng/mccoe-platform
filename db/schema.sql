CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    tags TEXT DEFAULT '',
    description TEXT DEFAULT '',
    UNIQUE(ioc_type, value, source)
);

CREATE TABLE IF NOT EXISTS log_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    line_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp TEXT,
    source_ip TEXT,
    method TEXT,
    path TEXT,
    status_code INTEGER,
    user_agent TEXT,
    raw_line TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES log_sessions(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    message TEXT NOT NULL,
    matched_line TEXT,
    remediation TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES log_sessions(id)
);

CREATE TABLE IF NOT EXISTS vuln_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    open_ports TEXT DEFAULT '[]',
    header_issues TEXT DEFAULT '[]',
    cve_findings TEXT DEFAULT '[]',
    risk_score REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    port_range TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    hosts_up INTEGER DEFAULT 0,
    open_ports INTEGER DEFAULT 0,
    results TEXT DEFAULT '[]',
    json_path TEXT DEFAULT '',
    summary TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    summary TEXT DEFAULT '',
    ioc_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    vuln_count INTEGER DEFAULT 0
);