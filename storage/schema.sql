-- CSIMS relational schema aligned with Thesis Figure 6 (ERD).
-- SQLite implementation of the five entities described in Section 2.5.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL
        CHECK (role IN ('Administrator', 'Security Analyst')),
    is_active BOOLEAN NOT NULL DEFAULT 1
        CHECK (is_active IN (0, 1)),
    must_change_password BOOLEAN NOT NULL DEFAULT 0
        CHECK (must_change_password IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_record_id INTEGER NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL
        CHECK (category IN (
            'Reconnaissance',
            'Dos / DDoS',
            'Exploitation',
            'Other suspicious activity'
        )),
    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status VARCHAR(20) NOT NULL DEFAULT 'New'
        CHECK (status IN ('New', 'In Progress', 'Resolved', 'Closed')),
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL
        CHECK (category IN (
            'Reconnaissance',
            'Dos / DDoS',
            'Exploitation',
            'Other suspicious activity'
        )),
    default_severity VARCHAR(20) NOT NULL
        CHECK (default_severity IN ('Low', 'Medium', 'High', 'Critical')),
    is_enabled BOOLEAN NOT NULL DEFAULT 1
        CHECK (is_enabled IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_comments (
    comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    comment_text TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS incident_rules (
    incident_id INTEGER NOT NULL,
    rule_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, rule_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(rule_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at
    ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity
    ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_comments_incident
    ON incident_comments(incident_id);
