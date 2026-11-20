CREATE TABLE projects (
    project TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    deleted_by TEXT,
    deletion_reason TEXT
);
CREATE TABLE analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL REFERENCES projects(project),
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    analyzed_epoch INTEGER NOT NULL,
    report_schema_version INTEGER NOT NULL,
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    metrics_json TEXT NOT NULL,
    duplication_json TEXT,
    gate_json TEXT,
    report_json TEXT NOT NULL,
    assessment_json TEXT,
    content_hash TEXT NOT NULL,
    deleted_at TEXT,
    deleted_by TEXT,
    deletion_reason TEXT,
    UNIQUE(project, branch, commit_sha)
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    identity TEXT NOT NULL,
    occurrence INTEGER NOT NULL CHECK (occurrence >= 0),
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    rule_key TEXT NOT NULL,
    message TEXT NOT NULL,
    range_json TEXT NOT NULL,
    ambiguous INTEGER NOT NULL CHECK (ambiguous IN (0, 1)),
    UNIQUE(analysis_id, identity, kind, occurrence)
);
CREATE TABLE reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL REFERENCES projects(project),
    branch TEXT NOT NULL,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    identity TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    UNIQUE(project, branch, identity, kind)
);
CREATE TABLE review_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id INTEGER NOT NULL REFERENCES reviews(id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(id),
    identity TEXT NOT NULL,
    kind TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    UNIQUE(review_id, version)
);
CREATE TABLE deletion_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    analysis_id INTEGER,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
