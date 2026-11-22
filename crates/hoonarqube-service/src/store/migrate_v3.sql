CREATE TABLE project_gate_policies (
    project TEXT NOT NULL REFERENCES projects(project),
    version INTEGER NOT NULL CHECK(version > 0),
    config_json TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project, version)
);
ALTER TABLE analyses ADD COLUMN gate_policy_version INTEGER CHECK(gate_policy_version > 0);
ALTER TABLE analyses ADD COLUMN assigned_gate_json TEXT
    CHECK ((gate_policy_version IS NULL) = (assigned_gate_json IS NULL));
