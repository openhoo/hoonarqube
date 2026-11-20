CREATE INDEX IF NOT EXISTS findings_analysis_order
    ON findings(analysis_id, path, rule_key, identity, occurrence, id);
