CREATE INDEX IF NOT EXISTS analyses_active_project_time
    ON analyses(project, analyzed_epoch DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS analyses_active_branch_time
    ON analyses(project, branch, analyzed_epoch DESC, id DESC) WHERE deleted_at IS NULL;
