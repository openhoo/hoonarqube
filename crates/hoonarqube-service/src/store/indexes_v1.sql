CREATE INDEX IF NOT EXISTS analyses_project_branch_time
    ON analyses(project, branch, analyzed_epoch DESC, id DESC);
CREATE INDEX IF NOT EXISTS findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS reviews_project_branch
    ON reviews(project, branch, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS review_history_review
    ON review_history(review_id, version ASC);
