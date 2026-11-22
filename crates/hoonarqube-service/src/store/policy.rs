//! Project-owned gate revisions and immutable analysis bindings.
use super::{
    BackupAnalysis, BackupEnvelope, Store, StoreError, ensure_active_project, to_sqlite_u64,
};
use crate::{
    ApiError, MAX_PROJECT_BYTES, validate_identity_component, validate_timestamp, wire_json,
};
use hoonarqube_gates::{GateConfig, evaluate_gate};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub version: u64,
    #[serde(deserialize_with = "deserialize_config")]
    pub config: GateConfig,
    pub updated_by: String,
    pub updated_at: String,
}

pub(crate) fn deserialize_config<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<GateConfig, D::Error> {
    serde_json::from_value(wire_json::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

pub(crate) fn valid_config(config: &GateConfig) -> bool {
    config.conditions.len() <= 64 && config.validate().is_ok()
}

pub(super) fn parse_config(raw: &str) -> Result<GateConfig, StoreError> {
    let config =
        serde_json::from_value(wire_json::parse(raw).map_err(invalid)?).map_err(invalid)?;
    if !valid_config(&config) {
        return Err(StoreError::Invalid("corrupt gate config".into()));
    }
    Ok(config)
}

fn invalid(e: impl std::fmt::Display) -> StoreError {
    StoreError::Invalid(e.to_string())
}

fn read_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<Policy> {
    let raw: String = row.get(1)?;
    let config = parse_config(&raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Policy {
        version: super::from_sqlite_u64(row.get(0)?, 0)?,
        config,
        updated_by: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

pub(super) fn latest(db: &Connection, project: &str) -> Result<Option<Policy>, StoreError> {
    Ok(db
        .query_row(
            "SELECT version, config_json, updated_by, updated_at FROM project_gate_policies
         WHERE project = ?1 ORDER BY version DESC LIMIT 1",
            [project],
            read_policy,
        )
        .optional()?)
}

pub(super) fn history(db: &Connection, project: &str) -> Result<Vec<Policy>, StoreError> {
    let mut query = db.prepare(
        "SELECT version, config_json, updated_by, updated_at FROM project_gate_policies
         WHERE project = ?1 ORDER BY version",
    )?;
    Ok(query
        .query_map([project], read_policy)?
        .collect::<Result<Vec<_>, _>>()?)
}

fn add(db: &Connection, project: &str, policy: &Policy) -> Result<(), StoreError> {
    db.execute(
        "INSERT INTO project_gate_policies(project, version, config_json, updated_by, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            project,
            to_sqlite_u64(policy.version)?,
            serde_json::to_string(&policy.config).map_err(invalid)?,
            policy.updated_by,
            policy.updated_at
        ],
    )?;
    Ok(())
}

impl Store {
    pub(crate) fn project_policy(&self, project: &str) -> Result<Option<Policy>, StoreError> {
        let db = self.lock()?;
        ensure_active_project(&db, project)?;
        latest(&db, project)
    }

    pub(crate) fn assign_policy(
        &self,
        project: &str,
        expected: u64,
        config: GateConfig,
        actor: &str,
        now: &str,
    ) -> Result<Policy, StoreError> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO projects(project,created_at) VALUES (?,?)",
            params![project, now],
        )?;
        ensure_active_project(&tx, project)?;
        let last = latest(&tx, project)?.map_or(0, |p| p.version);
        if last != expected {
            return Err(StoreError::Conflict(
                "stale project gate policy version".into(),
            ));
        }
        let policy = Policy {
            version: last
                .checked_add(1)
                .ok_or_else(|| invalid("policy version exhausted"))?,
            config,
            updated_by: actor.into(),
            updated_at: now.into(),
        };
        add(&tx, project, &policy)?;
        tx.commit()?;
        Ok(policy)
    }
}

pub(super) fn bind(
    db: &Connection,
    id: i64,
    policy: &Policy,
    report: &str,
) -> Result<(), StoreError> {
    let report =
        serde_json::from_value(wire_json::parse(report).map_err(invalid)?).map_err(invalid)?;
    let gate = evaluate_gate(&policy.config, &report);
    let changed = db.execute(
        "UPDATE analyses SET gate_policy_version = ?1, assigned_gate_json = ?2
         WHERE id = ?3 AND gate_policy_version IS NULL",
        params![
            to_sqlite_u64(policy.version)?,
            serde_json::to_string(&gate).map_err(invalid)?,
            id
        ],
    )?;
    if changed != 1 {
        return Err(invalid("policy already bound"));
    }
    Ok(())
}

pub(crate) fn validate_backup(backup: &BackupEnvelope) -> Result<(), ApiError> {
    if (backup.schema_version == 1) != backup.gate_policies.is_empty() {
        return Err(ApiError::bad_request());
    }
    for (i, policy) in backup.gate_policies.iter().enumerate() {
        if usize::try_from(policy.version).ok() != Some(i + 1)
            || !valid_config(&policy.config)
            || validate_identity_component(&policy.updated_by, MAX_PROJECT_BYTES, "policy actor")
                .is_err()
            || validate_timestamp(&policy.updated_at).is_err()
        {
            return Err(ApiError::bad_request());
        }
    }
    if backup
        .analyses
        .iter()
        .filter_map(|a| a.gate_policy_version)
        .any(|v| {
            v == 0
                || usize::try_from(v)
                    .ok()
                    .is_none_or(|i| i > backup.gate_policies.len())
        })
    {
        return Err(ApiError::conflict());
    }
    Ok(())
}

pub(super) fn restore_history(
    db: &Connection,
    backup: &BackupEnvelope,
) -> Result<bool, StoreError> {
    let existing = history(db, &backup.project)?;
    if !existing.is_empty() && existing != backup.gate_policies {
        return Err(StoreError::Conflict(
            "restore conflicts with existing project policy history".into(),
        ));
    }
    if existing.is_empty() {
        for policy in &backup.gate_policies {
            add(db, &backup.project, policy)?;
        }
    }
    Ok(!existing.is_empty())
}

pub(super) fn restore_binding(
    db: &Connection,
    backup: &BackupEnvelope,
    analysis: &BackupAnalysis,
    id: i64,
    inserted: bool,
) -> Result<(), StoreError> {
    if !inserted {
        let bound: Option<u64> = db.query_row(
            "SELECT gate_policy_version FROM analyses WHERE id=?",
            [id],
            |r| super::optional_u64(r, 0),
        )?;
        if bound != analysis.gate_policy_version {
            return Err(StoreError::Conflict(
                "restore conflicts with immutable analysis gate policy".into(),
            ));
        }
    } else if let Some(v) = analysis.gate_policy_version {
        let i = usize::try_from(v)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .ok_or_else(|| invalid("missing policy version"))?;
        let p = backup
            .gate_policies
            .get(i)
            .ok_or_else(|| invalid("unknown policy version"))?;
        bind(
            db,
            id,
            p,
            &serde_json::to_string(&analysis.report).map_err(invalid)?,
        )?;
    }
    Ok(())
}
