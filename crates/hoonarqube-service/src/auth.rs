//! Bearer credentials and project permissions for the report service.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::watch;

use crate::{InitError, MAX_PROJECT_BYTES, validate_identity_component};

const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Reader,
    Reviewer,
    Admin,
}

impl Role {
    fn permits(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Role::Admin, _)
                | (Role::Reviewer, Role::Reader | Role::Reviewer)
                | (Role::Reader, Role::Reader)
        )
    }
}

#[derive(Clone)]
pub struct Credential {
    pub user_id: String,
    token: String,
    pub projects: BTreeMap<String, Role>,
    pub global_admin: bool,
}

impl Credential {
    #[must_use]
    pub fn new(
        user_id: impl Into<String>,
        token: impl Into<String>,
        projects: impl IntoIterator<Item = (String, Role)>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            token: token.into(),
            projects: projects.into_iter().collect(),
            global_admin: false,
        }
    }

    #[must_use]
    pub fn global_admin(mut self, global_admin: bool) -> Self {
        self.global_admin = global_admin;
        self
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    credentials: watch::Sender<Arc<[Credential]>>,
}

#[derive(Deserialize)]
struct CredentialConfig {
    user_id: String,
    token: String,
    #[serde(default)]
    projects: BTreeMap<String, Role>,
    #[serde(default)]
    global_admin: bool,
}

impl AuthConfig {
    /// Builds an authentication configuration after validating all credentials.
    ///
    /// # Errors
    ///
    /// Returns `InitError::Config` if credentials are empty, invalid, or duplicated.
    pub fn new(credentials: Vec<Credential>) -> Result<Self, InitError> {
        if credentials.is_empty() {
            return Err(InitError::Config(
                "at least one explicit service credential is required".to_string(),
            ));
        }
        let mut users = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        for credential in &credentials {
            validate_identity_component(&credential.user_id, MAX_PROJECT_BYTES, "user_id")
                .map_err(InitError::Config)?;
            if credential.token.is_empty() {
                return Err(InitError::Config(
                    "credential token must not be empty".to_string(),
                ));
            }
            if !tokens.insert(&credential.token) {
                return Err(InitError::Config(
                    "credential token must be unique".to_string(),
                ));
            }
            if !users.insert(credential.user_id.clone()) {
                return Err(InitError::Config(
                    "credential user_id must be unique".to_string(),
                ));
            }
            for project in credential.projects.keys() {
                validate_identity_component(project, MAX_PROJECT_BYTES, "project")
                    .map_err(InitError::Config)?;
            }
        }
        Ok(Self {
            credentials: watch::channel(Arc::from(credentials)).0,
        })
    }

    /// Parses authentication credentials from `JSON`.
    ///
    /// # Errors
    ///
    /// Returns `InitError::Config` if the text is invalid or parsed credentials fail validation.
    pub fn from_json(text: &str) -> Result<Self, InitError> {
        let entries: Vec<CredentialConfig> = serde_json::from_str(text).map_err(|error| {
            InitError::Config(format!(
                "invalid credentials JSON at line {}, column {}",
                error.line(),
                error.column()
            ))
        })?;
        Self::new(
            entries
                .into_iter()
                .map(|entry| Credential {
                    user_id: entry.user_id,
                    token: entry.token,
                    projects: entry.projects,
                    global_admin: entry.global_admin,
                })
                .collect(),
        )
    }

    /// Loads a validated credential set from a regular file of at most 1 MiB.
    ///
    /// # Errors
    /// Returns a configuration error when the file cannot be read or validated.
    pub fn from_file(path: &Path) -> Result<Self, InitError> {
        let unavailable = || InitError::Config("cannot read service credential file".into());
        if !path.is_file() {
            return Err(unavailable());
        }
        let file = File::open(path).map_err(|_| unavailable())?;
        if !file.metadata().map_err(|_| unavailable())?.is_file() {
            return Err(unavailable());
        }
        let mut data = Vec::new();
        file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| unavailable())?;
        if data.len() as u64 > MAX_CREDENTIAL_FILE_BYTES {
            return Err(InitError::Config(
                "service credential file exceeds 1 MiB".into(),
            ));
        }
        let text = std::str::from_utf8(&data)
            .map_err(|_| InitError::Config("service credential file is not UTF-8".into()))?;
        Self::from_json(text)
    }

    /// Replaces credentials for all clones. An invalid replacement denies all new requests.
    ///
    /// # Errors
    /// Returns the validation or read error after clearing the active credentials.
    pub async fn reload_file(&self, path: PathBuf) -> Result<(), InitError> {
        let loaded = tokio::task::spawn_blocking(move || Self::from_file(&path))
            .await
            .unwrap_or_else(|_| Err(InitError::Config("credential loading task failed".into())));
        let next = loaded.as_ref().map_or_else(
            |_| Arc::from([]),
            |auth| Arc::clone(&auth.credentials.borrow()),
        );
        self.credentials.send_replace(next);
        loaded.map(|_| ())
    }

    pub(super) fn authenticate(&self, token: &str) -> Option<Principal> {
        let snapshot = Arc::clone(&self.credentials.borrow());
        snapshot.iter().find_map(|credential| {
            if token
                .as_bytes()
                .ct_eq(credential.token.as_bytes())
                .unwrap_u8()
                != 1
            {
                return None;
            }
            Some(Principal {
                user_id: credential.user_id.clone(),
                projects: credential.projects.clone(),
                global_admin: credential.global_admin,
            })
        })
    }
}

#[derive(Clone)]
pub(super) struct Principal {
    pub(super) user_id: String,
    projects: BTreeMap<String, Role>,
    global_admin: bool,
}

impl Principal {
    pub(super) fn permits(&self, project: &str, required: Role) -> bool {
        self.global_admin
            || self
                .projects
                .get(project)
                .is_some_and(|role| role.permits(required))
    }
}
