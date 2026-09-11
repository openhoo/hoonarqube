#![forbid(unsafe_code)]

mod store;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
#[cfg(test)]
use std::path::PathBuf;
use std::path::{Component, Path as FsPath};
use std::sync::Arc;

use crate::store::{
    AnalysisDetail, AnalysisSummary, BackupAnalysis, BackupFinding, BackupHistory, BackupReview,
    BranchSummary, FindingRecord, HistoryRecord, ProjectSummary, RestoreResult, RetentionInput,
    RetentionResult, ReviewRecord, Store, StoreError,
};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::http::{StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hoonarqube_catalog::{embedded, native_rule};
use hoonarqube_core::assessment::gates::{
    GATE_CONFIG_SCHEMA_VERSION, GateCondition, GateConfig, evaluate_gate,
};
use hoonarqube_ir::assessment::GateReport;
use hoonarqube_ir::{AnalysisReport, FileReport, Issue};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
const API_PREFIX: &str = "/api/v1";
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROJECT_BYTES: usize = 256;
const MAX_BRANCH_BYTES: usize = 256;
const MAX_COMMIT_BYTES: usize = 128;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 4 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_RULE_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_REPORT_FILES: usize = 100_000;
const MAX_REPORT_ISSUES: usize = 500_000;
const MAX_REPORT_PROJECT_FILES: usize = 100_000;
const MAX_ASSESSMENT_SOURCES: usize = 100_000;
const MAX_ASSESSMENT_FINDINGS: usize = 500_000;

struct SafePath<T>(T);

impl<S, T> FromRequestParts<S> for SafePath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| ApiError::bad_request())
    }
}

struct SafeQuery<T>(T);

impl<S, T> FromRequestParts<S> for SafeQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|_| ApiError::bad_request())
    }
}

struct SafeBytes(Bytes);

impl<S> FromRequest<S> for SafeBytes
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Bytes::from_request(request, state)
            .await
            .map(Self)
            .map_err(|rejection| api_body_error(rejection.status()))
    }
}

struct SafeJson<T>(T);

impl<S, T> FromRequest<S> for SafeJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| api_body_error(rejection.status()))
    }
}

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
    credentials: Arc<Vec<Credential>>,
}

#[derive(Debug, Deserialize)]
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
        for credential in &credentials {
            validate_identity_component(&credential.user_id, MAX_PROJECT_BYTES, "user_id")
                .map_err(InitError::Config)?;
            if credential.token.is_empty() {
                return Err(InitError::Config(
                    "credential token must not be empty".to_string(),
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
            credentials: Arc::new(credentials),
        })
    }

    /// Parses authentication credentials from `JSON`.
    ///
    /// # Errors
    ///
    /// Returns `InitError::Config` if the text is invalid or parsed credentials fail validation.
    pub fn from_json(text: &str) -> Result<Self, InitError> {
        let entries: Vec<CredentialConfig> = serde_json::from_str(text)
            .map_err(|error| InitError::Config(format!("invalid credentials JSON: {error}")))?;
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

    fn authenticate(&self, token: &str) -> Option<Principal> {
        self.credentials.iter().find_map(|credential| {
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
struct Principal {
    user_id: String,
    projects: BTreeMap<String, Role>,
    global_admin: bool,
}

impl Principal {
    fn permits(&self, project: &str, required: Role) -> bool {
        self.global_admin
            || self
                .projects
                .get(project)
                .is_some_and(|role| role.permits(required))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_report_files: usize,
    pub max_report_issues: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
            max_report_files: MAX_REPORT_FILES,
            max_report_issues: MAX_REPORT_ISSUES,
        }
    }
}

#[derive(Clone)]
struct AppState {
    store: Store,
    auth: AuthConfig,
    limits: Limits,
}

pub struct Service {
    state: AppState,
}

impl Service {
    /// Opens a service backed by the `SQLite` database at `path`.
    ///
    /// # Errors
    ///
    /// Returns `InitError` if the database cannot be opened or initialized.
    pub fn open(path: impl AsRef<std::path::Path>, auth: AuthConfig) -> Result<Self, InitError> {
        let store = Store::open(path).map_err(|error| InitError::Store(Box::new(error)))?;
        Ok(Self {
            state: AppState {
                store,
                auth,
                limits: Limits::default(),
            },
        })
    }

    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.state.limits = limits;
        self
    }

    pub fn router(&self) -> Router {
        router(self.state.clone())
    }
}

#[derive(Debug)]
pub enum InitError {
    Config(String),
    Store(Box<dyn std::error::Error + Send + Sync>),
}

impl Display for InitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration error: {message}"),
            Self::Store(_) => formatter.write_str("database initialization failed"),
        }
    }
}

impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(_) => None,
            Self::Store(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Finding,
    Hotspot,
}

impl FindingKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Hotspot => "hotspot",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "finding" => Some(Self::Finding),
            "hotspot" => Some(Self::Hotspot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Open,
    Accepted,
    Resolved,
    ToReview,
    Safe,
    ConfirmedRisk,
}

impl ReviewState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Resolved => "resolved",
            Self::ToReview => "to_review",
            Self::Safe => "safe",
            Self::ConfirmedRisk => "confirmed_risk",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "open" => Some(Self::Open),
            "accepted" => Some(Self::Accepted),
            "resolved" => Some(Self::Resolved),
            "to_review" => Some(Self::ToReview),
            "safe" => Some(Self::Safe),
            "confirmed_risk" => Some(Self::ConfirmedRisk),
            _ => None,
        }
    }
}

pub(crate) fn valid_review_transition(
    kind: FindingKind,
    previous: Option<ReviewState>,
    next: ReviewState,
) -> bool {
    (match kind {
        FindingKind::Finding => matches!(
            next,
            ReviewState::Open | ReviewState::Accepted | ReviewState::Resolved
        ),
        FindingKind::Hotspot => matches!(
            next,
            ReviewState::ToReview | ReviewState::Safe | ReviewState::ConfirmedRisk
        ),
    }) && previous.is_none_or(|previous| match kind {
        FindingKind::Finding => match previous {
            ReviewState::Open => matches!(
                next,
                ReviewState::Open | ReviewState::Accepted | ReviewState::Resolved
            ),
            ReviewState::Accepted => matches!(
                next,
                ReviewState::Open | ReviewState::Accepted | ReviewState::Resolved
            ),
            ReviewState::Resolved => matches!(
                next,
                ReviewState::Open | ReviewState::Accepted | ReviewState::Resolved
            ),
            _ => false,
        },
        FindingKind::Hotspot => match previous {
            ReviewState::ToReview => matches!(
                next,
                ReviewState::ToReview | ReviewState::Safe | ReviewState::ConfirmedRisk
            ),
            ReviewState::Safe => matches!(next, ReviewState::ToReview | ReviewState::Safe),
            ReviewState::ConfirmedRisk => {
                matches!(next, ReviewState::ToReview | ReviewState::ConfirmedRisk)
            }
            _ => false,
        },
    })
}

#[derive(Debug, Clone)]
pub(crate) struct FindingRecordInput {
    pub identity: String,
    pub occurrence: u32,
    pub kind: FindingKind,
    pub path: String,
    pub rule_key: String,
    pub message: String,
    pub range: Value,
    pub range_json: String,
    pub ambiguous: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct IngestData {
    pub project: String,
    pub branch: String,
    pub commit: String,
    pub analyzed_at: String,
    pub analyzed_epoch: i64,
    pub report_schema_version: u32,
    pub complete: bool,
    pub metrics_json: String,
    pub duplication_json: Option<String>,
    pub gate_json: Option<String>,
    pub report_json: String,
    pub assessment_json: Option<String>,
    pub content_hash: String,
    pub received_at: String,
    pub findings: Vec<FindingRecordInput>,
}
type AssessmentClaims = HashMap<(String, usize), (Option<String>, bool)>;

struct FindingAccumulator<'a> {
    keys: &'a BTreeMap<String, usize>,
    claims: &'a AssessmentClaims,
    matched_claims: &'a mut BTreeSet<(String, usize)>,
    claimed_identity_indexes: &'a mut HashMap<String, Vec<usize>>,
    occurrences: &'a mut HashMap<String, u32>,
    findings: &'a mut Vec<FindingRecordInput>,
}

#[derive(Clone, Copy)]
struct FindingBackupKeyInput<'a> {
    analysis_id: i64,
    identity: &'a str,
    occurrence: u32,
    kind: FindingKind,
    path: &'a str,
    rule_key: &'a str,
    message: &'a str,
    range_json: &'a str,
    ambiguous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackupEnvelope {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) project: String,
    pub(crate) exported_at: String,
    #[serde(default)]
    pub(crate) project_deleted_at: Option<String>,
    pub(crate) analyses: Vec<BackupAnalysis>,
    pub(crate) findings: Vec<BackupFinding>,
    pub(crate) reviews: Vec<BackupReview>,
    pub(crate) history: Vec<BackupHistory>,
    pub(crate) deletions: Vec<DeletionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeletionRecord {
    pub(crate) id: i64,
    pub(crate) resource_type: String,
    pub(crate) analysis_id: Option<i64>,
    pub(crate) action: String,
    pub(crate) actor: String,
    pub(crate) reason: String,
    pub(crate) created_at: String,
}

pub(crate) struct ValidatedRestore {
    pub backup: BackupEnvelope,
}

#[derive(Debug, Deserialize)]
struct IngestRequest {
    schema_version: u32,
    branch: String,
    commit: String,
    analyzed_at: String,
    report: Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReviewRequest {
    pub schema_version: u32,
    pub analysis_id: i64,
    pub identity: String,
    pub kind: FindingKind,
    pub state: ReviewState,
    pub reason: String,
    pub expected_version: u64,
}

#[derive(Debug, Deserialize)]
struct RetentionRequest {
    before: String,
    #[serde(default)]
    branch: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct DeleteQuery {
    reason: String,
}

#[derive(Debug, Deserialize)]
struct AnalysisQuery {
    #[serde(default)]
    branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewQuery {
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    analysis_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct FindingIdentityQuery {
    #[serde(default)]
    finding_identity: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProjectsResponse {
    projects: Vec<ProjectSummary>,
}

#[derive(Debug, Serialize)]
struct BranchesResponse {
    branches: Vec<BranchSummary>,
}

#[derive(Debug, Serialize)]
struct AnalysesResponse {
    analyses: Vec<AnalysisSummary>,
}

#[derive(Debug, Serialize)]
struct AnalysisResponse {
    analysis: AnalysisDetail,
}

#[derive(Debug, Serialize)]
struct FindingsResponse {
    findings: Vec<FindingRecord>,
}

#[derive(Debug, Serialize)]
struct ReviewsResponse {
    reviews: Vec<ReviewRecord>,
}

#[derive(Debug, Serialize)]
struct HistoryResponse {
    history: Vec<HistoryRecord>,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    analysis: AnalysisSummary,
    idempotent: bool,
}

#[derive(Debug, Serialize)]
struct ReviewResponse {
    review: ReviewRecord,
    history: HistoryRecord,
}

#[derive(Debug, Serialize)]
struct RestoreResponse {
    restore: RestoreResult,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Debug, Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "authentication is required",
        }
    }

    const fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "the credential is not authorized for this project",
        }
    }

    const fn bad_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "the request is invalid",
        }
    }

    const fn unsupported_media_type() -> Self {
        Self {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            code: "unsupported_media_type",
            message: "the request content type is not supported",
        }
    }

    const fn unprocessable_entity() -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "unprocessable_entity",
            message: "the request body could not be deserialized",
        }
    }

    const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "the requested resource was not found",
        }
    }

    const fn method_not_allowed() -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: "method_not_allowed",
            message: "the request method is not supported",
        }
    }

    const fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: "the request conflicts with immutable or concurrent state",
        }
    }

    const fn too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            message: "the request exceeds the configured size limit",
        }
    }

    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "the service could not complete the request",
        }
    }
}

fn api_body_error(status: StatusCode) -> ApiError {
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::too_large(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::unsupported_media_type(),
        StatusCode::UNPROCESSABLE_ENTITY => ApiError::unprocessable_entity(),
        StatusCode::INTERNAL_SERVER_ERROR => ApiError::internal(),
        _ => ApiError::bad_request(),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: ErrorPayload {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        security_headers(response.headers_mut());
        response
    }
}

fn router(state: AppState) -> Router {
    let max_body_bytes = state.limits.max_body_bytes;
    Router::new()
        .route(&format!("{API_PREFIX}/projects"), get(list_projects))
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/branches"),
            get(list_branches),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/analyses"),
            get(list_analyses).post(ingest_analysis),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/analyses/{{analysis_id}}"),
            get(get_analysis).delete(delete_analysis),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/analyses/{{analysis_id}}/findings"),
            get(get_findings),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/reviews"),
            get(list_reviews).post(post_review),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/reviews/{{review_id}}/history"),
            get(get_history),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/export"),
            get(export_project),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/restore"),
            post(restore_project),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/retention"),
            post(retention),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}"),
            delete(delete_project),
        )
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(apply_security_headers))
        .with_state(state)
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProjectsResponse>, ApiError> {
    let principal = authenticate(&state, &headers)?;
    let projects = state
        .store
        .list_projects()
        .map_err(|error| store_error(&error))?
        .into_iter()
        .filter(|project| principal.permits(&project.project, Role::Reader))
        .collect();
    Ok(Json(ProjectsResponse { projects }))
}

async fn list_branches(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
) -> Result<Json<BranchesResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    let branches = state
        .store
        .list_branches(&project)
        .map_err(|error| store_error(&error))?;
    Ok(Json(BranchesResponse { branches }))
}

async fn list_analyses(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeQuery(query): SafeQuery<AnalysisQuery>,
) -> Result<Json<AnalysesResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    if let Some(branch) = query.branch.as_deref() {
        validate_branch(branch)?;
    }
    let analyses = state
        .store
        .list_analyses(&project, query.branch.as_deref())
        .map_err(|error| store_error(&error))?;
    Ok(Json(AnalysesResponse { analyses }))
}

async fn get_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, analysis_id)): SafePath<(String, i64)>,
) -> Result<Json<AnalysisResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    if analysis_id <= 0 {
        return Err(ApiError::bad_request());
    }
    let analysis = state
        .store
        .get_analysis(&project, analysis_id)
        .map_err(|error| store_error(&error))?;
    Ok(Json(AnalysisResponse { analysis }))
}

async fn get_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, analysis_id)): SafePath<(String, i64)>,
) -> Result<Json<FindingsResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    if analysis_id <= 0 {
        return Err(ApiError::bad_request());
    }
    let findings = state
        .store
        .findings(&project, analysis_id)
        .map_err(|error| store_error(&error))?;
    Ok(Json(FindingsResponse { findings }))
}

async fn ingest_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeBytes(body): SafeBytes,
) -> Result<Json<IngestResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    let _ = principal;
    validate_project(&project)?;
    if body.len() > state.limits.max_body_bytes {
        return Err(ApiError::too_large());
    }
    let request: IngestRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request())?;
    let data = validate_ingest(&project, request, state.limits)?;
    let result = state
        .store
        .insert_analysis(&data)
        .map_err(|error| store_error(&error))?;
    Ok(Json(IngestResponse {
        analysis: result.analysis,
        idempotent: result.idempotent,
    }))
}

async fn list_reviews(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeQuery(query): SafeQuery<ReviewQuery>,
) -> Result<Json<ReviewsResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    if let Some(branch) = query.branch.as_deref() {
        validate_branch(branch)?;
    }
    if query.analysis_id.is_some_and(|id| id <= 0) {
        return Err(ApiError::bad_request());
    }
    let reviews = state
        .store
        .list_reviews(&project, query.branch.as_deref(), query.analysis_id)
        .map_err(|error| store_error(&error))?;
    Ok(Json(ReviewsResponse { reviews }))
}

async fn post_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeJson(request): SafeJson<ReviewRequest>,
) -> Result<Json<ReviewResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reviewer)?;
    validate_project(&project)?;
    if request.schema_version != 1 {
        return Err(ApiError::bad_request());
    }
    validate_identity_component(&request.identity, MAX_IDENTITY_BYTES, "identity")
        .map_err(|_| ApiError::bad_request())?;
    validate_reason(&request.reason)?;
    if request.analysis_id <= 0 || !is_review_identity(&request.identity) {
        return Err(ApiError::bad_request());
    }
    if !valid_review_transition(request.kind, None, request.state) {
        return Err(ApiError::bad_request());
    }
    let mutation = state
        .store
        .apply_review(&project, &request, &principal.user_id, &now_timestamp())
        .map_err(|error| store_error(&error))?;
    Ok(Json(ReviewResponse {
        review: mutation.review,
        history: mutation.history,
    }))
}

async fn get_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, review_id)): SafePath<(String, i64)>,
    SafeQuery(query): SafeQuery<FindingIdentityQuery>,
) -> Result<Json<HistoryResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Reader)?;
    let _ = principal;
    validate_project(&project)?;
    if review_id <= 0 || query.finding_identity.is_some() {
        return Err(ApiError::bad_request());
    }
    let history = state
        .store
        .review_history(&project, review_id)
        .map_err(|error| store_error(&error))?;
    Ok(Json(HistoryResponse { history }))
}

async fn delete_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, analysis_id)): SafePath<(String, i64)>,
    SafeQuery(query): SafeQuery<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    validate_project(&project)?;
    validate_reason(&query.reason)?;
    if analysis_id <= 0 {
        return Err(ApiError::bad_request());
    }
    state
        .store
        .delete_analysis(
            &project,
            analysis_id,
            &principal.user_id,
            &query.reason,
            &now_timestamp(),
        )
        .map_err(|error| store_error(&error))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeQuery(query): SafeQuery<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    validate_project(&project)?;
    validate_reason(&query.reason)?;
    state
        .store
        .delete_project(
            &project,
            &principal.user_id,
            &query.reason,
            &now_timestamp(),
        )
        .map_err(|error| store_error(&error))?;
    Ok(StatusCode::NO_CONTENT)
}
async fn export_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
) -> Result<Json<BackupEnvelope>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    let _ = principal;
    validate_project(&project)?;
    let backup = state
        .store
        .export_project(&project, &now_timestamp())
        .map_err(|error| store_error(&error))?;
    if serde_json::to_vec(&backup)
        .map_err(|_| ApiError::internal())?
        .len()
        > state.limits.max_body_bytes
    {
        return Err(ApiError::too_large());
    }
    Ok(Json(backup))
}

async fn restore_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeBytes(body): SafeBytes,
) -> Result<Json<RestoreResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    let _ = principal;
    validate_project(&project)?;
    if body.len() > state.limits.max_body_bytes {
        return Err(ApiError::too_large());
    }
    let backup: BackupEnvelope =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request())?;
    let validated = validate_restore(&project, backup, state.limits)?;
    let result = state
        .store
        .restore(&validated)
        .map_err(|error| store_error(&error))?;
    Ok(Json(RestoreResponse { restore: result }))
}

async fn retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeJson(request): SafeJson<RetentionRequest>,
) -> Result<Json<RetentionResult>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    validate_project(&project)?;
    let (before, before_epoch) =
        normalize_timestamp(&request.before).map_err(|_| ApiError::bad_request())?;
    if let Some(branch) = request.branch.as_deref() {
        validate_branch(branch)?;
    }
    validate_reason(&request.reason)?;
    let now = now_timestamp();
    let result = state
        .store
        .apply_retention(&RetentionInput {
            project: &project,
            before: &before,
            before_epoch,
            branch: request.branch.as_deref(),
            actor: &principal.user_id,
            reason: &request.reason,
            now: &now,
        })
        .map_err(|error| store_error(&error))?;
    Ok(Json(result))
}

async fn index() -> Response {
    static_response(
        "text/html; charset=utf-8",
        include_str!("../static/index.html"),
    )
}

async fn app_js() -> Response {
    static_response(
        "text/javascript; charset=utf-8",
        include_str!("../static/app.js"),
    )
}

async fn style_css() -> Response {
    static_response(
        "text/css; charset=utf-8",
        include_str!("../static/style.css"),
    )
}

async fn api_not_found(uri: Uri) -> Response {
    let _ = uri;
    ApiError::not_found().into_response()
}
async fn api_method_not_allowed() -> Response {
    ApiError::method_not_allowed().into_response()
}

async fn apply_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    security_headers(response.headers_mut());
    response
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response =
        (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response();
    security_headers(response.headers_mut());
    response
}

fn security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    state
        .auth
        .authenticate(token)
        .ok_or_else(ApiError::unauthorized)
}

fn authorize_project(
    state: &AppState,
    headers: &HeaderMap,
    project: &str,
    required: Role,
) -> Result<Principal, ApiError> {
    let principal = authenticate(state, headers)?;
    if !principal.permits(project, required) {
        return Err(ApiError::forbidden());
    }
    Ok(principal)
}

fn store_error(error: &StoreError) -> ApiError {
    match error {
        StoreError::Conflict(_) => ApiError::conflict(),
        StoreError::NotFound => ApiError::not_found(),
        StoreError::Sql(_) | StoreError::Invalid(_) => ApiError::internal(),
    }
}

fn validate_ingest(
    project: &str,
    request: IngestRequest,
    limits: Limits,
) -> Result<IngestData, ApiError> {
    if request.schema_version != 1 {
        return Err(ApiError::bad_request());
    }
    validate_branch(&request.branch)?;
    validate_commit(&request.commit)?;
    let (analyzed_at, analyzed_epoch) =
        normalize_timestamp(&request.analyzed_at).map_err(|_| ApiError::bad_request())?;
    let report_object = request
        .report
        .as_object()
        .ok_or_else(ApiError::bad_request)?;
    let report_schema = report_object
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(ApiError::bad_request)?;
    if report_schema != 1 {
        return Err(ApiError::bad_request());
    }
    validate_report_shape(&request.report, limits)?;
    let report: AnalysisReport =
        serde_json::from_value(request.report.clone()).map_err(|_| ApiError::bad_request())?;
    if report.schema_version != 1 {
        return Err(ApiError::bad_request());
    }
    if let Some(assessment) = report.assessment.as_ref() {
        assessment
            .validate_against(&report.files)
            .map_err(|_| ApiError::conflict())?;
        validate_gate_claim_against_report(assessment.gate.as_ref(), &report)?;
        if assessment
            .context
            .source_revision
            .as_deref()
            .is_some_and(|revision| revision != request.commit)
        {
            return Err(ApiError::conflict());
        }
    }
    let report_json =
        serde_json::to_string(&request.report).map_err(|_| ApiError::bad_request())?;
    let assessment = request.report.get("assessment").cloned();
    validate_assessment_binding(assessment.as_ref(), &request.commit)?;
    let assessment_json = assessment
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::bad_request())?;
    let metrics_json = serde_json::to_string(&json!(report.project.metrics))
        .map_err(|_| ApiError::bad_request())?;
    let duplication_json = report
        .project
        .duplication
        .as_ref()
        .map(|duplication| {
            serde_json::to_value(duplication).and_then(|value| serde_json::to_string(&value))
        })
        .transpose()
        .map_err(|_| ApiError::bad_request())?;
    let gate_json = assessment
        .as_ref()
        .and_then(|value| value.get("gate"))
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::bad_request())?;
    let findings = extract_findings(&report, assessment.as_ref())?;
    let content_hash = hash_bytes(
        format!(
            "{}\n{}\n{}\n{}",
            request.branch, request.commit, analyzed_at, report_json
        )
        .as_bytes(),
    );
    Ok(IngestData {
        project: project.to_string(),
        branch: request.branch,
        commit: request.commit,
        analyzed_at,
        analyzed_epoch,
        report_schema_version: 1,
        complete: report.project.complete,
        metrics_json,
        duplication_json,
        gate_json,
        report_json,
        assessment_json,
        content_hash,
        received_at: now_timestamp(),
        findings,
    })
}

fn validate_report_shape(report: &Value, limits: Limits) -> Result<(), ApiError> {
    validate_json_paths(report)?;
    let object = report.as_object().ok_or_else(ApiError::bad_request)?;
    let files = object
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(ApiError::bad_request)?;
    if files.len() > limits.max_report_files {
        return Err(ApiError::too_large());
    }
    let project = object
        .get("project")
        .and_then(Value::as_object)
        .ok_or_else(ApiError::bad_request)?;
    let project_files = project
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(ApiError::bad_request)?;
    if project_files.len() > MAX_REPORT_PROJECT_FILES {
        return Err(ApiError::too_large());
    }
    let mut issue_count = 0_usize;
    for file in files {
        let file_object = file.as_object().ok_or_else(ApiError::bad_request)?;
        let path = file_object
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(ApiError::bad_request)?;
        validate_relative_path(path).map_err(|_| ApiError::bad_request())?;
        validate_string(
            file_object.get("language").and_then(Value::as_str),
            MAX_RULE_BYTES,
        )?;
        let issues = file_object
            .get("issues")
            .and_then(Value::as_array)
            .ok_or_else(ApiError::bad_request)?;
        issue_count = issue_count.saturating_add(issues.len());
        if issue_count > limits.max_report_issues {
            return Err(ApiError::too_large());
        }
        for issue in issues {
            let issue_object = issue.as_object().ok_or_else(ApiError::bad_request)?;
            validate_string(
                issue_object.get("rule_key").and_then(Value::as_str),
                MAX_RULE_BYTES,
            )?;
            validate_string(
                issue_object.get("message").and_then(Value::as_str),
                MAX_MESSAGE_BYTES,
            )?;
        }
    }
    if let Some(assessment) = object.get("assessment") {
        validate_assessment(assessment)?;
    }
    Ok(())
}
fn validate_assessment(assessment: &Value) -> Result<(), ApiError> {
    let object = assessment.as_object().ok_or_else(ApiError::bad_request)?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(ApiError::bad_request());
    }
    if let Some(sources) = object.get("sources") {
        validate_assessment_sources(sources)?;
    }
    validate_gate_claim(object.get("gate"))?;
    Ok(())
}

fn validate_assessment_sources(sources: &Value) -> Result<(), ApiError> {
    let sources = sources.as_array().ok_or_else(ApiError::bad_request)?;
    if sources.len() > MAX_ASSESSMENT_SOURCES {
        return Err(ApiError::too_large());
    }
    let mut findings = 0_usize;
    for source in sources {
        validate_assessment_source(source, &mut findings)?;
    }
    Ok(())
}

fn validate_assessment_source(source: &Value, findings: &mut usize) -> Result<(), ApiError> {
    let source = source.as_object().ok_or_else(ApiError::bad_request)?;
    let path = source
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(ApiError::bad_request)?;
    validate_relative_path(path).map_err(|_| ApiError::bad_request())?;
    let Some(entries) = source.get("findings") else {
        return Ok(());
    };
    let entries = entries.as_array().ok_or_else(ApiError::bad_request)?;
    *findings = (*findings).saturating_add(entries.len());
    if *findings > MAX_ASSESSMENT_FINDINGS {
        return Err(ApiError::too_large());
    }
    for finding in entries {
        validate_assessment_finding(finding)?;
    }
    Ok(())
}

fn validate_assessment_finding(finding: &Value) -> Result<(), ApiError> {
    let finding = finding.as_object().ok_or_else(ApiError::bad_request)?;
    if let Some(identity) = finding.get("identity").and_then(Value::as_str)
        && canonical_claim_identity(identity).is_none()
    {
        return Err(ApiError::bad_request());
    }
    if finding
        .get("ambiguous")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_assessment_binding(assessment: Option<&Value>, commit: &str) -> Result<(), ApiError> {
    let Some(assessment) = assessment else {
        return Ok(());
    };
    let object = assessment.as_object().ok_or_else(ApiError::bad_request)?;
    if let Some(context) = object.get("context") {
        let context = context.as_object().ok_or_else(ApiError::bad_request)?;
        if let Some(source_revision) = context.get("source_revision") {
            if let Some(source_revision) = source_revision.as_str() {
                if source_revision != commit {
                    return Err(ApiError::conflict());
                }
            } else if !source_revision.is_null() {
                return Err(ApiError::bad_request());
            }
        }
    }
    Ok(())
}
fn validate_gate_claim_against_report(
    gate: Option<&GateReport>,
    report: &AnalysisReport,
) -> Result<(), ApiError> {
    let Some(gate) = gate else {
        return Ok(());
    };
    gate.validate().map_err(|_| ApiError::conflict())?;
    let config = GateConfig {
        schema_version: GATE_CONFIG_SCHEMA_VERSION,
        conditions: gate
            .conditions
            .iter()
            .map(|condition| GateCondition {
                scope: condition.scope,
                metric: condition.metric.clone(),
                operator: condition.operator,
                threshold: condition.threshold,
            })
            .collect(),
    };
    let evaluated = evaluate_gate(&config, report);
    if evaluated.schema_version != gate.schema_version
        || evaluated.status != gate.status
        || evaluated.conditions.len() != gate.conditions.len()
        || evaluated
            .conditions
            .iter()
            .zip(&gate.conditions)
            .any(|(expected, claimed)| {
                expected.scope != claimed.scope
                    || expected.metric != claimed.metric
                    || expected.operator != claimed.operator
                    || expected.threshold.partial_cmp(&claimed.threshold) != Some(Ordering::Equal)
                    || expected.actual != claimed.actual
                    || expected.status != claimed.status
            })
    {
        return Err(ApiError::conflict());
    }
    Ok(())
}

fn validate_gate_claim(gate: Option<&Value>) -> Result<(), ApiError> {
    let Some(gate) = gate else {
        return Ok(());
    };
    let gate = gate.as_object().ok_or_else(ApiError::bad_request)?;
    let status = gate
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(ApiError::bad_request)?;
    if !matches!(status, "pass" | "fail" | "unavailable") {
        return Err(ApiError::bad_request());
    }
    if status != "pass" {
        return Ok(());
    }
    let conditions = gate
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or_else(ApiError::bad_request)?;
    if conditions.is_empty() {
        return Err(ApiError::conflict());
    }
    for condition in conditions {
        let condition = condition.as_object().ok_or_else(ApiError::bad_request)?;
        if condition
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status != "pass")
            || condition.get("actual").is_none_or(Value::is_null)
        {
            return Err(ApiError::conflict());
        }
    }
    Ok(())
}
fn extract_findings(
    report: &AnalysisReport,
    assessment: Option<&Value>,
) -> Result<Vec<FindingRecordInput>, ApiError> {
    let keys = finding_key_counts(report)?;
    let claims = assessment_claims(assessment)?;
    let mut matched_claims = BTreeSet::new();
    let mut claimed_identity_indexes = HashMap::<String, Vec<usize>>::new();
    let mut occurrences = HashMap::<String, u32>::new();
    let mut findings = Vec::new();
    {
        let mut accumulator = FindingAccumulator {
            keys: &keys,
            claims: &claims,
            matched_claims: &mut matched_claims,
            claimed_identity_indexes: &mut claimed_identity_indexes,
            occurrences: &mut occurrences,
            findings: &mut findings,
        };
        for file in &report.files {
            append_file_findings(file, &mut accumulator)?;
        }
    }

    if claims.keys().any(|key| !matched_claims.contains(key)) {
        return Err(ApiError::bad_request());
    }
    for indexes in claimed_identity_indexes
        .values()
        .filter(|indexes| indexes.len() > 1)
    {
        for index in indexes {
            findings[*index].ambiguous = true;
        }
    }
    Ok(findings)
}

fn finding_key_counts(report: &AnalysisReport) -> Result<BTreeMap<String, usize>, ApiError> {
    let mut keys = BTreeMap::<String, usize>::new();
    for file in &report.files {
        let path = path_string(&file.path)?;
        for issue in &file.issues {
            let key = finding_key(&path, &file.language, issue);
            *keys.entry(key).or_default() += 1;
        }
    }
    Ok(keys)
}

fn append_file_findings(
    file: &FileReport,
    accumulator: &mut FindingAccumulator<'_>,
) -> Result<(), ApiError> {
    let path = path_string(&file.path)?;
    for (issue_index, issue) in file.issues.iter().enumerate() {
        append_finding(&path, &file.language, issue_index, issue, accumulator)?;
    }
    Ok(())
}

fn append_finding(
    path: &str,
    language: &str,
    issue_index: usize,
    issue: &Issue,
    accumulator: &mut FindingAccumulator<'_>,
) -> Result<(), ApiError> {
    let key = finding_key(path, language, issue);
    let fallback_identity = format!("sha256:{}", hash_bytes(key.as_bytes()));
    let duplicate = accumulator.keys.get(&key).copied().unwrap_or_default() > 1;
    let kind = issue_kind(issue)?;
    let (identity, claimed, claim_present) = {
        let claim = accumulator.claims.get(&(path.to_owned(), issue_index));
        let claim_present = claim.is_some();
        let (identity, claimed) = match claim {
            Some((Some(identity), false)) => match canonical_claim_identity(identity) {
                Some(identity) => (identity, true),
                None => (fallback_identity, false),
            },
            _ => (fallback_identity, false),
        };
        (identity, claimed, claim_present)
    };
    let occurrence_key = format!("{identity}\0{}", kind.as_str());
    let occurrence = accumulator.occurrences.entry(occurrence_key).or_insert(0);
    let this_occurrence = *occurrence;
    *occurrence = occurrence.saturating_add(1);
    if claim_present {
        accumulator
            .matched_claims
            .insert((path.to_owned(), issue_index));
    }
    let range = serde_json::to_value(&issue.range).map_err(|_| ApiError::bad_request())?;
    let range_json = serde_json::to_string(&range).map_err(|_| ApiError::bad_request())?;
    let index = accumulator.findings.len();
    accumulator.findings.push(FindingRecordInput {
        identity: identity.clone(),
        occurrence: this_occurrence,
        kind,
        path: path.to_owned(),
        rule_key: issue.rule_key.clone(),
        message: issue.message.clone(),
        range,
        range_json,
        ambiguous: duplicate || !claimed,
    });
    if claimed {
        accumulator
            .claimed_identity_indexes
            .entry(identity)
            .or_default()
            .push(index);
    }
    Ok(())
}

fn canonical_claim_identity(raw: &str) -> Option<String> {
    let digest = raw.strip_prefix("sha256:").unwrap_or(raw);
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", digest.to_ascii_lowercase()))
}
fn is_review_identity(raw: &str) -> bool {
    let Some(digest) = raw.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn assessment_claims(assessment: Option<&Value>) -> Result<AssessmentClaims, ApiError> {
    let mut claims = HashMap::new();
    let Some(assessment) = assessment else {
        return Ok(claims);
    };
    let Some(sources) = assessment.get("sources").and_then(Value::as_array) else {
        return Ok(claims);
    };
    for source in sources {
        let source = source.as_object().ok_or_else(ApiError::bad_request)?;
        let path = source
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(ApiError::bad_request)?
            .to_string();
        let Some(findings) = source.get("findings").and_then(Value::as_array) else {
            continue;
        };
        for finding in findings {
            let finding = finding.as_object().ok_or_else(ApiError::bad_request)?;
            let index = finding
                .get("issue_index")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(ApiError::bad_request)?;
            let identity = finding
                .get("identity")
                .and_then(Value::as_str)
                .map(str::to_string);
            let ambiguous = finding
                .get("ambiguous")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if claims
                .insert((path.clone(), index), (identity, ambiguous))
                .is_some()
            {
                return Err(ApiError::bad_request());
            }
        }
    }
    Ok(claims)
}
fn issue_kind(issue: &Issue) -> Result<FindingKind, ApiError> {
    let rule_type = embedded()
        .rule(&issue.rule_key)
        .map(|rule| rule.rule_type.as_str())
        .or_else(|| native_rule(&issue.rule_key).map(|rule| rule.rule_type));
    match rule_type {
        Some("SECURITY_HOTSPOT") => Ok(FindingKind::Hotspot),
        Some("BUG" | "CODE_SMELL" | "VULNERABILITY") => Ok(FindingKind::Finding),

        Some(_) | None => Err(ApiError::bad_request()),
    }
}
fn history_chain_matches<'a>(
    entries: impl Iterator<Item = &'a BackupHistory>,
    expected: ReviewState,
) -> bool {
    let mut previous = None;
    for history in entries {
        if history.previous_state != previous
            || !valid_review_transition(history.kind, history.previous_state, history.new_state)
        {
            return false;
        }
        previous = Some(history.new_state);
    }
    previous == Some(expected)
}

fn finding_key(path: &str, language: &str, issue: &Issue) -> String {
    format!("{path}\0{language}\0{}\0{}", issue.rule_key, issue.message)
}

fn validate_restore(
    project: &str,
    mut backup: BackupEnvelope,
    limits: Limits,
) -> Result<ValidatedRestore, ApiError> {
    validate_restore_header(project, &backup)?;
    let derived = validate_restore_analyses(project, &backup.analyses, limits)?;
    validate_restore_findings(&backup.findings, &derived)?;
    {
        let reviews_by_id = validate_restore_reviews(project, &backup.reviews, &derived)?;
        let history_by_review =
            validate_restore_history(&backup.history, &reviews_by_id, &derived)?;
        validate_restore_history_chains(&backup.reviews, &history_by_review)?;
    }
    validate_restore_deletions(&backup.deletions, &derived)?;
    backup.findings.sort_by(|left, right| {
        (left.analysis_id, left.identity.as_str(), left.path.as_str()).cmp(&(
            right.analysis_id,
            right.identity.as_str(),
            right.path.as_str(),
        ))
    });
    Ok(ValidatedRestore { backup })
}

fn validate_restore_header(project: &str, backup: &BackupEnvelope) -> Result<(), ApiError> {
    if backup.schema_version != 1
        || backup.kind != "hoonarqube_service_backup"
        || backup.project != project
    {
        return Err(ApiError::bad_request());
    }
    validate_project(project)?;
    validate_timestamp(&backup.exported_at).map_err(|_| ApiError::bad_request())?;
    if let Some(deleted_at) = backup.project_deleted_at.as_deref() {
        validate_timestamp(deleted_at).map_err(|_| ApiError::bad_request())?;
    }
    Ok(())
}

fn validate_restore_analyses(
    project: &str,
    analyses: &[BackupAnalysis],
    limits: Limits,
) -> Result<HashMap<i64, (String, Vec<FindingRecordInput>)>, ApiError> {
    let mut derived = HashMap::<i64, (String, Vec<FindingRecordInput>)>::new();
    let mut analysis_ids = BTreeSet::new();
    for analysis in analyses {
        if analysis.id <= 0 || !analysis_ids.insert(analysis.id) {
            return Err(ApiError::bad_request());
        }
        let (branch, findings) = validate_restore_analysis(project, analysis, limits)?;
        derived.insert(analysis.id, (branch, findings));
    }
    Ok(derived)
}

fn validate_restore_analysis(
    project: &str,
    analysis: &BackupAnalysis,
    limits: Limits,
) -> Result<(String, Vec<FindingRecordInput>), ApiError> {
    validate_branch(&analysis.branch)?;
    validate_commit(&analysis.commit)?;
    validate_timestamp(&analysis.analyzed_at).map_err(|_| ApiError::bad_request())?;
    if let Some(deleted_at) = analysis.deleted_at.as_deref() {
        validate_timestamp(deleted_at).map_err(|_| ApiError::bad_request())?;
    }
    validate_identity_component(&analysis.content_hash, 128, "content_hash")
        .map_err(|_| ApiError::bad_request())?;
    if analysis.report_schema_version != 1 {
        return Err(ApiError::bad_request());
    }
    let data = validate_ingest(
        project,
        IngestRequest {
            schema_version: 1,
            branch: analysis.branch.clone(),
            commit: analysis.commit.clone(),
            analyzed_at: analysis.analyzed_at.clone(),
            report: analysis.report.clone(),
        },
        limits,
    )?;
    let normalized_backup_at =
        normalize_timestamp(&analysis.analyzed_at).map_err(|_| ApiError::bad_request())?;
    validate_restore_analysis_match(analysis, &data, normalized_backup_at.1)?;
    Ok((analysis.branch.clone(), data.findings))
}
fn validate_restore_analysis_match(
    analysis: &BackupAnalysis,
    data: &IngestData,
    normalized_epoch: i64,
) -> Result<(), ApiError> {
    if data.analyzed_at != analysis.analyzed_at
        || data.analyzed_epoch != analysis.analyzed_epoch
        || data.analyzed_epoch != normalized_epoch
        || data.content_hash != analysis.content_hash
        || data.complete != analysis.complete
        || data.report_json
            != serde_json::to_string(&analysis.report).map_err(|_| ApiError::bad_request())?
        || optional_json_text(analysis.assessment.as_ref()) != data.assessment_json
        || data.metrics_json
            != serde_json::to_string(&analysis.metrics).map_err(|_| ApiError::bad_request())?
        || data.duplication_json != optional_json_text(analysis.duplication.as_ref())
        || data.gate_json != optional_json_text(analysis.gate.as_ref())
    {
        return Err(ApiError::conflict());
    }
    Ok(())
}

fn validate_restore_findings(
    findings: &[BackupFinding],
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<(), ApiError> {
    let expected = expected_restore_findings(derived);
    let actual = actual_restore_findings(findings, derived)?;
    if expected != actual {
        return Err(ApiError::conflict());
    }
    Ok(())
}

fn expected_restore_findings(
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> HashMap<(i64, String), usize> {
    let mut expected = HashMap::<(i64, String), usize>::new();
    for (analysis_id, (_, findings)) in derived {
        for finding in findings {
            let key = finding_backup_key(&FindingBackupKeyInput {
                analysis_id: *analysis_id,
                identity: &finding.identity,
                occurrence: finding.occurrence,
                kind: finding.kind,
                path: &finding.path,
                rule_key: &finding.rule_key,
                message: &finding.message,
                range_json: &finding.range_json,
                ambiguous: finding.ambiguous,
            });
            *expected.entry(key).or_default() += 1;
        }
    }
    expected
}

fn actual_restore_findings(
    findings: &[BackupFinding],
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<HashMap<(i64, String), usize>, ApiError> {
    let mut actual = HashMap::<(i64, String), usize>::new();
    for finding in findings {
        validate_relative_path(&finding.path).map_err(|_| ApiError::bad_request())?;
        validate_identity_component(&finding.identity, MAX_IDENTITY_BYTES, "identity")
            .map_err(|_| ApiError::bad_request())?;
        validate_string(Some(&finding.rule_key), MAX_RULE_BYTES)?;
        validate_string(Some(&finding.message), MAX_MESSAGE_BYTES)?;
        if !derived.contains_key(&finding.analysis_id) {
            return Err(ApiError::bad_request());
        }
        let range_json =
            serde_json::to_string(&finding.range).map_err(|_| ApiError::bad_request())?;
        let key = finding_backup_key(&FindingBackupKeyInput {
            analysis_id: finding.analysis_id,
            identity: &finding.identity,
            occurrence: finding.occurrence,
            kind: finding.kind,
            path: &finding.path,
            rule_key: &finding.rule_key,
            message: &finding.message,
            range_json: &range_json,
            ambiguous: finding.ambiguous,
        });
        *actual.entry(key).or_default() += 1;
    }
    Ok(actual)
}

fn validate_restore_reviews<'a>(
    project: &str,
    reviews: &'a [BackupReview],
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<HashMap<i64, &'a BackupReview>, ApiError> {
    let mut reviews_by_id = HashMap::new();
    let mut review_keys = BTreeSet::new();
    for review in reviews {
        if review.id <= 0 || reviews_by_id.insert(review.id, review).is_some() {
            return Err(ApiError::bad_request());
        }
        if review.project != project
            || !validate_review_reference(review, derived)
            || !review_keys.insert((
                review.branch.clone(),
                review.identity.clone(),
                review.kind.as_str(),
            ))
        {
            return Err(ApiError::conflict());
        }
        validate_reason(&review.reason)?;
        validate_identity_component(&review.updated_by, MAX_PROJECT_BYTES, "updated_by")
            .map_err(|_| ApiError::bad_request())?;
        validate_timestamp(&review.updated_at).map_err(|_| ApiError::bad_request())?;
        if review.version == 0 || !valid_review_transition(review.kind, None, review.state) {
            return Err(ApiError::bad_request());
        }
    }
    Ok(reviews_by_id)
}

fn validate_restore_history<'a>(
    history: &'a [BackupHistory],
    reviews_by_id: &HashMap<i64, &'a BackupReview>,
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<HashMap<i64, BTreeMap<u64, &'a BackupHistory>>, ApiError> {
    let mut history_by_review = HashMap::<i64, BTreeMap<u64, &'a BackupHistory>>::new();
    let mut history_ids = BTreeSet::new();
    for history in history {
        if history.id <= 0 || !history_ids.insert(history.id) {
            return Err(ApiError::bad_request());
        }
        let review = reviews_by_id
            .get(&history.review_id)
            .ok_or_else(ApiError::bad_request)?;
        let Some((analysis_branch, findings)) = derived.get(&history.analysis_id) else {
            return Err(ApiError::bad_request());
        };
        validate_restore_history_entry(
            history,
            review,
            analysis_branch,
            findings,
            &mut history_by_review,
        )?;
    }
    Ok(history_by_review)
}
fn validate_restore_history_entry<'a>(
    history: &'a BackupHistory,
    review: &BackupReview,
    analysis_branch: &str,
    findings: &[FindingRecordInput],
    history_by_review: &mut HashMap<i64, BTreeMap<u64, &'a BackupHistory>>,
) -> Result<(), ApiError> {
    let (review_branch, review_identity, review_kind) = (
        review.branch.as_str(),
        review.identity.as_str(),
        review.kind,
    );
    if analysis_branch != review_branch
        || history.identity != review_identity
        || history.kind != review_kind
        || !findings.iter().any(|finding| {
            finding.identity == history.identity
                && finding.kind == history.kind
                && !finding.ambiguous
        })
    {
        return Err(ApiError::conflict());
    }
    validate_identity_component(&history.actor, MAX_PROJECT_BYTES, "actor")
        .map_err(|_| ApiError::bad_request())?;
    validate_reason(&history.reason)?;
    validate_timestamp(&history.created_at).map_err(|_| ApiError::bad_request())?;
    if history.version == 0
        || !valid_review_transition(history.kind, history.previous_state, history.new_state)
    {
        return Err(ApiError::bad_request());
    }
    if history_by_review
        .entry(history.review_id)
        .or_default()
        .insert(history.version, history)
        .is_some()
    {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_restore_history_chains(
    reviews: &[BackupReview],
    history_by_review: &HashMap<i64, BTreeMap<u64, &BackupHistory>>,
) -> Result<(), ApiError> {
    for review in reviews {
        let entries = history_by_review
            .get(&review.id)
            .ok_or_else(ApiError::bad_request)?;
        if entries.len() != usize::try_from(review.version).map_err(|_| ApiError::bad_request())?
            || entries
                .keys()
                .copied()
                .enumerate()
                .any(|(index, version)| version != u64::try_from(index + 1).unwrap_or(u64::MAX))
        {
            return Err(ApiError::conflict());
        }
        if !history_chain_matches(entries.values().copied(), review.state) {
            return Err(ApiError::conflict());
        }
    }
    Ok(())
}

fn validate_restore_deletions(
    deletions: &[DeletionRecord],
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<(), ApiError> {
    let mut deletion_ids = BTreeSet::new();
    for deletion in deletions {
        if deletion.id <= 0 || !deletion_ids.insert(deletion.id) {
            return Err(ApiError::bad_request());
        }
        validate_string(Some(&deletion.resource_type), 32)?;
        validate_string(Some(&deletion.action), 32)?;
        validate_string(Some(&deletion.actor), MAX_PROJECT_BYTES)?;
        validate_reason(&deletion.reason)?;
        validate_timestamp(&deletion.created_at).map_err(|_| ApiError::bad_request())?;
        if !matches!(deletion.resource_type.as_str(), "analysis" | "project")
            || !matches!(deletion.action.as_str(), "delete" | "retention")
            || (deletion.action == "retention" && deletion.resource_type != "analysis")
        {
            return Err(ApiError::bad_request());
        }
        match (deletion.resource_type.as_str(), deletion.analysis_id) {
            ("project", None) => {}
            ("analysis", Some(analysis_id)) if derived.contains_key(&analysis_id) => {}
            _ => return Err(ApiError::bad_request()),
        }
    }
    Ok(())
}

fn optional_json_text(value: Option<&Value>) -> Option<String> {
    value.map(|value| serde_json::to_string(value).expect("JSON values are serializable"))
}
fn finding_backup_key(input: &FindingBackupKeyInput<'_>) -> (i64, String) {
    let FindingBackupKeyInput {
        analysis_id,
        identity,
        occurrence,
        kind,
        path,
        rule_key,
        message,
        range_json,
        ambiguous,
    } = *input;
    let kind = kind.as_str();
    (
        analysis_id,
        format!(
            "{identity}\0{occurrence}\0{kind}\0{path}\0{rule_key}\0{message}\0{range_json}\0{ambiguous}"
        ),
    )
}

fn validate_review_reference(
    review: &BackupReview,
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> bool {
    let Some((branch, findings)) = derived.get(&review.analysis_id) else {
        return false;
    };
    branch == &review.branch
        && findings.iter().any(|finding| {
            finding.identity == review.identity && finding.kind == review.kind && !finding.ambiguous
        })
}

fn validate_project(project: &str) -> Result<(), ApiError> {
    validate_identity_component(project, MAX_PROJECT_BYTES, "project")
        .map_err(|_| ApiError::bad_request())
}

fn validate_branch(branch: &str) -> Result<(), ApiError> {
    validate_identity_component(branch, MAX_BRANCH_BYTES, "branch")
        .map_err(|_| ApiError::bad_request())?;
    if branch.contains("..") || branch.contains('\\') || branch.starts_with('/') {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_commit(commit: &str) -> Result<(), ApiError> {
    validate_identity_component(commit, MAX_COMMIT_BYTES, "commit")
        .map_err(|_| ApiError::bad_request())?;
    if commit.contains('/') || commit.contains('\\') || commit.contains("..") {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), ApiError> {
    validate_string(Some(reason), MAX_REASON_BYTES)
}

fn validate_identity_component(value: &str, max_bytes: usize, _name: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err("invalid bounded identity component".to_string());
    }
    Ok(())
}

fn validate_string(value: Option<&str>, max_bytes: usize) -> Result<(), ApiError> {
    let value = value.ok_or_else(ApiError::bad_request)?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\\') || path.contains(':') {
        return Err("path is not a bounded relative path".to_string());
    }
    let path = FsPath::new(path);
    if path.is_absolute() {
        return Err("absolute paths are not accepted".to_string());
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err("path traversal is not accepted".to_string());
        }
    }
    Ok(())
}

fn validate_json_paths(value: &Value) -> Result<(), ApiError> {
    match value {
        Value::Array(values) => values.iter().try_for_each(validate_json_paths),
        Value::Object(object) => {
            for (key, child) in object {
                if key == "path" {
                    let path = child.as_str().ok_or_else(ApiError::bad_request)?;
                    validate_relative_path(path).map_err(|_| ApiError::bad_request())?;
                } else if key == "roots" {
                    let roots = child.as_array().ok_or_else(ApiError::bad_request)?;
                    for root in roots {
                        let root = root.as_str().ok_or_else(ApiError::bad_request)?;
                        validate_relative_path(root).map_err(|_| ApiError::bad_request())?;
                    }
                }
                validate_json_paths(child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn path_string(path: &FsPath) -> Result<String, ApiError> {
    let path = path.to_str().ok_or_else(ApiError::bad_request)?;
    validate_relative_path(path).map_err(|_| ApiError::bad_request())?;
    Ok(path.to_string())
}

fn normalize_timestamp(timestamp: &str) -> Result<(String, i64), String> {
    if timestamp.is_empty() || timestamp.len() > 64 || timestamp.chars().any(char::is_control) {
        return Err("timestamp is not bounded".to_string());
    }
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339)
        .map_err(|_| "timestamp must be RFC3339".to_string())?;
    let canonical = parsed
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| "timestamp cannot be formatted".to_string())?;
    let nanos = parsed
        .unix_timestamp_nanos()
        .try_into()
        .map_err(|_| "timestamp is outside supported range".to_string())?;
    Ok((canonical, nanos))
}

fn validate_timestamp(timestamp: &str) -> Result<(), String> {
    normalize_timestamp(timestamp).map(|_| ())
}

fn now_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);

    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::time::Duration;

    #[test]
    fn review_state_machines_are_disjoint() {
        assert!(valid_review_transition(
            FindingKind::Finding,
            None,
            ReviewState::Accepted
        ));
        assert!(!valid_review_transition(
            FindingKind::Finding,
            Some(ReviewState::Open),
            ReviewState::Safe
        ));
        assert!(valid_review_transition(
            FindingKind::Hotspot,
            Some(ReviewState::Safe),
            ReviewState::ToReview
        ));
        assert!(!valid_review_transition(
            FindingKind::Hotspot,
            Some(ReviewState::Safe),
            ReviewState::ConfirmedRisk
        ));
    }
    #[test]
    fn restore_history_rejects_non_contiguous_state_transitions() {
        let first = BackupHistory {
            id: 1,
            review_id: 1,
            analysis_id: 1,
            identity: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            kind: FindingKind::Finding,
            previous_state: None,
            new_state: ReviewState::Accepted,
            actor: "user".to_string(),
            reason: "first".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            version: 1,
        };
        let second = BackupHistory {
            previous_state: Some(ReviewState::Resolved),
            new_state: ReviewState::Accepted,
            version: 2,
            ..first.clone()
        };
        assert!(!history_chain_matches(
            [&first, &second].into_iter(),
            ReviewState::Accepted
        ));
    }

    #[test]
    fn identities_are_ambiguous_when_same_canonical_key_repeats() {
        let issue = Issue::new(
            "rust:S106",
            "same",
            hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos { line: 1, column: 0 },
                end: hoonarqube_ir::Pos { line: 1, column: 1 },
            },
        );
        let report = AnalysisReport {
            schema_version: 1,
            files: vec![FileReport {
                path: PathBuf::from("src/a.rs"),
                language: "rust".to_string(),
                issues: vec![issue.clone(), issue],
                metrics: hoonarqube_ir::FileMetrics {
                    lines: 1,
                    code_lines: 1,
                    comment_lines: 0,
                },
            }],
            project: serde_json::from_value(json!({
                "metrics":{"files":1,"lines":1,"code_lines":1,"comment_lines":0},
                "files":[],"duplications":[],"duplication":null,"complete":true,"warnings":[],"roots":[]
            }))
            .expect("project fixture"),
            assessment: None,
        };
        let findings = extract_findings(&report, None).expect("findings");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.ambiguous));
        assert_eq!(findings[0].identity, findings[1].identity);
    }

    #[test]
    fn api_body_rejections_preserve_framework_statuses() {
        assert_eq!(
            api_body_error(StatusCode::PAYLOAD_TOO_LARGE).status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            api_body_error(StatusCode::UNSUPPORTED_MEDIA_TYPE).status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            api_body_error(StatusCode::UNPROCESSABLE_ENTITY).status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            api_body_error(StatusCode::INTERNAL_SERVER_ERROR).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            api_body_error(StatusCode::BAD_REQUEST).status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn api_error_responses_include_json_and_security_headers() {
        let response = ApiError::unauthorized().into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.headers().get(header::CONTENT_SECURITY_POLICY),
            Some(&HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'"
            ))
        );
        assert_eq!(
            response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer"))
        );
    }
    const TEST_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'";
    static NEXT_HTTP_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct RawHttpResponse {
        status: u16,
        headers: std::collections::BTreeMap<String, String>,
        body: Vec<u8>,
    }

    fn response_header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn response_content_length(header_bytes: &[u8]) -> Option<usize> {
        String::from_utf8_lossy(header_bytes)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
    }

    fn parse_http_response(bytes: &[u8]) -> RawHttpResponse {
        let header_end = response_header_end(bytes).expect("HTTP response headers");
        let header_text = String::from_utf8_lossy(&bytes[..header_end]);
        let mut lines = header_text.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .expect("HTTP response status");
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect();
        RawHttpResponse {
            status,
            headers,
            body: bytes[header_end + 4..].to_vec(),
        }
    }

    fn send_http_request(address: SocketAddr, request: &str) -> RawHttpResponse {
        let mut stream = TcpStream::connect(address).expect("connect to test service");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set HTTP read timeout");
        stream
            .write_all(request.as_bytes())
            .expect("write HTTP request");
        let mut response = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = match stream.read(&mut buffer) {
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("read HTTP response: {error}"),
            };
            if count == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..count]);
            if let Some(header_end) = response_header_end(&response)
                && let Some(length) = response_content_length(&response[..header_end])
                && response.len() >= header_end + 4 + length
            {
                break;
            }
        }
        parse_http_response(&response)
    }

    async fn http_request(address: SocketAddr, request: String) -> RawHttpResponse {
        tokio::task::spawn_blocking(move || send_http_request(address, &request))
            .await
            .expect("HTTP client task")
    }

    async fn api_request(
        address: SocketAddr,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> RawHttpResponse {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(content_type) = content_type {
            write!(&mut request, "Content-Type: {content_type}\r\n").expect("write request header");
        }
        request.push_str("\r\n");
        request.push_str(body);
        http_request(address, request).await
    }

    fn assert_api_headers(response: &RawHttpResponse) {
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            response
                .headers
                .get("content-security-policy")
                .map(String::as_str),
            Some(TEST_CSP)
        );
        assert_eq!(
            response
                .headers
                .get("x-content-type-options")
                .map(String::as_str),
            Some("nosniff")
        );
    }

    fn assert_api_error(response: &RawHttpResponse, status: u16, code: &str) {
        assert_eq!(response.status, status);
        assert_api_headers(response);
        let body: Value = serde_json::from_slice(&response.body).expect("JSON API error");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str),
            Some(code)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_api_boundaries_are_json_hardened() {
        let test_id = NEXT_HTTP_TEST_ID.fetch_add(1, AtomicOrdering::Relaxed);
        let database_path = std::env::temp_dir().join(format!(
            "hoonarqube-service-http-{}-{test_id}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&database_path);
        let auth = AuthConfig::new(vec![Credential::new(
            "admin",
            "secret",
            [("demo".to_string(), Role::Admin)],
        )])
        .expect("test credentials");
        let service = Service::open(&database_path, auth)
            .expect("test database")
            .with_limits(Limits {
                max_body_bytes: 64,
                max_report_files: 100,
                max_report_issues: 100,
            });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("test listener address");
        let router = service.router();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test service server");
        });

        let success = api_request(address, "GET", "/api/v1/projects", None, "").await;
        assert_eq!(success.status, 200);
        assert_api_headers(&success);
        let success_body: Value =
            serde_json::from_slice(&success.body).expect("JSON project response");
        assert!(success_body.get("projects").is_some_and(Value::is_array));

        let malformed = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/reviews",
            Some("application/json"),
            "{",
        )
        .await;
        assert_api_error(&malformed, 400, "invalid_request");

        let bad_path = api_request(
            address,
            "GET",
            "/api/v1/projects/demo/analyses/not-an-id",
            None,
            "",
        )
        .await;
        assert_api_error(&bad_path, 400, "invalid_request");

        let method_not_allowed = api_request(address, "POST", "/api/v1/projects", None, "").await;
        assert_api_error(&method_not_allowed, 405, "method_not_allowed");

        let oversized_body = "x".repeat(128);
        let too_large = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/reviews",
            Some("application/json"),
            &oversized_body,
        )
        .await;
        assert_api_error(&too_large, 413, "payload_too_large");

        let unsupported_media_type = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/reviews",
            Some("text/plain"),
            "{}",
        )
        .await;
        assert_api_error(&unsupported_media_type, 415, "unsupported_media_type");

        let unprocessable = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/reviews",
            Some("application/json"),
            r#"{"schema_version":"bad"}"#,
        )
        .await;
        assert_api_error(&unprocessable, 422, "unprocessable_entity");

        server.abort();
        let _ = server.await;
        drop(service);
        let _ = std::fs::remove_file(&database_path);
        let _ = std::fs::remove_file(format!("{}-wal", database_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", database_path.display()));
    }
}
