#![forbid(unsafe_code)]

mod auth;
mod store;
mod wire_json;

use auth::Principal;
pub use auth::{AuthConfig, Credential, Role};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
#[cfg(test)]
use std::path::PathBuf;
use std::path::{Component, Path as FsPath};

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
use hoonarqube_gates::{
    GATE_CONFIG_SCHEMA_VERSION, GateCondition, GateConfig, evaluate_gate,
    evaluate_gate_with_reviews, is_security_hotspot,
};
use hoonarqube_ir::assessment::{ASSESSMENT_SCHEMA_VERSION, GateReport};
use hoonarqube_ir::{AnalysisReport, FileClassification, FileReport, Issue, MeasurementStatus};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
const API_PREFIX: &str = "/api/v1";
const DEFAULT_FINDINGS_PAGE_SIZE: u16 = 100;
const MAX_FINDINGS_PAGE_SIZE: u16 = 500;
const MAX_FINDINGS_CURSOR_BYTES: usize = 42;
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

type FindingLocation = (String, hoonarqube_ir::Pos, hoonarqube_ir::Pos);

struct FindingAccumulator<'a> {
    keys: &'a BTreeMap<FindingLocation, usize>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) gate_policies: Vec<store::policy::Policy>,
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
struct IngestRequest<R = Value> {
    schema_version: u32,
    branch: String,
    commit: String,
    analyzed_at: String,
    report: R,
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

#[derive(Debug, Deserialize)]
struct FindingsPageQuery {
    limit: Option<u16>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct FindingsPageResponse {
    findings: Vec<FindingRecord>,
    next_cursor: Option<String>,
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
            &format!("{API_PREFIX}/projects/{{project}}/gate-policy"),
            get(get_project_gate_policy).put(put_project_gate_policy),
        )
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
            &format!("{API_PREFIX}/projects/{{project}}/analyses/{{analysis_id}}/gate"),
            get(get_live_gate),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/analyses/{{analysis_id}}/findings"),
            get(get_findings),
        )
        .route(
            &format!("{API_PREFIX}/projects/{{project}}/analyses/{{analysis_id}}/findings/page"),
            get(get_findings_page),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignGatePolicy {
    schema_version: u32,
    expected_version: u64,
    #[serde(deserialize_with = "store::policy::deserialize_config")]
    config: GateConfig,
}

async fn get_project_gate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
) -> Result<Json<Value>, ApiError> {
    authorize_project(&state, &headers, &project, Role::Reader)?;
    validate_project(&project)?;
    let policy = state
        .store
        .project_policy(&project)
        .map_err(|err| store_error(&err))?;
    Ok(Json(json!({"policy":policy})))
}

async fn put_project_gate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeJson(request): SafeJson<AssignGatePolicy>,
) -> Result<Json<Value>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Admin)?;
    validate_project(&project)?;
    if request.schema_version != 1 || !store::policy::valid_config(&request.config) {
        return Err(ApiError::bad_request());
    }
    let policy = state
        .store
        .assign_policy(
            &project,
            request.expected_version,
            request.config,
            &principal.user_id,
            &now_timestamp(),
        )
        .map_err(|err| store_error(&err))?;
    Ok(Json(json!({"policy":policy})))
}

/// Re-evaluates the bound gate against current authorized reviews.
async fn get_live_gate(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, analysis_id)): SafePath<(String, i64)>,
) -> Result<Json<GateReport>, ApiError> {
    authorize_project(&state, &headers, &project, Role::Reader)?;
    validate_project(&project)?;
    if analysis_id <= 0 {
        return Err(ApiError::bad_request());
    }
    let inputs = state
        .store
        .live_gate_inputs(&project, analysis_id)
        .map_err(|error| store_error(&error))?;
    let report: AnalysisReport =
        serde_json::from_value(inputs.report).map_err(|_| ApiError::internal())?;
    let config = match inputs.assigned {
        Some(config) => config,
        None => config_for_gate(
            report
                .assessment
                .as_ref()
                .and_then(|a| a.gate.as_ref())
                .ok_or_else(ApiError::not_found)?,
        ),
    };
    Ok(Json(evaluate_gate_with_reviews(
        &config,
        &report,
        &inputs.reviewed,
    )))
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

async fn get_findings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath((project, analysis_id)): SafePath<(String, i64)>,
    SafeQuery(query): SafeQuery<FindingsPageQuery>,
) -> Result<Json<FindingsPageResponse>, ApiError> {
    authorize_project(&state, &headers, &project, Role::Reader)?;
    validate_project(&project)?;
    let limit = query.limit.unwrap_or(DEFAULT_FINDINGS_PAGE_SIZE);
    if analysis_id <= 0 || !(1..=MAX_FINDINGS_PAGE_SIZE).contains(&limit) {
        return Err(ApiError::bad_request());
    }
    let after_id = query
        .cursor
        .as_deref()
        .map(|cursor| parse_finding_cursor(analysis_id, cursor))
        .transpose()?;
    let store::FindingPage { findings, next_id } = state
        .store
        .findings_page(&project, analysis_id, after_id, limit)
        .map_err(|error| store_error(&error))?;
    Ok(Json(FindingsPageResponse {
        findings,
        next_cursor: next_id.map(|id| encode_finding_cursor(analysis_id, id)),
    }))
}

fn encode_finding_cursor(analysis_id: i64, finding_id: i64) -> String {
    format!("v1.{analysis_id}.{finding_id}")
}

fn parse_finding_cursor(analysis_id: i64, cursor: &str) -> Result<i64, ApiError> {
    if cursor.len() > MAX_FINDINGS_CURSOR_BYTES {
        return Err(ApiError::bad_request());
    }
    let (_, id) = cursor.rsplit_once('.').ok_or_else(ApiError::bad_request)?;
    let id: i64 = id.parse().map_err(|_| ApiError::bad_request())?;
    if id <= 0 || encode_finding_cursor(analysis_id, id) != cursor {
        return Err(ApiError::bad_request());
    }
    Ok(id)
}

async fn ingest_analysis(
    State(state): State<AppState>,
    headers: HeaderMap,
    SafePath(project): SafePath<String>,
    SafeBytes(body): SafeBytes,
) -> Result<Json<IngestResponse>, ApiError> {
    let principal = authorize_project(&state, &headers, &project, Role::Scanner)?;
    let _ = principal;
    validate_project(&project)?;
    if body.len() > state.limits.max_body_bytes {
        return Err(ApiError::too_large());
    }
    let IngestRequest {
        schema_version,
        branch,
        commit,
        analyzed_at,
        report: raw_report,
    }: IngestRequest<&serde_json::value::RawValue> =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request())?;
    let report = wire_json::parse(raw_report.get()).map_err(|_| ApiError::bad_request())?;
    let data = validate_ingest(
        &project,
        IngestRequest {
            schema_version,
            branch,
            commit,
            analyzed_at,
            report,
        },
        state.limits,
    )?;
    let result = state
        .store
        .insert_analysis(&data, || {
            // Only consulted to match a row written by the legacy parser.
            let legacy: Value = serde_json::from_str(raw_report.get()).ok()?;
            let json = serde_json::to_string(&legacy).ok()?;
            Some(analysis_content_hash(
                &data.branch,
                &data.commit,
                &data.analyzed_at,
                &json,
            ))
        })
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
        StoreError::InvalidFindingCursor => ApiError::bad_request(),
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
    validate_report_consistency(&report)?;
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
    let content_hash =
        analysis_content_hash(&request.branch, &request.commit, &analyzed_at, &report_json);
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

fn valid_file_metrics(metrics: &hoonarqube_ir::FileMetrics) -> bool {
    metrics.code_lines <= metrics.lines && metrics.comment_lines <= metrics.lines
}

fn eligible_measurement(measurement: &hoonarqube_ir::ProjectFileMeasurement) -> bool {
    matches!(
        measurement.classification,
        FileClassification::Source | FileClassification::Test
    )
}

fn retained_report_measurement(measurement: &hoonarqube_ir::ProjectFileMeasurement) -> bool {
    eligible_measurement(measurement)
        && matches!(
            measurement.status,
            MeasurementStatus::Complete | MeasurementStatus::Failed
        )
}

fn validate_scope_measurement(
    measurement: &hoonarqube_ir::ProjectFileMeasurement,
    complete: bool,
    files: &BTreeMap<&FsPath, &FileReport>,
    totals: &mut hoonarqube_ir::ProjectMetrics,
) -> Result<(), ApiError> {
    if measurement
        .metrics
        .as_ref()
        .is_some_and(|metrics| !valid_file_metrics(metrics))
    {
        return Err(ApiError::bad_request());
    }
    let eligible = eligible_measurement(measurement);
    if complete && eligible && measurement.status != MeasurementStatus::Complete {
        return Err(ApiError::bad_request());
    }
    if measurement.status != MeasurementStatus::Complete || !eligible {
        return Ok(());
    }
    let metrics = measurement
        .metrics
        .as_ref()
        .ok_or_else(ApiError::bad_request)?;
    let file = files
        .get(measurement.path.as_path())
        .ok_or_else(ApiError::bad_request)?;
    if file.metrics != *metrics {
        return Err(ApiError::bad_request());
    }
    if measurement.classification == FileClassification::Source {
        totals.files += 1;
        totals.lines += u64::from(metrics.lines);
        totals.code_lines += u64::from(metrics.code_lines);
        totals.comment_lines += u64::from(metrics.comment_lines);
    }
    Ok(())
}

fn validate_report_consistency(report: &AnalysisReport) -> Result<(), ApiError> {
    if report.project.complete && !report.project.warnings.is_empty() {
        return Err(ApiError::bad_request());
    }
    let mut files = BTreeMap::new();
    for file in &report.files {
        if !valid_file_metrics(&file.metrics) || files.insert(file.path.as_path(), file).is_some() {
            return Err(ApiError::bad_request());
        }
    }
    let mut paths = BTreeMap::new();
    let mut totals = hoonarqube_ir::ProjectMetrics {
        files: 0,
        lines: 0,
        code_lines: 0,
        comment_lines: 0,
    };
    for measurement in &report.project.files {
        if paths
            .insert(measurement.path.as_path(), measurement)
            .is_some()
        {
            return Err(ApiError::bad_request());
        }
        validate_scope_measurement(measurement, report.project.complete, &files, &mut totals)?;
    }
    if files.keys().any(|path| {
        !paths
            .get(path)
            .is_some_and(|measurement| retained_report_measurement(measurement))
    }) || totals != report.project.metrics
    {
        return Err(ApiError::bad_request());
    }
    Ok(())
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
            validate_message(issue_object.get("message").and_then(Value::as_str))?;
        }
    }
    if let Some(assessment) = object.get("assessment") {
        validate_assessment(assessment)?;
    }
    Ok(())
}
fn validate_assessment(assessment: &Value) -> Result<(), ApiError> {
    let object = assessment.as_object().ok_or_else(ApiError::bad_request)?;
    if object.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(ASSESSMENT_SCHEMA_VERSION))
    {
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
fn config_for_gate(gate: &GateReport) -> GateConfig {
    GateConfig {
        schema_version: GATE_CONFIG_SCHEMA_VERSION,
        conditions: gate
            .conditions
            .iter()
            .map(|condition| GateCondition {
                scope: condition.scope,
                metric: condition.metric.clone(),
                operator: condition.operator,
                threshold: condition.threshold,
                precision: condition.precision,
                small_change_policy: condition.small_change_policy,
            })
            .collect(),
    }
}

fn validate_gate_claim_against_report(
    gate: Option<&GateReport>,
    report: &AnalysisReport,
) -> Result<(), ApiError> {
    let Some(gate) = gate else {
        return Ok(());
    };
    gate.validate().map_err(|_| ApiError::conflict())?;
    let config = config_for_gate(gate);
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
                    || expected.precision != claimed.precision
                    || expected.ignored_on_small_change != claimed.ignored_on_small_change
                    || expected.small_change_policy != claimed.small_change_policy
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
        let status = condition.get("status").and_then(Value::as_str);
        let no_value = status == Some("no_value")
            && condition.get("scope").and_then(Value::as_str) == Some("new_code")
            && (matches!(
                condition.get("metric").and_then(Value::as_str),
                Some("security_hotspots_reviewed" | "community_26_9_security_hotspots_reviewed")
            ) || condition.get("small_change_policy").and_then(Value::as_str)
                == Some("community20"))
            && condition.get("actual").is_some_and(Value::is_null);
        if !no_value
            && (status != Some("pass") || condition.get("actual").is_none_or(Value::is_null))
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

fn finding_key_counts(
    report: &AnalysisReport,
) -> Result<BTreeMap<FindingLocation, usize>, ApiError> {
    let mut keys = BTreeMap::new();
    for file in &report.files {
        let path = path_string(&file.path)?;
        for issue in &file.issues {
            let key = finding_key(&path, &file.language, issue);
            *keys
                .entry((key, issue.range.start, issue.range.end))
                .or_default() += 1;
        }
    }
    Ok(keys)
}

fn append_file_findings(
    file: &FileReport,
    accumulator: &mut FindingAccumulator<'_>,
) -> Result<(), ApiError> {
    let path = path_string(&file.path)?;
    // The report preserves the spelling supplied to the CLI; assessment identities
    // use the IR's normalized spelling even for a scan rooted at ".".
    let assessment_path = hoonarqube_ir::assessment::normalize_path(&file.path)
        .map_err(|_| ApiError::bad_request())?;
    let assessment_path = assessment_path.to_str().ok_or_else(ApiError::bad_request)?;
    for (issue_index, issue) in file.issues.iter().enumerate() {
        append_finding(
            &path,
            assessment_path,
            &file.language,
            issue_index,
            issue,
            accumulator,
        )?;
    }
    Ok(())
}

fn append_finding(
    path: &str,
    assessment_path: &str,
    language: &str,
    issue_index: usize,
    issue: &Issue,
    accumulator: &mut FindingAccumulator<'_>,
) -> Result<(), ApiError> {
    let key = finding_key(path, language, issue);
    let fallback_identity = format!("sha256:{}", hash_bytes(key.as_bytes()));
    // The fallback identity remains stable for legacy reports. Claims also bind
    // the source occurrence, so only the same location is a duplicate here.
    let duplicate = accumulator
        .keys
        .get(&(key, issue.range.start, issue.range.end))
        .copied()
        .unwrap_or_default()
        > 1;
    let kind = issue_kind(issue)?;
    let (identity, claimed, claim_present) = {
        let claim = accumulator
            .claims
            .get(&(assessment_path.to_owned(), issue_index));
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
            .insert((assessment_path.to_owned(), issue_index));
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
    match is_security_hotspot(&issue.rule_key) {
        Some(true) => Ok(FindingKind::Hotspot),
        Some(false) => Ok(FindingKind::Finding),
        None => Err(ApiError::bad_request()),
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
    store::policy::validate_backup(&backup)?;
    let mut derived = validate_restore_analyses(project, &backup.analyses, limits)?;
    validate_restore_findings(&backup.findings, &mut derived)?;
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
    if !matches!(backup.schema_version, 1 | 2)
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
    derived: &mut HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> Result<(), ApiError> {
    let actual = actual_restore_findings(findings, derived)?;
    if expected_restore_findings(derived) == actual {
        return Ok(());
    }
    // Older services marked every repeated message in a file ambiguous, even
    // with distinct locations and scanner identities. Preserve that stricter
    // result for each legacy analysis, including its review-history checks.
    for (id, (_, rows)) in derived.iter_mut() {
        let needs_legacy = rows
            .iter()
            .any(|f| !f.ambiguous && actual.contains_key(&restore_finding_key(*id, f, true)));
        if needs_legacy {
            let mut seen = BTreeSet::new();
            let mut duplicates = BTreeSet::new();
            for f in rows.iter() {
                let key = (&f.path, &f.rule_key, &f.message);
                if !seen.insert(key) {
                    duplicates.insert((f.path.clone(), f.rule_key.clone(), f.message.clone()));
                }
            }
            for f in rows {
                f.ambiguous |=
                    duplicates.contains(&(f.path.clone(), f.rule_key.clone(), f.message.clone()));
            }
        }
    }
    if expected_restore_findings(derived) != actual {
        return Err(ApiError::conflict());
    }
    Ok(())
}

fn restore_finding_key(id: i64, f: &FindingRecordInput, ambiguous: bool) -> (i64, String) {
    finding_backup_key(&FindingBackupKeyInput {
        analysis_id: id,
        identity: &f.identity,
        occurrence: f.occurrence,
        kind: f.kind,
        path: &f.path,
        rule_key: &f.rule_key,
        message: &f.message,
        range_json: &f.range_json,
        ambiguous,
    })
}

fn expected_restore_findings(
    derived: &HashMap<i64, (String, Vec<FindingRecordInput>)>,
) -> HashMap<(i64, String), usize> {
    let mut expected = HashMap::<(i64, String), usize>::new();
    for (analysis_id, (_, findings)) in derived {
        for finding in findings {
            let key = restore_finding_key(*analysis_id, finding, finding.ambiguous);
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
        validate_message(Some(&finding.message))?;
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
        if !history_chain_matches(entries.values().copied(), review.state)
            || !entries
                .last_key_value()
                .is_some_and(|(_, latest)| review_matches_history(review, latest))
        {
            return Err(ApiError::conflict());
        }
    }
    Ok(())
}

// A live review and its latest audit entry are written in one transaction.
// Restoration must preserve that invariant instead of importing two different
// accounts of who reviewed which analysis, when, and for what reason.
fn review_matches_history(review: &BackupReview, latest: &BackupHistory) -> bool {
    (
        review.analysis_id,
        review.version,
        review.state,
        &review.updated_by,
        &review.updated_at,
        &review.reason,
    ) == (
        latest.analysis_id,
        latest.version,
        latest.new_state,
        &latest.actor,
        &latest.created_at,
        &latest.reason,
    )
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

fn validate_message(value: Option<&str>) -> Result<(), ApiError> {
    let value = value.ok_or_else(ApiError::bad_request)?;
    if value.is_empty()
        || value.len() > MAX_MESSAGE_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::bad_request());
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.as_bytes().contains(&0)
        || path.contains('\\')
        || path.contains(':')
    {
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

fn analysis_content_hash(branch: &str, commit: &str, timestamp: &str, report: &str) -> String {
    hash_bytes(format!("{branch}\n{commit}\n{timestamp}\n{report}").as_bytes())
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
    fn duplicate_bearer_tokens_are_rejected_without_exposing_the_token() {
        let result = AuthConfig::new(vec![
            Credential::new(
                "reader",
                "shared-secret",
                [("demo".to_string(), Role::Reader)],
            ),
            Credential::new(
                "admin",
                "shared-secret",
                [("demo".to_string(), Role::Admin)],
            ),
        ]);
        let Err(error) = result else {
            panic!("one bearer token must identify exactly one principal");
        };
        assert_eq!(
            error.to_string(),
            "configuration error: credential token must be unique"
        );
        assert!(!error.to_string().contains("shared-secret"));
    }

    #[test]
    fn distinct_bearer_tokens_preserve_each_principals_authority() {
        let auth = AuthConfig::new(vec![
            Credential::new(
                "reader",
                "reader-secret",
                [("demo".to_string(), Role::Reader)],
            ),
            Credential::new("admin", "admin-secret", [("demo".to_string(), Role::Admin)]),
        ])
        .expect("distinct credentials");
        let reader = auth.authenticate("reader-secret").expect("reader token");
        assert_eq!(reader.user_id, "reader");
        assert!(reader.permits("demo", Role::Reader));
        assert!(!reader.permits("demo", Role::Admin));
        let admin = auth.authenticate("admin-secret").expect("admin token");
        assert_eq!(admin.user_id, "admin");
        assert!(admin.permits("demo", Role::Admin));
        assert!(auth.authenticate("unknown-secret").is_none());
    }

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
            parity: None,
        };
        let findings = extract_findings(&report, None).expect("findings");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.ambiguous));
        assert_eq!(findings[0].identity, findings[1].identity);
    }

    #[test]
    fn claimed_occurrences_need_both_unique_locations_and_unique_identities() {
        let mut report: AnalysisReport = serde_json::from_str(reviewable_report()).unwrap();
        let first = report.files[0].issues[0].clone();
        let mut second = first.clone();
        second.range.start.line += 1;
        second.range.end.line += 1;
        report.files[0].issues.push(second);
        let mut claims = json!({"sources":[{"path":"a.py","findings":[
            {"issue_index":0,"identity":"a".repeat(64)},
            {"issue_index":1,"identity":"b".repeat(64)}
        ]}]});
        let extract = |report: &AnalysisReport, claims: &Value| {
            extract_findings(report, Some(claims))
                .unwrap()
                .into_iter()
                .map(|f| f.ambiguous)
                .collect::<Vec<_>>()
        };
        assert_eq!(extract(&report, &claims), [false, false]);
        claims["sources"][0]["findings"][1]["identity"] = json!("a".repeat(64));
        assert_eq!(extract(&report, &claims), [true, true]);
        claims["sources"][0]["findings"][1]["identity"] = json!("b".repeat(64));
        report.files[0].issues[1] = first;
        assert_eq!(extract(&report, &claims), [true, true]);
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

    async fn spawn_test_service() -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
        let service = Service::open(&database_path, auth).expect("test database");
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
        (address, server)
    }

    fn scope_report(classification: &str, status: &str, complete: bool, path: &str) -> Value {
        json!({
            "schema_version": 1,
            "files": [],
            "project": {
                "metrics": {"files": 0, "lines": 0, "code_lines": 0, "comment_lines": 0},
                "files": [{"path": path, "classification": classification, "status": status,
                           "metrics": null, "duplication": null, "reason": "fixture"}],
                "duplications": [], "duplication": null, "complete": complete,
                "warnings": [], "roots": ["."]
            }
        })
    }

    async fn ingest_report(address: SocketAddr, commit: &str, report: Value) -> RawHttpResponse {
        let body = json!({"schema_version": 1, "branch": "main", "commit": commit,
                          "analyzed_at": "2026-10-07T08:00:00Z", "report": report});
        api_request(
            address,
            "POST",
            "/api/v1/projects/demo/analyses",
            Some("application/json"),
            &body.to_string(),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_rejects_complete_claim_for_failed_source_or_test() {
        let (address, server) = spawn_test_service().await;
        let baseline = ingest_report(
            address,
            "baseline",
            scope_report("excluded", "excluded", true, "excluded.py"),
        )
        .await;
        assert_eq!(baseline.status, 200);
        for classification in ["source", "test"] {
            for status in ["failed", "unsupported", "excluded"] {
                let response = ingest_report(
                    address,
                    &format!("{classification}-{status}"),
                    scope_report(classification, status, true, "failed.py"),
                )
                .await;
                assert_api_error(&response, 400, "invalid_request");
            }
        }
        let stored = api_request(address, "GET", "/api/v1/projects/demo/analyses", None, "").await;
        assert_eq!(
            json_body(&stored)["analyses"]
                .as_array()
                .expect("analyses")
                .len(),
            1
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_preserves_incomplete_and_excluded_scope_controls() {
        let (address, server) = spawn_test_service().await;
        for classification in ["source", "test"] {
            for status in ["failed", "unsupported"] {
                let response = ingest_report(
                    address,
                    &format!("{classification}-{status}"),
                    scope_report(classification, status, false, "failed.py"),
                )
                .await;
                assert_eq!(response.status, 200);
                assert_eq!(json_body(&response)["analysis"]["complete"], false);
            }
        }
        for classification in ["generated", "vendor", "excluded"] {
            let response = ingest_report(
                address,
                &format!("{classification}-excluded"),
                scope_report(classification, "excluded", true, "excluded.py"),
            )
            .await;
            assert_eq!(response.status, 200);
        }
        for classification in ["generated", "vendor", "excluded"] {
            let response = ingest_report(
                address,
                &format!("{classification}-unsupported"),
                scope_report(classification, "unsupported", true, "unmeasured.py"),
            )
            .await;
            assert_eq!(response.status, 200);
        }
        server.abort();
        let _ = server.await;
    }

    fn measured_scope_report() -> Value {
        json!({"schema_version": 1,
            "files": [
                {"path": "a.py", "language": "python", "issues": [],
                 "metrics": {"lines": 2, "code_lines": 1, "comment_lines": 1}},
                {"path": "test_a.py", "language": "python", "issues": [],
                 "metrics": {"lines": 4, "code_lines": 3, "comment_lines": 2}}
            ],
            "project": {
                "metrics": {"files": 1, "lines": 2, "code_lines": 1, "comment_lines": 1},
                "files": [
                    {"path": "a.py", "classification": "source", "status": "complete",
                     "metrics": {"lines": 2, "code_lines": 1, "comment_lines": 1},
                     "duplication": null, "reason": "excluded from duplication"},
                    {"path": "test_a.py", "classification": "test", "status": "complete",
                     "metrics": {"lines": 4, "code_lines": 3, "comment_lines": 2},
                     "duplication": null, "reason": null},
                    {"path": "vendor", "classification": "vendor", "status": "excluded",
                     "metrics": null, "duplication": null, "reason": "excluded"}
                ],
                "duplications": [], "duplication": null, "complete": true,
                "warnings": [], "roots": ["."]
            }
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_rejects_inconsistent_native_report_inventory_and_metrics() {
        let (address, server) = spawn_test_service().await;
        let baseline = ingest_report(address, "baseline", measured_scope_report()).await;
        assert_eq!(baseline.status, 200);
        for mutation in [
            "totals",
            "warnings",
            "null_metrics",
            "duplicate_inventory",
            "missing_report",
            "invalid_file_metrics",
            "mismatched_file_metrics",
            "duplicate_report",
            "orphan_report",
        ] {
            let mut report = measured_scope_report();
            match mutation {
                "totals" => report["project"]["metrics"]["lines"] = json!(0),
                "warnings" => report["project"]["warnings"] = json!(["incomplete scan"]),
                "null_metrics" => report["project"]["files"][0]["metrics"] = Value::Null,
                "duplicate_inventory" => {
                    let duplicate = report["project"]["files"][0].clone();
                    report["project"]["files"]
                        .as_array_mut()
                        .expect("inventory")
                        .push(duplicate);
                }
                "missing_report" => {
                    report["files"].as_array_mut().expect("files").remove(0);
                }
                "invalid_file_metrics" => report["files"][0]["metrics"]["code_lines"] = json!(99),
                "mismatched_file_metrics" => report["files"][0]["metrics"]["lines"] = json!(3),
                "duplicate_report" => {
                    let duplicate = report["files"][0].clone();
                    report["files"]
                        .as_array_mut()
                        .expect("files")
                        .push(duplicate);
                }
                "orphan_report" => report["files"][0]["path"] = json!("orphan.py"),
                _ => unreachable!(),
            }
            let response = ingest_report(address, mutation, report).await;
            assert_api_error(&response, 400, "invalid_request");
        }
        let mut partial = measured_scope_report();
        partial["project"]["complete"] = json!(false);
        partial["project"]["warnings"] = json!(["test failed"]);
        partial["project"]["files"][1]["status"] = json!("failed");
        partial["project"]["files"][1]["metrics"] = Value::Null;
        let partial = ingest_report(address, "partial-with-retained-report", partial).await;
        assert_eq!(partial.status, 200);
        assert_eq!(json_body(&partial)["analysis"]["complete"], false);
        let stored = api_request(address, "GET", "/api/v1/projects/demo/analyses", None, "").await;
        assert_eq!(
            json_body(&stored)["analyses"]
                .as_array()
                .expect("analyses")
                .len(),
            2
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_accepts_native_complete_and_incomplete_reports() {
        let (address, server) = spawn_test_service().await;
        let options = hoonarqube_core::AnalyzerOptions::default();
        for incomplete in [false, true] {
            let mut inputs = vec![
                hoonarqube_core::analyze_project_file(
                    FsPath::new("a.py"),
                    "x = 1 # inline\n",
                    &options,
                    FileClassification::Source,
                    true,
                ),
                hoonarqube_core::analyze_project_file(
                    FsPath::new("test_a.py"),
                    "assert True\n",
                    &options,
                    FileClassification::Test,
                    false,
                ),
                hoonarqube_core::analyze_project_file(
                    FsPath::new("vendor"),
                    "",
                    &options,
                    FileClassification::Vendor,
                    false,
                ),
            ];
            if incomplete {
                inputs.push(hoonarqube_core::analyze_project_file(
                    FsPath::new("broken.py"),
                    "x =\n",
                    &options,
                    FileClassification::Source,
                    false,
                ));
            }
            let report = hoonarqube_core::build_project_report(
                inputs,
                vec![PathBuf::from(".")],
                Vec::new(),
                &hoonarqube_core::DuplicationOptions::default(),
            )
            .expect("native project report");
            assert_eq!(report.project.complete, !incomplete);
            let report_json = serde_json::to_value(report).expect("native report JSON");
            let response = ingest_report(
                address,
                if incomplete {
                    "native-incomplete"
                } else {
                    "native-complete"
                },
                report_json.clone(),
            )
            .await;
            assert_eq!(response.status, 200);
            assert_eq!(json_body(&response)["analysis"]["complete"], !incomplete);
            let id = json_body(&response)["analysis"]["id"]
                .as_i64()
                .expect("analysis id");
            let stored = api_request(
                address,
                "GET",
                &format!("/api/v1/projects/demo/analyses/{id}"),
                None,
                "",
            )
            .await;
            assert_eq!(json_body(&stored)["analysis"]["report"], report_json);
            if incomplete {
                let mut nul_message = report_json.clone();
                nul_message["files"][1]["issues"][0]["message"] = json!("bad\0message");
                let refused = ingest_report(address, "nul-message", nul_message).await;
                assert_api_error(&refused, 400, "invalid_request");
                let exported =
                    api_request(address, "GET", "/api/v1/projects/demo/export", None, "").await;
                let (destination, destination_server) = spawn_test_service().await;
                let restored = api_request(
                    destination,
                    "POST",
                    "/api/v1/projects/demo/restore",
                    Some("application/json"),
                    &String::from_utf8(exported.body).expect("backup JSON"),
                )
                .await;
                assert_eq!(restored.status, 200);
                destination_server.abort();
                let _ = destination_server.await;
            }
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_restore_rejects_inconsistent_report_before_creating_project() {
        let (source, source_server) = spawn_test_service().await;
        let ingested = ingest_report(source, "baseline", measured_scope_report()).await;
        assert_eq!(ingested.status, 200);
        let exported = api_request(source, "GET", "/api/v1/projects/demo/export", None, "").await;
        assert_eq!(exported.status, 200);
        let clean = json_body(&exported);
        let (destination, destination_server) = spawn_test_service().await;
        for mutation in ["warnings", "nul", "failed_source"] {
            let mut corrupted = clean.clone();
            let report = &mut corrupted["analyses"][0]["report"];
            match mutation {
                "warnings" => report["project"]["warnings"] = json!(["incomplete scan"]),
                "nul" => report["project"]["roots"] = json!(["bad\0.py"]),
                "failed_source" => report["project"]["files"][0]["status"] = json!("failed"),
                _ => unreachable!(),
            }
            let analysis = &mut corrupted["analyses"][0];
            analysis["content_hash"] = json!(hash_bytes(
                format!(
                    "{}\n{}\n{}\n{}",
                    analysis["branch"].as_str().expect("branch"),
                    analysis["commit"].as_str().expect("commit"),
                    analysis["analyzed_at"].as_str().expect("timestamp"),
                    serde_json::to_string(&analysis["report"]).expect("report JSON")
                )
                .as_bytes()
            ));
            let response = api_request(
                destination,
                "POST",
                "/api/v1/projects/demo/restore",
                Some("application/json"),
                &corrupted.to_string(),
            )
            .await;
            assert_api_error(&response, 400, "invalid_request");
            let projects = api_request(destination, "GET", "/api/v1/projects", None, "").await;
            assert!(
                json_body(&projects)["projects"]
                    .as_array()
                    .expect("projects")
                    .is_empty()
            );
        }
        let restored = api_request(
            destination,
            "POST",
            "/api/v1/projects/demo/restore",
            Some("application/json"),
            &clean.to_string(),
        )
        .await;
        assert_eq!(restored.status, 200);
        source_server.abort();
        let _ = source_server.await;
        destination_server.abort();
        let _ = destination_server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_rejects_nul_paths_without_mutating_store() {
        let (address, server) = spawn_test_service().await;
        let baseline = ingest_report(
            address,
            "baseline",
            scope_report("excluded", "excluded", true, "normal name.py"),
        )
        .await;
        assert_eq!(baseline.status, 200);
        for target in ["inventory", "file", "root", "duplication"] {
            let mut report = scope_report("excluded", "excluded", true, "normal.py");
            match target {
                "inventory" => report["project"]["files"][0]["path"] = json!("bad\0.py"),
                "root" => report["project"]["roots"] = json!(["bad\0.py"]),
                "file" => {
                    report["files"] = json!([{"path": "bad\0.py", "language": "python",
                    "issues": [], "metrics": {"lines": 0, "code_lines": 0, "comment_lines": 0}}]);
                }
                "duplication" => {
                    report["project"]["duplications"] = json!([{
                    "language": "python", "occurrences": [{"path": "bad\0.py", "start_line": 1,
                    "end_line": 1, "start_byte": 0, "end_byte": 1}]}]);
                }
                _ => unreachable!(),
            }
            let response = ingest_report(address, target, report).await;
            assert_api_error(&response, 400, "invalid_request");
        }
        let stored = api_request(address, "GET", "/api/v1/projects/demo/analyses", None, "").await;
        assert_eq!(
            json_body(&stored)["analyses"]
                .as_array()
                .expect("analyses")
                .len(),
            1
        );
        server.abort();
        let _ = server.await;
    }

    fn json_body(response: &RawHttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("JSON response body")
    }

    fn reviewable_report() -> &'static str {
        r#"{"schema_version":1,"files":[{"path":"a.py","language":"python","issues":[{"rule_key":"python:S1134","message":"Take the required action to fix the issue indicated by this \"FIXME\" comment.","range":{"start":{"line":1,"column":0},"end":{"line":1,"column":20}}}],"metrics":{"lines":2,"code_lines":1,"comment_lines":1}}],"project":{"metrics":{"files":1,"lines":2,"code_lines":1,"comment_lines":1},"files":[{"path":"a.py","classification":"source","status":"complete","metrics":{"lines":2,"code_lines":1,"comment_lines":1},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null}],"duplications":[],"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"complete":true,"warnings":[],"roots":["a.py"]},"assessment":{"schema_version":3,"context":{"analyzer_version":"hoonarqube-cli/0.8.2","catalog_digest":"d9ce2a1a13961a57f4dede498924fd3518312e8de5a4a5bc671952c73c158a84","options_digest":"471a1bbba734ab8a2da6fa62d0d84d5dd967dd2e1476565c78de6881b54b48d1","scope_digest":"dc756006f7d7366908f4cff666986e61f0fbd42c39b18381e745422035d69e36"},"sources":[{"path":"a.py","content_digest":"f89600824c3f62a48dcc441d730d7d43f1923b7b37bccb3a0536d109c1199764","line_digests":["1dd36e4257b84fc35cfcaca20a29fcbbd61530714fcbde191251b7d679dd9a44","e09e09453d48049c48cadbc630a121ed1b033498846be9aba19eafb8ab73f917"],"findings":[{"issue_index":0,"rule_key":"python:S1134","message":"Take the required action to fix the issue indicated by this \"FIXME\" comment.","source_digest":"2837a0fd9c3732d35586b5be9794e0511049637f586fba20edb81d67b7d237f8","context_digest":"c2d980f6467c3167454753db29f2986ca82af25bd310de58bb297175584b3e30","start_line":1,"end_line":1,"occurrence":0,"content_identity":"7adf5f8ba5eb9ee66cc0e57217b0cf038955673f8f2156e35d664e146042a5ce","identity":"506e1fcd2d2ab0df6909a6d7df84a4c48c623b893175bf1251c636ce01ff2e8b","ambiguous":false,"path":"a.py"}]}]}}"#
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_ingest_recomputes_overall_line_coverage_at_the_declared_precision() {
        use hoonarqube_ir::assessment::{AnalysisContext, AssessmentReport, SourceInput};
        let (address, server) = spawn_test_service().await;
        let mut report = measured_scope_report();
        let parsed: AnalysisReport = serde_json::from_value(report.clone()).unwrap();
        let assessment = AssessmentReport::from_reports_and_source_inputs(
            AnalysisContext::new("test", "catalog", "options", "scope", None::<String>),
            &parsed.files,
            &[
                SourceInput::new(FsPath::new("a.py"), b"# header\nx=1\n"),
                SourceInput::new(
                    FsPath::new("test_a.py"),
                    b"# header\nx=1\ny=2\nassert x != y\n",
                ),
            ],
        )
        .unwrap();
        report["assessment"] = serde_json::to_value(assessment).unwrap();
        report["assessment"]["coverage"] = json!({
            "schema_version": ASSESSMENT_SCHEMA_VERSION, "status":"complete", "inputs":[], "diagnostics":[],
            "files":[{"path":"a.py","lines":[{"line":1,"covered":true},{"line":2,"covered":true}]},
                     {"path":"test_a.py","lines":[{"line":4,"covered":false}]}],
            "lines":{"covered":2,"eligible":3}, "branches":{"covered":0,"eligible":0}
        });
        report["assessment"]["gate"] = json!({
            "schema_version": ASSESSMENT_SCHEMA_VERSION, "status":"pass", "diagnostics":[],
            "conditions":[{"scope":"overall","metric":"line_coverage","operator":"gte","threshold":66.7,
                           "precision":"one_decimal","actual":66.7,"status":"pass"}]
        });
        let accepted = ingest_report(address, "rounded", report.clone()).await;
        assert_eq!(accepted.status, 200);
        let stored = &json_body(&accepted)["analysis"]["gate"]["conditions"][0];
        assert_eq!(stored["precision"], "one_decimal");
        assert_eq!(stored["actual"], 66.7);

        let mut forged = report.clone();
        forged["assessment"]["gate"]["conditions"][0]["actual"] = json!(66.8);
        assert_api_error(
            &ingest_report(address, "wrong-actual", forged).await,
            409,
            "conflict",
        );
        let mut forged = report.clone();
        forged["assessment"]["gate"]["conditions"][0]
            .as_object_mut()
            .unwrap()
            .remove("precision");
        assert_api_error(
            &ingest_report(address, "missing-precision", forged).await,
            409,
            "conflict",
        );
        let mut forged = report.clone();
        forged["assessment"]["gate"]["conditions"][0]["metric"] = json!("branch_coverage");
        assert_api_error(
            &ingest_report(address, "wrong-metric", forged).await,
            400,
            "invalid_request",
        );
        report["assessment"]
            .as_object_mut()
            .unwrap()
            .remove("coverage");
        assert_api_error(
            &ingest_report(address, "missing-coverage", report).await,
            409,
            "conflict",
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_duplication_density_survives_ingest_read_and_restore() {
        const DENSITY: &str = "9.586466165413533";
        let (source, source_server) = spawn_test_service().await;
        let (destination, destination_server) = spawn_test_service().await;
        let report = reviewable_report().replace(
            r#""duplicated_lines_density":0.0"#,
            &format!(r#""duplicated_lines_density":{DENSITY}"#),
        );
        let envelope = format!(
            r#"{{"schema_version":1,"branch":"main","commit":"precision","analyzed_at":"2026-11-20T12:00:00Z","report":{report}}}"#
        );
        let analyses = "/api/v1/projects/demo/analyses";
        let created = api_request(
            source,
            "POST",
            analyses,
            Some("application/json"),
            &envelope,
        )
        .await;
        assert_eq!(created.status, 200);
        let id = json_body(&created)["analysis"]["id"].as_i64().unwrap();
        let detail = format!("{analyses}/{id}");
        let response = api_request(source, "GET", &detail, None, "").await;
        assert_eq!(response.status, 200);
        assert_eq!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .matches(DENSITY)
                .count(),
            3,
            "summary, project and file density must preserve the input f64"
        );
        let exported = api_request(source, "GET", "/api/v1/projects/demo/export", None, "").await;
        assert_eq!(exported.status, 200);
        let backup = std::str::from_utf8(&exported.body).unwrap();
        for expected_count in [1, 0] {
            let restored = api_request(
                destination,
                "POST",
                "/api/v1/projects/demo/restore",
                Some("application/json"),
                backup,
            )
            .await;
            assert_eq!(restored.status, 200);
            assert_eq!(json_body(&restored)["restore"]["analyses"], expected_count);
        }
        let replay = api_request(
            destination,
            "POST",
            analyses,
            Some("application/json"),
            &envelope,
        )
        .await;
        assert_eq!(replay.status, 200);
        assert_eq!(json_body(&replay)["idempotent"], true);
        let changed = envelope.replace(DENSITY, "9.586466165413531");
        let conflict = api_request(
            destination,
            "POST",
            analyses,
            Some("application/json"),
            &changed,
        )
        .await;
        assert_api_error(&conflict, 409, "conflict");
        source_server.abort();
        destination_server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn assigned_threshold_equal_to_measured_density_survives_restore() {
        // The legacy serde path rounds this decimal down by one ULP: equality would fail.
        let density = "9.586466165413533";
        let (source, source_server) = spawn_test_service().await;
        let (target, target_server) = spawn_test_service().await;
        let project = "/api/v1/projects/demo";
        let config = format!(
            r#"{{"schema_version":1,"expected_version":0,"config":{{"schema_version":1,"conditions":[{{"scope":"overall","metric":"duplicated_lines_density","operator":"eq","threshold":{density}}}]}}}}"#
        );
        let assigned = api_request(
            source,
            "PUT",
            &format!("{project}/gate-policy"),
            Some("application/json"),
            &config,
        )
        .await;
        assert_eq!(assigned.status, 200);
        let report = reviewable_report().replace(
            r#""duplicated_lines_density":0.0"#,
            &format!(r#""duplicated_lines_density":{density}"#),
        );
        let envelope = format!(
            r#"{{"schema_version":1,"branch":"main","commit":"policy-precision","analyzed_at":"2026-11-20T12:00:00Z","report":{report}}}"#
        );
        let created = api_request(
            source,
            "POST",
            &format!("{project}/analyses"),
            Some("application/json"),
            &envelope,
        )
        .await;
        assert_eq!(created.status, 200);
        let row = &json_body(&created)["analysis"];
        assert_eq!(row["gate"]["status"], "pass");
        let id = row["id"].as_i64().unwrap();
        let backup = api_request(source, "GET", &format!("{project}/export"), None, "").await;
        let data = std::str::from_utf8(&backup.body).unwrap();
        let restored = api_request(
            target,
            "POST",
            &format!("{project}/restore"),
            Some("application/json"),
            data,
        )
        .await;
        assert_eq!(restored.status, 200);
        for server in [source, target] {
            let gate = api_request(
                server,
                "GET",
                &format!("{project}/analyses/{id}/gate"),
                None,
                "",
            )
            .await;
            assert_eq!(gate.status, 200);
            assert_eq!(json_body(&gate)["status"], "pass");
            assert_eq!(
                std::str::from_utf8(&gate.body)
                    .unwrap()
                    .matches(density)
                    .count(),
                2
            );
        }
        source_server.abort();
        target_server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_legacy_backup_preserves_stored_density_and_accepts_original_replay() {
        const ORIGINAL: &str = "9.586466165413533";
        const LEGACY: &str = "9.586466165413531";
        let (source, source_server) = spawn_test_service().await;
        let (destination, destination_server) = spawn_test_service().await;
        let report = reviewable_report().replace(
            r#""duplicated_lines_density":0.0"#,
            &format!(r#""duplicated_lines_density":{LEGACY}"#),
        );
        let stored = format!(
            r#"{{"schema_version":1,"branch":"main","commit":"old","analyzed_at":"2026-11-20T12:00:00Z","report":{report}}}"#
        );
        let analyses = "/api/v1/projects/demo/analyses";
        let created =
            api_request(source, "POST", analyses, Some("application/json"), &stored).await;
        assert_eq!(created.status, 200);
        let exported = api_request(source, "GET", "/api/v1/projects/demo/export", None, "").await;
        assert_eq!(exported.status, 200);
        let export = String::from_utf8(exported.body).unwrap();
        assert!(export.contains(r#","exact_floats":true"#));
        let v1_backup = export.replace(r#","exact_floats":true"#, "");
        let restored = api_request(
            destination,
            "POST",
            "/api/v1/projects/demo/restore",
            Some("application/json"),
            &v1_backup,
        )
        .await;
        assert_eq!(restored.status, 200);
        let original = stored.replace(LEGACY, ORIGINAL);
        let replay = api_request(
            destination,
            "POST",
            analyses,
            Some("application/json"),
            &original,
        )
        .await;
        assert_eq!(replay.status, 200);
        assert_eq!(json_body(&replay)["idempotent"], true);
        let id = json_body(&replay)["analysis"]["id"].as_i64().unwrap();
        let response = api_request(destination, "GET", &format!("{analyses}/{id}"), None, "").await;
        assert_eq!(response.status, 200);
        let raw = std::str::from_utf8(&response.body).unwrap();
        assert_eq!(raw.matches(LEGACY).count(), 3);
        assert!(!raw.contains(ORIGINAL));
        // A real content change must still conflict with a legacy hash.
        let changed = original.replace(r#""roots":["a.py"]"#, r#""roots":["a.py","changed"]"#);
        assert_ne!(changed, original);
        let response = api_request(
            destination,
            "POST",
            analyses,
            Some("application/json"),
            &changed,
        )
        .await;
        assert_api_error(&response, 409, "conflict");
        source_server.abort();
        destination_server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_findings_pages_preserve_order_and_validate_cursors() {
        let (address, server) = spawn_test_service().await;
        let mut report: Value = serde_json::from_str(reviewable_report()).unwrap();
        report.as_object_mut().unwrap().remove("assessment");
        let issues = report["files"][0]["issues"].as_array_mut().unwrap();
        let item = issues[0].clone();
        issues.push(item.clone());
        for message in ["second", "third", "fourth"] {
            let mut finding = item.clone();
            finding["message"] = json!(message);
            issues.push(finding);
        }
        let mut empty_report = report.clone();
        empty_report["files"][0]["issues"] = json!([]);
        let response = ingest_report(address, "paginated", report).await;
        assert_eq!(response.status, 200);
        let id = json_body(&response)["analysis"]["id"].as_i64().unwrap();
        let path = format!("/api/v1/projects/demo/analyses/{id}/findings");
        let unpaginated = api_request(address, "GET", &path, None, "").await;
        assert_eq!(unpaginated.status, 200);
        let all = json_body(&unpaginated)["findings"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(all.len(), 5);

        let page_path = format!("{path}/page");
        let mut fetched = Vec::new();
        let mut query = String::new();
        for count in [2, 2, 1] {
            let response = api_request(
                address,
                "GET",
                &format!("{page_path}?limit=2{query}"),
                None,
                "",
            )
            .await;
            assert_eq!(response.status, 200);
            let page = json_body(&response);
            let items = page["findings"].as_array().unwrap();
            assert_eq!(items.len(), count);
            fetched.extend_from_slice(items);
            if count == 1 {
                assert!(page["next_cursor"].is_null());
            } else {
                query = format!("&cursor={}", page["next_cursor"].as_str().unwrap());
            }
        }
        assert_eq!(fetched, all);
        let default = api_request(address, "GET", &page_path, None, "").await;
        assert_eq!(default.status, 200);
        assert_eq!(
            json_body(&default),
            json!({"findings": all, "next_cursor": null})
        );

        let empty = ingest_report(address, "no-findings", empty_report).await;
        assert_eq!(empty.status, 200);
        let other_id = json_body(&empty)["analysis"]["id"].as_i64().unwrap();
        let empty_path = format!("/api/v1/projects/demo/analyses/{other_id}/findings/page");
        let response = api_request(address, "GET", &empty_path, None, "").await;
        assert_eq!(response.status, 200);
        assert_eq!(
            json_body(&response),
            json!({"findings": [], "next_cursor": null})
        );
        let foreign_cursor = format!("{empty_path}?limit=2{query}");
        let response = api_request(address, "GET", &foreign_cursor, None, "").await;
        assert_api_error(&response, 400, "invalid_request");

        for invalid in [
            "limit=0".to_owned(),
            "limit=501".to_owned(),
            "limit=-1".to_owned(),
            "limit=abc".to_owned(),
            "cursor=invalid".to_owned(),
            format!("cursor=v1.{id}.{}", i64::MAX),
        ] {
            let url = format!("{page_path}?{invalid}");
            let response = api_request(address, "GET", &url, None, "").await;
            assert_api_error(&response, 400, "invalid_request");
        }
        let forbidden = format!("/api/v1/projects/foreign/analyses/{id}/findings/page?limit=1");
        let response = api_request(address, "GET", &forbidden, None, "").await;
        assert_api_error(&response, 403, "forbidden");
        let nonexistent = format!("/api/v1/projects/demo/analyses/{}/findings/page", i64::MAX);
        let response = api_request(address, "GET", &nonexistent, None, "").await;
        assert_api_error(&response, 404, "not_found");
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn assessment_claims_follow_the_normalized_report_path() {
        let (address, server) = spawn_test_service().await;
        let mut report: Value = serde_json::from_str(reviewable_report()).unwrap();
        let claim = report["assessment"]["sources"][0]["findings"][0]["identity"]
            .as_str()
            .unwrap()
            .to_owned();
        for path in ["./a.py", "a.py", "../a.py", "other.py"] {
            report["files"][0]["path"] = json!(path);
            report["project"]["files"][0]["path"] = json!(path);
            let response =
                ingest_report(address, &format!("case-{}", path.len()), report.clone()).await;
            if path == "../a.py" || path == "other.py" {
                assert!(matches!(response.status, 400 | 409));
                continue;
            }
            assert_eq!(response.status, 200, "{path}");
            let id = json_body(&response)["analysis"]["id"].as_i64().unwrap();
            let list = api_request(
                address,
                "GET",
                &format!("/api/v1/projects/demo/analyses/{id}/findings"),
                None,
                "",
            )
            .await;
            assert_eq!(list.status, 200);
            let finding = &json_body(&list)["findings"][0];
            assert_eq!(finding["identity"], format!("sha256:{claim}"));
            assert_eq!(finding["ambiguous"], false);
            assert_eq!(finding["path"], path);
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn findings_only_inherit_reviews_from_the_same_branch_and_context() {
        let (address, server) = spawn_test_service().await;
        let (backup, _) = export_reviewed_backup(address).await;
        let expected = backup["reviews"][0]["identity"].clone();
        for (commit, branch, field, inherits) in [
            ("same", "main", "source_revision", true),
            ("alternate", "develop", "source_revision", false),
            ("analyzer", "main", "analyzer_version", false),
            ("catalog", "main", "catalog_digest", false),
            ("options", "main", "options_digest", false),
            ("scope", "main", "scope_digest", false),
        ] {
            let mut report: Value = serde_json::from_str(reviewable_report()).unwrap();
            report["assessment"]["context"][field] = if field == "source_revision" {
                json!(commit)
            } else {
                json!("a".repeat(64))
            };
            let input = json!({"schema_version":1,"branch":branch,"commit":commit,
                "analyzed_at":"2026-11-19T11:00:00Z","report":report});
            let ingested = api_request(
                address,
                "POST",
                "/api/v1/projects/demo/analyses",
                Some("application/json"),
                &input.to_string(),
            )
            .await;
            assert_eq!(ingested.status, 200, "{commit}");
            let id = json_body(&ingested)["analysis"]["id"].as_i64().unwrap();
            let result = api_request(
                address,
                "GET",
                &format!("/api/v1/projects/demo/analyses/{id}/findings"),
                None,
                "",
            )
            .await;
            assert_eq!(result.status, 200);
            let item = &json_body(&result)["findings"][0];
            assert_eq!(item["identity"], expected);
            assert_eq!(item.get("review").is_some(), inherits, "{commit}");
        }
        server.abort();
        let _ = server.await;
    }

    async fn export_reviewed_backup(source: SocketAddr) -> (Value, i64) {
        let report: Value = serde_json::from_str(reviewable_report()).expect("reviewable report");
        let ingested = ingest_report(source, "reviewed", report.clone()).await;
        assert_eq!(ingested.status, 200);
        let analysis_id = json_body(&ingested)["analysis"]["id"]
            .as_i64()
            .expect("analysis id");
        let second = ingest_report(source, "later", report).await;
        assert_eq!(second.status, 200);
        let second_id = json_body(&second)["analysis"]["id"]
            .as_i64()
            .expect("second id");
        let findings = api_request(
            source,
            "GET",
            &format!("/api/v1/projects/demo/analyses/{analysis_id}/findings"),
            None,
            "",
        )
        .await;
        let identity = json_body(&findings)["findings"][0]["identity"].clone();
        for (version, state) in [(0, "accepted"), (1, "open")] {
            let review = api_request(source, "POST", "/api/v1/projects/demo/reviews", Some("application/json"),
                &json!({"schema_version": 1, "analysis_id": analysis_id, "identity": identity,
                    "kind": "finding", "state": state, "reason": "reviewed", "expected_version": version}).to_string()).await;
            assert_eq!(review.status, 200);
        }
        let exported = api_request(source, "GET", "/api/v1/projects/demo/export", None, "").await;
        assert_eq!(exported.status, 200);
        (json_body(&exported), second_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_restore_binds_review_summary_to_latest_history() {
        let (source, source_server) = spawn_test_service().await;
        let (clean, second_id) = export_reviewed_backup(source).await;
        let (destination, destination_server) = spawn_test_service().await;
        for field in ["updated_by", "reason", "updated_at", "analysis_id"] {
            let mut corrupted = clean.clone();
            corrupted["reviews"][0][field] = match field {
                "updated_by" => json!("different-actor"),
                "reason" => json!("different-reason"),
                "updated_at" => json!("2026-09-21T10:00:00Z"),
                "analysis_id" => json!(second_id),
                _ => unreachable!(),
            };
            let restored = api_request(
                destination,
                "POST",
                "/api/v1/projects/demo/restore",
                Some("application/json"),
                &corrupted.to_string(),
            )
            .await;
            assert_api_error(&restored, 409, "conflict");
            let projects = api_request(destination, "GET", "/api/v1/projects", None, "").await;
            assert!(
                json_body(&projects)["projects"]
                    .as_array()
                    .expect("projects")
                    .is_empty()
            );
        }
        let restored = api_request(
            destination,
            "POST",
            "/api/v1/projects/demo/restore",
            Some("application/json"),
            &clean.to_string(),
        )
        .await;
        assert_eq!(restored.status, 200);
        let reviews = api_request(
            destination,
            "GET",
            "/api/v1/projects/demo/reviews",
            None,
            "",
        )
        .await;
        let review = json_body(&reviews)["reviews"][0].clone();
        assert_eq!(review["version"], 2);
        assert_eq!(review["state"], "open");
        assert_eq!(review["updated_by"], clean["reviews"][0]["updated_by"]);
        assert_eq!(review["reason"], clean["reviews"][0]["reason"]);
        assert_eq!(review["updated_at"], clean["reviews"][0]["updated_at"]);
        let replay = api_request(
            destination,
            "POST",
            "/api/v1/projects/demo/restore",
            Some("application/json"),
            &clean.to_string(),
        )
        .await;
        assert_eq!(replay.status, 200);
        for field in ["analyses", "findings", "reviews", "history"] {
            assert_eq!(json_body(&replay)["restore"][field], 0);
        }
        let history = api_request(
            destination,
            "GET",
            &format!("/api/v1/projects/demo/reviews/{}/history", review["id"]),
            None,
            "",
        )
        .await;
        assert_eq!(history.status, 200);
        assert_eq!(
            json_body(&history)["history"]
                .as_array()
                .expect("history")
                .len(),
            2
        );
        source_server.abort();
        let _ = source_server.await;
        destination_server.abort();
        let _ = destination_server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleted_project_rejects_idempotent_analysis_replay() {
        async fn ingest(address: SocketAddr, body: &str) -> RawHttpResponse {
            api_request(
                address,
                "POST",
                "/api/v1/projects/demo/analyses",
                Some("application/json"),
                body,
            )
            .await
        }
        let (address, server) = spawn_test_service().await;
        let payload = r#"{"schema_version":1,"branch":"main","commit":"c1","analyzed_at":"2026-09-20T10:00:00Z","report":{"schema_version":1,"files":[],"project":{"metrics":{"files":0,"lines":0,"code_lines":0,"comment_lines":0},"files":[],"duplications":[],"duplication":null,"complete":true,"warnings":[],"roots":["."]}}}"#;

        let first = ingest(address, payload).await;
        assert_eq!(first.status, 200);
        assert_eq!(json_body(&first)["idempotent"], false);

        let replay = ingest(address, payload).await;
        assert_eq!(replay.status, 200);
        assert_eq!(json_body(&replay)["idempotent"], true);

        let deleted = api_request(
            address,
            "DELETE",
            "/api/v1/projects/demo?reason=probe",
            None,
            "",
        )
        .await;
        assert_eq!(deleted.status, 204);

        let replay_after_delete = ingest(address, payload).await;
        assert_api_error(&replay_after_delete, 409, "conflict");

        let fresh_commit = ingest(
            address,
            &payload.replace("\"commit\":\"c1\"", "\"commit\":\"c2\""),
        )
        .await;
        assert_api_error(&fresh_commit, 409, "conflict");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retention_keeps_context_compatible_accepted_review_visible() {
        async fn ingest_analysis(
            address: SocketAddr,
            commit: &str,
            analyzed_at: &str,
            report: &str,
        ) -> RawHttpResponse {
            let body = format!(
                r#"{{"schema_version":1,"branch":"main","commit":"{commit}","analyzed_at":"{analyzed_at}","report":{report}}}"#
            );
            api_request(
                address,
                "POST",
                "/api/v1/projects/demo/analyses",
                Some("application/json"),
                &body,
            )
            .await
        }
        let (address, server) = spawn_test_service().await;
        let report = reviewable_report();
        let ingest = async |commit: &str, analyzed_at: &str| {
            ingest_analysis(address, commit, analyzed_at, report).await
        };
        let first = ingest("c1", "2026-09-20T10:00:00Z").await;
        assert_eq!(first.status, 200);
        let first_id = json_body(&first)["analysis"]["id"]
            .as_i64()
            .expect("first analysis id");
        let second = ingest("c2", "2026-09-20T12:00:00Z").await;
        assert_eq!(second.status, 200);
        let second_id = json_body(&second)["analysis"]["id"]
            .as_i64()
            .expect("second analysis id");

        let findings = api_request(
            address,
            "GET",
            &format!("/api/v1/projects/demo/analyses/{first_id}/findings"),
            None,
            "",
        )
        .await;
        assert_eq!(findings.status, 200);
        let identity = json_body(&findings)["findings"][0]["identity"]
            .as_str()
            .expect("finding identity")
            .to_string();

        let review = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/reviews",
            Some("application/json"),
            &format!(
                r#"{{"schema_version":1,"analysis_id":{first_id},"identity":"{identity}","kind":"finding","state":"accepted","reason":"reviewed","expected_version":0}}"#
            ),
        )
        .await;
        assert_eq!(review.status, 200);
        assert_eq!(json_body(&review)["review"]["state"], "accepted");

        let inherited_before = api_request(
            address,
            "GET",
            &format!("/api/v1/projects/demo/analyses/{second_id}/findings"),
            None,
            "",
        )
        .await;
        assert_eq!(inherited_before.status, 200);
        assert_eq!(
            json_body(&inherited_before)["findings"][0]["review"]["state"],
            "accepted"
        );

        let retention = api_request(
            address,
            "POST",
            "/api/v1/projects/demo/retention",
            Some("application/json"),
            r#"{"before":"2026-09-20T11:00:00Z","reason":"probe"}"#,
        )
        .await;
        assert_eq!(retention.status, 200);
        assert_eq!(json_body(&retention)["deleted"], 1);

        let inherited_after = api_request(
            address,
            "GET",
            &format!("/api/v1/projects/demo/analyses/{second_id}/findings"),
            None,
            "",
        )
        .await;
        assert_eq!(inherited_after.status, 200);
        assert_eq!(
            json_body(&inherited_after)["findings"][0]["review"]["state"],
            "accepted"
        );

        let reviews = api_request(address, "GET", "/api/v1/projects/demo/reviews", None, "").await;
        assert_eq!(reviews.status, 200);
        assert_eq!(json_body(&reviews)["reviews"][0]["state"], "accepted");

        server.abort();
        let _ = server.await;
    }
}
