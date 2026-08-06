//! HTTP surface (axum).
//!
//! Three POST endpoints take a signed Aqua tree as the request body, verbatim.
//! The body is extracted as a `String` rather than through a JSON extractor on
//! purpose: the registry stores exactly the bytes the publisher signed, and a
//! parse-then-reserialize round trip could reorder keys and change them.
//!
//! Everything else is a GET over the derived indexes. `GET /templates/{hash}`
//! returns the stored signed tree unchanged, so a consumer can re-verify it with
//! `aqua-rs-sdk-core` and never has to take this registry's word for anything.
//!
//! Errors are `{"error": {"code", "message"}}` with a stable `code`, so clients
//! branch on the code and not on prose.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;
use crate::model::RegistrationKind;
use crate::registry::Registry;
use crate::templates;

/// Shared handle every handler gets.
pub type SharedRegistry = Arc<Registry>;

/// Build the router.
pub fn router(registry: SharedRegistry) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/registration-templates", get(registration_templates))
        .route("/vendors", post(post_vendor).get(list_vendors))
        .route("/vendors/{vendor}", get(get_vendor))
        .route("/vendors/{vendor}/tree", get(get_vendor_tree))
        .route("/templates", post(post_template))
        .route("/templates/{hash}", get(get_template_tree))
        .route("/templates/{hash}/metadata", get(get_template_metadata))
        .route("/aliases", post(post_alias))
        .route("/publishers/{did}/vendors", get(get_publisher_vendors))
        .route("/publishers/{did}/templates", get(get_publisher_templates))
        .route("/publishers/{did}/aliases", get(get_publisher_aliases))
        .route("/publishers/{did}/feed", get(get_feed))
        .route("/resolve/{vendor}/{name}", get(get_resolve))
        .with_state(registry)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

struct ApiError(RegistryError);

impl From<RegistryError> for ApiError {
    fn from(e: RegistryError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.0.code(),
                message: self.0.to_string(),
            },
        };
        (status, Json(body)).into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

/// Respond with a stored JSON document verbatim, without re-serializing it.
fn raw_json(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Service metadata
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ServiceInfo {
    service: &'static str,
    version: &'static str,
    spec: &'static str,
    subscription: &'static str,
}

async fn index() -> Json<ServiceInfo> {
    Json(ServiceInfo {
        service: "aqua-template-registry",
        version: env!("CARGO_PKG_VERSION"),
        spec: "https://aqua-protocol.org (spec-type-registry.md, spec-module-ecosystem.md)",
        subscription: "poll GET /publishers/{did}/feed?since=<seq>",
    })
}

async fn health() -> &'static str {
    "ok"
}

async fn stats(State(reg): State<SharedRegistry>) -> Json<crate::model::Stats> {
    Json(reg.stats())
}

#[derive(Serialize)]
struct RegistrationTemplateInfo {
    kind: RegistrationKind,
    name: &'static str,
    template_hash: String,
    definition: serde_json::Value,
}

/// The three vendored registration template definitions and their hashes.
///
/// A publisher needs these hashes to build a registration tree, so the registry
/// publishes them rather than making every client vendor the files too.
async fn registration_templates() -> Json<Vec<RegistrationTemplateInfo>> {
    Json(
        templates::catalog()
            .iter()
            .map(|t| RegistrationTemplateInfo {
                kind: t.kind,
                name: t.name,
                template_hash: t.link.to_string(),
                definition: serde_json::from_str(t.json).expect("vendored template is valid JSON"),
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Submission
// ---------------------------------------------------------------------------

async fn post_vendor(
    State(reg): State<SharedRegistry>,
    body: String,
) -> ApiResult<(StatusCode, Json<crate::model::Receipt>)> {
    let receipt = reg.submit_vendor(&body).await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

async fn post_template(
    State(reg): State<SharedRegistry>,
    body: String,
) -> ApiResult<(StatusCode, Json<crate::model::Receipt>)> {
    let receipt = reg.submit_template(&body).await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

async fn post_alias(
    State(reg): State<SharedRegistry>,
    body: String,
) -> ApiResult<(StatusCode, Json<crate::model::Receipt>)> {
    let receipt = reg.submit_alias(&body).await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

// ---------------------------------------------------------------------------
// Vendors
// ---------------------------------------------------------------------------

async fn list_vendors(State(reg): State<SharedRegistry>) -> Json<Vec<crate::model::VendorRecord>> {
    Json(reg.vendors())
}

async fn get_vendor(
    State(reg): State<SharedRegistry>,
    Path(vendor): Path<String>,
) -> ApiResult<Json<crate::model::VendorRecord>> {
    Ok(Json(reg.vendor(&vendor)?))
}

async fn get_vendor_tree(
    State(reg): State<SharedRegistry>,
    Path(vendor): Path<String>,
) -> ApiResult<Response> {
    let record = reg.vendor(&vendor)?;
    Ok(raw_json(reg.tree_by_tip(&record.tree_tip)?))
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// The full signed registration tree, exactly as the publisher submitted it.
async fn get_template_tree(
    State(reg): State<SharedRegistry>,
    Path(hash): Path<String>,
) -> ApiResult<Response> {
    Ok(raw_json(reg.template_tree(&hash)?))
}

async fn get_template_metadata(
    State(reg): State<SharedRegistry>,
    Path(hash): Path<String>,
) -> ApiResult<Json<crate::model::TemplateRecord>> {
    Ok(Json(reg.template(&hash)?))
}

// ---------------------------------------------------------------------------
// Publishers
// ---------------------------------------------------------------------------

async fn get_publisher_vendors(
    State(reg): State<SharedRegistry>,
    Path(did): Path<String>,
) -> Json<Vec<crate::model::VendorRecord>> {
    Json(reg.publisher_vendors(&did))
}

async fn get_publisher_templates(
    State(reg): State<SharedRegistry>,
    Path(did): Path<String>,
) -> Json<Vec<crate::model::TemplateRecord>> {
    Json(reg.publisher_templates(&did))
}

async fn get_publisher_aliases(
    State(reg): State<SharedRegistry>,
    Path(did): Path<String>,
) -> Json<Vec<crate::model::AliasRecord>> {
    Json(reg.publisher_aliases(&did))
}

#[derive(Deserialize)]
struct FeedQuery {
    #[serde(default)]
    since: u64,
    limit: Option<usize>,
}

/// The subscription endpoint. Poll it with the `next` cursor from the previous
/// response to receive every registration this publisher makes, in order.
async fn get_feed(
    State(reg): State<SharedRegistry>,
    Path(did): Path<String>,
    Query(q): Query<FeedQuery>,
) -> Json<crate::model::FeedPage> {
    Json(reg.feed(&did, q.since, q.limit))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

async fn get_resolve(
    State(reg): State<SharedRegistry>,
    Path((vendor, name)): Path<(String, String)>,
) -> ApiResult<Json<crate::model::Resolution>> {
    Ok(Json(reg.resolve(&vendor, &name)?))
}
