//! Per-request access log for wallet-interop debugging: one event per
//! HTTP request at DEBUG under the `http_request` target, so it is off at
//! the default `RUST_LOG=info` and switched on with
//! `RUST_LOG=info,http_request=debug`.
//!
//! PII discipline (telemetry.rs, design §13.3): the event carries the
//! method, the path, the query parameter NAMES (never values), a few
//! content-negotiation headers, which credential-bearing headers were
//! present (never their values), the status and the latency. Request
//! bodies (proofs, tokens, claims) are never read.
//!
//! For a 4xx/5xx the response body is the rendered error: `{error,
//! error_description|message}` from the handlers (messages never carry
//! values, wallet.rs `client_auth_failure`) or axum's plain-text extractor
//! rejection. It is logged, truncated, because that is what tells WHY a
//! wallet's request failed. Success bodies are never buffered (credentials,
//! tokens, SSE streams pass through untouched).

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

/// The target RUST_LOG switches on (`http_request=debug`).
pub const TARGET: &str = "http_request";

/// Error bodies larger than this are not buffered (never the case for the
/// handlers' JSON errors).
const MAX_ERROR_BODY: usize = 16 * 1024;
/// How much of an error body goes into the log line.
const LOGGED_ERROR_BODY: usize = 1024;

/// Header names whose presence (not value) is logged.
const PRESENCE_HEADERS: [&str; 5] = [
    "authorization",
    "dpop",
    "oauth-client-attestation",
    "oauth-client-attestation-pop",
    "cookie",
];

fn header_str<'a>(headers: &'a HeaderMap, name: impl header::AsHeaderName) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
}

pub async fn log_request(request: Request, next: Next) -> Response {
    if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
        return next.run(request).await;
    }

    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query_keys: Vec<String> = request
        .uri()
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, _)| k.into_owned())
                .collect()
        })
        .unwrap_or_default();
    let headers = request.headers();
    let user_agent = header_str(headers, header::USER_AGENT).to_owned();
    let content_type = header_str(headers, header::CONTENT_TYPE).to_owned();
    let accept = header_str(headers, header::ACCEPT).to_owned();
    let client_ip = header_str(headers, "fly-client-ip").to_owned();
    let present: Vec<&str> = PRESENCE_HEADERS
        .iter()
        .copied()
        .filter(|h| headers.contains_key(*h))
        .collect();

    let response = next.run(request).await;
    let status = response.status();
    let latency_ms = started.elapsed().as_millis() as u64;

    // Fly's health check every 15 s would drown the log.
    if path == "/healthz" && status.is_success() {
        return response;
    }

    if !(status.is_client_error() || status.is_server_error()) {
        tracing::debug!(
            target: TARGET,
            %method, %path, query = ?query_keys, status = status.as_u16(), latency_ms,
            %client_ip, %user_agent, %content_type, %accept, headers = ?present,
            "request"
        );
        return response;
    }

    let (parts, body) = response.into_parts();
    // Buffer only a body known to be small; anything else passes through
    // unread so the wallet still gets the full response.
    let small = axum::body::HttpBody::size_hint(&body)
        .upper()
        .is_some_and(|n| n <= MAX_ERROR_BODY as u64);
    let (error_body, body) = if small {
        match to_bytes(body, MAX_ERROR_BODY).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let logged: String = text.chars().take(LOGGED_ERROR_BODY).collect();
                (logged, Body::from(bytes))
            }
            Err(e) => (format!("<body read failed: {e}>"), Body::empty()),
        }
    } else {
        ("<not buffered: size unknown or large>".to_owned(), body)
    };
    tracing::debug!(
        target: TARGET,
        %method, %path, query = ?query_keys, status = status.as_u16(), latency_ms,
        %client_ip, %user_agent, %content_type, %accept, headers = ?present,
        error = %error_body,
        "request failed"
    );
    Response::from_parts(parts, body)
}
