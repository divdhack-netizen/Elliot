//! Conversions between hudsucker's `http` messages and the shared
//! [`elliot_httpraw`] model, plus body collection.
//!
//! Collecting a body consumes it, so the capture path reads the full body and
//! then rebuilds a fresh message to forward on.

use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use hudsucker::Body;

use elliot_httpraw::net::split_host_port;
use elliot_httpraw::{Header, HttpVersion, Scheme};

/// Split a request into its parts and fully-collected body bytes.
pub async fn split_request(req: Request<Body>) -> Result<(http::request::Parts, Bytes)> {
    let (parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading request body: {e}"))?
        .to_bytes();
    Ok((parts, bytes))
}

/// Split a response into its parts and fully-collected body bytes.
pub async fn split_response(res: Response<Body>) -> Result<(http::response::Parts, Bytes)> {
    let (parts, body) = res.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading response body: {e}"))?
        .to_bytes();
    Ok((parts, bytes))
}

/// Rebuild a forwardable request from parts and body.
pub fn rebuild_request(parts: http::request::Parts, body: Bytes) -> Request<Body> {
    Request::from_parts(parts, Body::from(body))
}

/// Rebuild a forwardable response from parts and body.
pub fn rebuild_response(parts: http::response::Parts, body: Bytes) -> Response<Body> {
    Response::from_parts(parts, Body::from(body))
}

/// Build the shared parsed+raw request view.
pub fn to_httpraw_request(parts: &http::request::Parts, body: &Bytes) -> elliot_httpraw::Request {
    let method = parts.method.as_str().to_string();
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| parts.uri.to_string());
    let version = HttpVersion::from_http(parts.version);
    let headers = headers_vec(&parts.headers);
    let raw = elliot_httpraw::serialize_request(&method, &target, version, &headers, body);
    elliot_httpraw::Request {
        method,
        target,
        version,
        headers,
        body: body.clone(),
        raw,
    }
}

/// Build the shared parsed+raw response view.
pub fn to_httpraw_response(parts: &http::response::Parts, body: &Bytes) -> elliot_httpraw::Response {
    let status = parts.status.as_u16();
    let reason = parts
        .status
        .canonical_reason()
        .unwrap_or_default()
        .to_string();
    let version = HttpVersion::from_http(parts.version);
    let headers = headers_vec(&parts.headers);
    let raw = elliot_httpraw::serialize_response(status, &reason, version, &headers, body);
    elliot_httpraw::Response {
        status,
        reason,
        version,
        headers,
        body: body.clone(),
        raw,
    }
}

/// Derive (scheme, host, port) from a request, falling back to the `Host`
/// header and scheme-default ports when the URI is in origin form.
pub fn target_info(parts: &http::request::Parts) -> (Scheme, String, u16) {
    let scheme = match parts.uri.scheme_str() {
        Some("https") => Some(Scheme::Https),
        Some("http") => Some(Scheme::Http),
        _ => None,
    };

    let authority_host = parts.uri.host().map(|h| h.to_string());
    let host_header = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // "host:port" from either source.
    let (host, header_port) = match authority_host.or(host_header) {
        Some(raw) => split_host_port(&raw),
        None => (String::new(), None),
    };

    let port = parts
        .uri
        .port_u16()
        .or(header_port)
        .unwrap_or(match scheme {
            Some(Scheme::Https) => 443,
            _ => 80,
        });

    let scheme = scheme.unwrap_or(if port == 443 {
        Scheme::Https
    } else {
        Scheme::Http
    });

    (scheme, host, port)
}

fn headers_vec(map: &http::HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(name, value)| Header {
            name: name.as_str().to_string(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}
