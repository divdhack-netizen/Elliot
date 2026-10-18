//! hudsucker [`HttpHandler`] implementation: builds flows, consults scope,
//! emits events, and (Phase B) pauses for interception.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use hudsucker::{
    hyper::{Request, Response},
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use uuid::Uuid;

use elliot_httpraw::{Flow, FlowState, ScopeDecision};

use crate::convert;
use crate::intercept::{InterceptDecision, Registry};
use crate::scope::ScopeDecider;
use crate::ProxyEvent;

#[derive(Clone)]
pub struct Handler {
    pub events: tokio::sync::mpsc::Sender<ProxyEvent>,
    pub scope: Arc<dyn ScopeDecider>,
    pub intercept_on: Arc<AtomicBool>,
    pub registry: Registry,
    /// In-flight flows on this connection, FIFO (request order == response
    /// order on HTTP/1.1). Cloned empty for each new connection.
    pub pending: VecDeque<Flow>,
}

impl Handler {
    async fn emit(&self, event: ProxyEvent) {
        // The core owns the receiver; if it is gone the proxy is shutting down.
        let _ = self.events.send(event).await;
    }
}

impl HttpHandler for Handler {
    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> bool {
        // Out-of-scope CONNECT targets are tunnelled transparently: no MITM, no
        // decryption, no storage.
        let (host, port) = match req.uri().authority() {
            Some(a) => (a.host().to_string(), a.port_u16().unwrap_or(443)),
            None => return true,
        };
        !matches!(
            self.scope.decide("https", &host, port, ""),
            ScopeDecision::OutOfScope | ScopeDecision::Passthrough
        )
    }

    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // CONNECT is tunnel setup, not application traffic; hudsucker drives
        // the tunnel, so forward it untouched and never log it as a flow.
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }

        let (parts, body) = match convert::split_request(req).await {
            Ok(v) => v,
            Err(e) => {
                self.emit(ProxyEvent::Error(e.to_string())).await;
                return blocked_response(502, "Elliot: request read error").into();
            }
        };

        let (scheme, host, port) = convert::target_info(&parts);
        let path = parts.uri.path().to_string();
        let decision = self.scope.decide(scheme.as_str(), &host, port, &path);

        if decision != ScopeDecision::InScope {
            // Not in scope: forward untouched, log nothing, store nothing.
            return convert::rebuild_request(parts, body).into();
        }

        let request = convert::to_httpraw_request(&parts, &body);
        let flow = Flow {
            id: Uuid::new_v4(),
            started_at: SystemTime::now(),
            completed_at: None,
            client_addr: ctx.client_addr,
            scheme,
            host,
            port,
            request,
            response: None,
            state: FlowState::Pending,
            scope: ScopeDecision::InScope,
            error: None,
        };

        if self.intercept_on.load(Ordering::Relaxed) {
            return self.intercept(flow, parts, body).await;
        }

        self.emit(ProxyEvent::FlowStarted(flow.clone())).await;
        self.pending.push_back(flow);
        convert::rebuild_request(parts, body).into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let (parts, body) = match convert::split_response(res).await {
            Ok(v) => v,
            Err(e) => {
                self.emit(ProxyEvent::Error(e.to_string())).await;
                return blocked_response(502, "Elliot: response read error");
            }
        };

        if let Some(mut flow) = self.pending.pop_front() {
            flow.response = Some(convert::to_httpraw_response(&parts, &body));
            flow.completed_at = Some(SystemTime::now());
            flow.state = FlowState::Completed;
            self.emit(ProxyEvent::FlowCompleted(flow)).await;
        }
        convert::rebuild_response(parts, body)
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        if let Some(mut flow) = self.pending.pop_front() {
            flow.completed_at = Some(SystemTime::now());
            flow.state = FlowState::Error;
            flow.error = Some(err.to_string());
            self.emit(ProxyEvent::FlowCompleted(flow)).await;
        } else {
            self.emit(ProxyEvent::Error(err.to_string())).await;
        }
        blocked_response(502, "Elliot: upstream error")
    }
}

impl Handler {
    /// Pause an in-scope flow and act on the user's decision.
    async fn intercept(
        &mut self,
        mut flow: Flow,
        parts: http::request::Parts,
        body: bytes::Bytes,
    ) -> RequestOrResponse {
        flow.state = FlowState::Paused;
        self.emit(ProxyEvent::FlowUpdated(flow.clone())).await;

        let rx = self.registry.register(flow.id);
        let decision = rx.await.unwrap_or(InterceptDecision::Forward);

        match decision {
            InterceptDecision::Forward => {
                flow.state = FlowState::Pending;
                self.emit(ProxyEvent::FlowStarted(flow.clone())).await;
                self.pending.push_back(flow);
                convert::rebuild_request(parts, body).into()
            }
            InterceptDecision::ForwardEdited(edited) => {
                match crate::intercept::parse_edited_request(&edited, &parts) {
                    Ok((new_parts, new_body)) => {
                        flow.request = convert::to_httpraw_request(&new_parts, &new_body);
                        flow.state = FlowState::Pending;
                        self.emit(ProxyEvent::FlowStarted(flow.clone())).await;
                        self.pending.push_back(flow);
                        convert::rebuild_request(new_parts, new_body).into()
                    }
                    Err(e) => {
                        // Could not parse the edit: forward the original rather
                        // than silently dropping, and surface the error.
                        flow.error = Some(format!("edit rejected: {e}"));
                        flow.state = FlowState::Pending;
                        self.emit(ProxyEvent::FlowStarted(flow.clone())).await;
                        self.pending.push_back(flow);
                        convert::rebuild_request(parts, body).into()
                    }
                }
            }
            InterceptDecision::Drop => {
                flow.completed_at = Some(SystemTime::now());
                flow.state = FlowState::Dropped;
                self.emit(ProxyEvent::FlowCompleted(flow)).await;
                blocked_response(403, "Elliot: request dropped").into()
            }
        }
    }
}

fn blocked_response(status: u16, msg: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(msg))
        .expect("static response is valid")
}
