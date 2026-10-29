//! End-to-end WebSocket capture and intercept through the real proxy.
//!
//! The unit tests in `src/websocket.rs` cover the handler in isolation; this one
//! goes through hudsucker, because that is where the wiring is decided: the
//! handler is cloned once per connection (which is what makes `connection_id`
//! per-socket), the upgrade request is turned into an upstream socket, and the
//! returned frame is what actually reaches the origin.
//!
//! Everything is loopback: no outbound network, no external binary.
//!
//! `cargo test -p elliot-proxy --test websocket -- --nocapture`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, WebSocketStream};

use elliot_httpraw::WsMessage;
use elliot_proxy::{start, AllowAll, ProxyConfig, ProxyEvent, ProxyHandle, WsDecision};

/// How long any single step may take before the test fails.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a dropped frame must stay absent from the origin. Short on purpose:
/// it only has to outlive the proxy's hand-off, and a longer wait makes a
/// failing test slow.
const DROP_WINDOW: Duration = Duration::from_millis(300);

type Client = WebSocketStream<TcpStream>;

/// A loopback address that is free right now. The proxy does not report the
/// port it bound (it is given one), so pick one and hand it over.
fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    listener.local_addr().expect("local addr")
}

async fn start_proxy(addr: SocketAddr, ca_dir: &std::path::Path) -> (ProxyHandle, mpsc::Receiver<ProxyEvent>) {
    let (events, rx) = mpsc::channel(128);
    let config = ProxyConfig {
        listen_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
        ca_key_store: elliot_proxy::KeyStore::EncryptedFile,
        verify_upstream: true,
    };
    let handle = start(config, Arc::new(AllowAll), events)
        .await
        .expect("the proxy should start on loopback");
    (handle, rx)
}

/// A WebSocket origin that pushes every data frame it receives into a channel.
async fn spawn_origin() -> (SocketAddr, mpsc::UnboundedReceiver<Message>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(sock).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    // Only data frames matter to the assertions; control frames
                    // (and the close handshake) are transport noise here.
                    if matches!(message, Message::Text(_) | Message::Binary(_)) {
                        let _ = tx.send(message);
                    }
                }
            });
        }
    });
    (addr, rx)
}

/// Read until the end of the header block (`\r\n\r\n`), or EOF.
///
/// One byte at a time on purpose: any read-ahead would swallow the first
/// WebSocket frame, which the origin may send as soon as the handshake ends.
async fn read_headers<S: AsyncReadExt + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(buf)
}

/// Open a WebSocket through the proxy using an **absolute-form** request line.
///
/// The line spells `http://host:port/chat`, not `ws://…`: a forward proxy sees
/// the ordinary `http` scheme and hudsucker itself rewrites it to `ws` (a URI
/// that already says `ws` is taken as secure and the upstream connect attempts
/// TLS). `ws://` never uses CONNECT, so the absolute form is also what tells the
/// proxy where to connect; tungstenite's own client writes origin-form, hence
/// the hand-written handshake followed by `from_raw_socket`.
async fn connect_through_proxy(proxy: SocketAddr, origin: SocketAddr) -> Client {
    let mut tcp = TcpStream::connect(proxy).await.expect("connect to the proxy");
    let request = format!(
        "GET http://{origin}/chat HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let head = read_headers(&mut tcp).await.expect("read the handshake");
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "the proxy refused the upgrade: {}",
        String::from_utf8_lossy(&head)
    );
    WebSocketStream::from_raw_socket(tcp, Role::Client, None).await
}

/// Wait for the next WebSocket event, skipping the HTTP flow events that the
/// upgrade request also produces.
async fn next_ws(rx: &mut mpsc::Receiver<ProxyEvent>) -> WsMessage {
    tokio::time::timeout(STEP_TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(ProxyEvent::WebSocket(message)) => return message,
                Some(_) => continue,
                None => panic!("the proxy event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for a WebSocket event")
}

/// Wait for a frame to reach the origin.
async fn next_at_origin(rx: &mut mpsc::UnboundedReceiver<Message>, what: &str) -> Message {
    tokio::time::timeout(STEP_TIMEOUT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what} at the origin"))
        .unwrap_or_else(|| panic!("the origin socket closed before {what}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_edit_drop_and_per_socket_identity() {
    let ca_dir = tempfile::tempdir().unwrap();
    let (origin, mut at_origin) = spawn_origin().await;
    let proxy_addr = free_loopback_addr();
    let (proxy, mut events) = start_proxy(proxy_addr, ca_dir.path()).await;

    // --- forward with an edited payload --------------------------------
    // The upgrade itself is an HTTP request, so it is opened with intercept off
    // (a held upgrade would never become a socket); the switch is turned on for
    // the frames.
    let mut client = tokio::time::timeout(STEP_TIMEOUT, connect_through_proxy(proxy_addr, origin))
        .await
        .expect("the WebSocket upgrade timed out");
    proxy.set_intercept(true);
    client
        .send(Message::Text("hello".into()))
        .await
        .expect("send the first frame");

    let held = next_ws(&mut events).await;
    assert!(held.paused, "intercept is on: the frame must be held");
    assert_eq!(&held.payload[..], b"hello");
    assert!(
        held.connection.ends_with(&format!(" <-> {origin}")),
        "the label names the origin, got {:?}",
        held.connection
    );

    proxy.decide_ws(held.id, WsDecision::ForwardEdited(b"edited".to_vec()));
    let arrived = next_at_origin(&mut at_origin, "the edited frame").await;
    assert_eq!(
        arrived.to_text().unwrap(),
        "edited",
        "the origin must receive the edited payload, not the original"
    );

    // The resolved event announces what was actually forwarded (W2).
    let resolved = next_ws(&mut events).await;
    assert!(!resolved.paused, "the resolved frame is no longer held");
    assert_eq!(resolved.id, held.id);
    assert_eq!(&resolved.payload[..], b"edited");

    // --- drop -----------------------------------------------------------
    client
        .send(Message::Text("drop me".into()))
        .await
        .expect("send the frame to drop");
    let held = next_ws(&mut events).await;
    assert!(held.paused);
    assert_eq!(&held.payload[..], b"drop me");
    let same_socket = held.connection_id;
    assert_eq!(
        same_socket, resolved.connection_id,
        "every frame of one socket shares a connection id"
    );

    proxy.decide_ws(held.id, WsDecision::Drop);
    assert!(
        tokio::time::timeout(DROP_WINDOW, at_origin.recv())
            .await
            .is_err(),
        "a dropped frame must not reach the origin"
    );
    // A drop is not history either: nothing resolved is announced for it, and
    // the next event is the one belonging to the frame after it.
    client
        .send(Message::Text("after the drop".into()))
        .await
        .expect("send a frame after the drop");
    let held = next_ws(&mut events).await;
    assert_eq!(held.payload.as_ref(), b"after the drop");
    assert_eq!(
        held.connection_id, same_socket,
        "the socket survived the drop"
    );
    proxy.decide_ws(held.id, WsDecision::Forward);
    let arrived = next_at_origin(&mut at_origin, "the frame after the drop").await;
    assert_eq!(arrived.to_text().unwrap(), "after the drop");
    let resolved = next_ws(&mut events).await;
    assert!(!resolved.paused);

    // --- a second socket gets its own identity --------------------------
    // Intercept off: observe-only, so no decision is needed for the second
    // client and its frames arrive as already-resolved events.
    proxy.set_intercept(false);
    let mut second = tokio::time::timeout(STEP_TIMEOUT, connect_through_proxy(proxy_addr, origin))
        .await
        .expect("the second WebSocket upgrade timed out");
    second
        .send(Message::Text("from another socket".into()))
        .await
        .expect("send from the second socket");

    let observed = next_ws(&mut events).await;
    assert!(!observed.paused, "intercept is off");
    assert_eq!(&observed.payload[..], b"from another socket");
    assert_ne!(
        observed.connection_id, same_socket,
        "a new connection must not reuse the previous socket id"
    );
    let arrived = next_at_origin(&mut at_origin, "the second socket's frame").await;
    assert_eq!(arrived.to_text().unwrap(), "from another socket");

    tokio::time::timeout(STEP_TIMEOUT, proxy.stop())
        .await
        .expect("the proxy should stop");
}
