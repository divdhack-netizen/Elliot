//! End-to-end tests for the SOCKS5 CONNECT path: capture, the scope gate, the
//! optional TLS MITM and user/password auth — all against real sockets.

mod support;

use elliot_httpraw::{Direction, FlowState, ScopeDecision, Transport};
use elliot_scope::ScopePolicy;
use elliot_socks::protocol::{self, Target};
use elliot_socks::StreamEvent;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn captures_both_directions_of_a_tcp_stream() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let (handle, mut rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let (mut tunnel, rep) =
        connect_through(handle.local_addr(), &Target::Ip(echo.ip(), echo.port())).await;
    assert_eq!(rep, protocol::REP_SUCCEEDED);
    tunnel.write_all(b"PING\r\n").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut back = [0u8; 6];
    tunnel.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"PING\r\n");
    // Close the client side: the relay half-closes upstream, the echo server
    // sees EOF and closes, so the whole stream winds down.
    drop(tunnel);

    let StreamEvent::StreamStarted(started) = next_event(&mut rx).await else {
        panic!("expected the stream to start");
    };
    assert_eq!(started.transport, Transport::Tcp);
    assert_eq!(started.host, echo.ip().to_string());
    assert_eq!(started.port, echo.port());
    assert!(!started.tls, "no TLS on a plaintext connection");
    assert_eq!(started.scope, ScopeDecision::InScope);
    assert_eq!(started.state, FlowState::Pending);

    let StreamEvent::Message(to_server) = next_event(&mut rx).await else {
        panic!("expected the client-to-server message");
    };
    assert_eq!(to_server.stream_id, started.id);
    assert_eq!(to_server.direction, Direction::ClientToServer);
    assert_eq!(&to_server.data[..], b"PING\r\n");

    let StreamEvent::Message(to_client) = next_event(&mut rx).await else {
        panic!("expected the server-to-client message");
    };
    assert_eq!(to_client.direction, Direction::ServerToClient);
    assert_eq!(&to_client.data[..], b"PING\r\n");
    assert!(to_client.seq > to_server.seq, "sequence numbers increase");

    let StreamEvent::StreamCompleted(done) = next_event(&mut rx).await else {
        panic!("expected the stream to complete");
    };
    assert_eq!(done.id, started.id);
    assert_eq!(done.state, FlowState::Completed);
    assert!(done.completed_at.is_some());
    assert!(done.error.is_none());

    handle.stop().await;
}

#[tokio::test]
async fn out_of_scope_traffic_is_tunnelled_but_not_captured() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    // A policy that includes only some other host: 127.0.0.1 is out of scope.
    let policy = ScopePolicy::host_suffix("elsewhere.example");
    let (handle, mut rx) = start_listener(dir.path(), false, policy).await;

    let (mut tunnel, rep) =
        connect_through(handle.local_addr(), &Target::Ip(echo.ip(), echo.port())).await;
    assert_eq!(rep, protocol::REP_SUCCEEDED);
    tunnel.write_all(b"still works").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut back = [0u8; 11];
    tunnel.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"still works", "an out-of-scope target still relays");
    drop(tunnel);

    expect_no_events(&mut rx).await;
    handle.stop().await;
}

#[tokio::test]
async fn mitm_tls_captures_the_application_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tls_echo().await;
    let (handle, mut rx) = start_listener(dir.path(), true, ScopePolicy::new()).await;

    // The target is named, not a literal: the listener must mint a leaf for
    // exactly this name.
    let target = Target::Domain("localhost".into(), echo.port());
    let (tunnel, rep) = connect_through(handle.local_addr(), &target).await;
    assert_eq!(rep, protocol::REP_SUCCEEDED);

    // A client that trusts only the listener's CA: a successful handshake here
    // means the minted leaf chains to the shared local CA.
    let connector = client_trusting_ca(dir.path());
    let mut tls = connector
        .connect(server_name("localhost"), tunnel)
        .await
        .expect("the minted certificate must be accepted");
    tls.write_all(b"HELLO-TLS").await.unwrap();
    tls.flush().await.unwrap();
    let mut back = [0u8; 9];
    tls.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"HELLO-TLS");
    drop(tls);

    let StreamEvent::StreamStarted(started) = next_event(&mut rx).await else {
        panic!("expected the stream to start");
    };
    assert!(started.tls, "a terminated TLS stream is flagged as such");
    assert_eq!(started.host, "localhost");

    let StreamEvent::Message(to_server) = next_event(&mut rx).await else {
        panic!("expected the client-to-server message");
    };
    assert_eq!(
        &to_server.data[..],
        b"HELLO-TLS",
        "captured bytes are the plaintext, not the TLS records"
    );

    let StreamEvent::Message(to_client) = next_event(&mut rx).await else {
        panic!("expected the server-to-client message");
    };
    assert_eq!(&to_client.data[..], b"HELLO-TLS");

    handle.stop().await;
}

#[tokio::test]
async fn without_mitm_tls_the_bytes_are_captured_opaque() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tls_echo().await;
    let (handle, mut rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let target = Target::Domain("localhost".into(), echo.port());
    let (tunnel, rep) = connect_through(handle.local_addr(), &target).await;
    assert_eq!(rep, protocol::REP_SUCCEEDED);

    let connector = client_accepting_anything();
    let mut tls = connector
        .connect(server_name("localhost"), tunnel)
        .await
        .expect("TLS passes through untouched");
    tls.write_all(b"HELLO-TLS").await.unwrap();
    tls.flush().await.unwrap();
    let mut back = [0u8; 9];
    tls.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"HELLO-TLS");
    drop(tls);

    let StreamEvent::StreamStarted(started) = next_event(&mut rx).await else {
        panic!("expected the stream to start");
    };
    assert!(!started.tls);

    let StreamEvent::Message(to_server) = next_event(&mut rx).await else {
        panic!("expected the client-to-server message");
    };
    assert_eq!(to_server.data[0], 0x16, "a TLS handshake record");
    assert_eq!(to_server.data[1], 0x03);
    assert!(
        !to_server.data.windows(9).any(|w| w == b"HELLO-TLS"),
        "nothing is decrypted without mitm_tls"
    );

    handle.stop().await;
}

#[tokio::test]
async fn credentials_are_required_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, _rx) = start_listener_with(
        dir.path(),
        false,
        ScopePolicy::new(),
        Some(("user".into(), "pa55".into())),
    )
    .await;

    // A no-auth-only client is refused outright.
    let mut sock = TcpStream::connect(handle.local_addr()).await.unwrap();
    sock.write_all(&[protocol::VERSION, 1, protocol::METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [protocol::VERSION, protocol::METHOD_NONE_ACCEPTABLE]);

    // Offering user/password negotiates it; the credentials then decide.
    let mut sock = TcpStream::connect(handle.local_addr()).await.unwrap();
    sock.write_all(&[protocol::VERSION, 1, protocol::METHOD_USER_PASS])
        .await
        .unwrap();
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [protocol::VERSION, protocol::METHOD_USER_PASS]);

    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(5);
    auth.extend_from_slice(b"nope!");
    sock.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    sock.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [0x01, 0x01], "wrong password fails");

    // And the correct credentials let the request through.
    let mut sock = TcpStream::connect(handle.local_addr()).await.unwrap();
    sock.write_all(&[protocol::VERSION, 1, protocol::METHOD_USER_PASS])
        .await
        .unwrap();
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [protocol::VERSION, protocol::METHOD_USER_PASS]);
    let mut auth = vec![0x01, 4];
    auth.extend_from_slice(b"user");
    auth.push(4);
    auth.extend_from_slice(b"pa55");
    sock.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    sock.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [0x01, 0x00], "correct credentials are accepted");
    assert_eq!(
        request(
            &mut sock,
            protocol::CMD_CONNECT,
            &Target::Ip(refused_addr().ip(), 1)
        )
        .await,
        protocol::REP_CONNECTION_REFUSED,
        "the request is processed after a successful handshake"
    );

    handle.stop().await;
}

/// An address that is guaranteed to refuse connections: port 1 on loopback.
fn refused_addr() -> std::net::SocketAddr {
    "127.0.0.1:1".parse().unwrap()
}

#[tokio::test]
async fn unsupported_commands_are_answered_with_the_right_code() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, _rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let mut sock = TcpStream::connect(handle.local_addr()).await.unwrap();
    handshake(&mut sock).await;
    let rep = request(
        &mut sock,
        protocol::CMD_BIND,
        &Target::Ip("127.0.0.1".parse().unwrap(), 80),
    )
    .await;
    assert_eq!(rep, protocol::REP_COMMAND_UNSUPPORTED);

    handle.stop().await;
}

#[tokio::test]
async fn an_unreachable_target_becomes_a_socks_error_reply() {
    let dir = tempfile::tempdir().unwrap();
    let (handle, _rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    // Port 1 on loopback refuses connections.
    let (_, rep) = connect_through(handle.local_addr(), &Target::Ip(refused_addr().ip(), 1)).await;
    assert_eq!(rep, protocol::REP_CONNECTION_REFUSED);

    handle.stop().await;
}

#[tokio::test]
async fn stopping_the_listener_completes_open_streams() {
    let dir = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let (handle, mut rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let (mut tunnel, _) = connect_through(handle.local_addr(), &Target::Ip(echo.ip(), echo.port())).await;
    tunnel.write_all(b"still open").await.unwrap();
    tunnel.flush().await.unwrap();
    let mut back = [0u8; 10];
    tunnel.read_exact(&mut back).await.unwrap();

    let StreamEvent::StreamStarted(started) = next_event(&mut rx).await else {
        panic!("expected the stream to start");
    };
    assert_eq!(next_message(&mut rx).await.direction, Direction::ClientToServer);

    // Stopping must not leave the stream dangling: the relay winds down and
    // reports completion instead of being killed silently.
    handle.stop().await;
    let done = loop {
        match next_event(&mut rx).await {
            StreamEvent::StreamCompleted(s) => break s,
            StreamEvent::Message(_) => continue,
            other => panic!("unexpected event {other:?}"),
        }
    };
    assert_eq!(done.id, started.id);
    assert_eq!(done.state, FlowState::Completed);

    drop(tunnel);
}

async fn next_message(rx: &mut tokio::sync::mpsc::Receiver<StreamEvent>) -> elliot_httpraw::Message {
    match next_event(rx).await {
        StreamEvent::Message(m) => m,
        other => panic!("expected a message, got {other:?}"),
    }
}
