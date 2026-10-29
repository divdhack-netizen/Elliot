//! End-to-end tests for the SOCKS5 UDP ASSOCIATE path.

mod support;

use std::time::Duration;

use elliot_httpraw::{Direction, FlowState, ScopeDecision, Transport};
use elliot_scope::ScopePolicy;
use elliot_socks::protocol::{self, Target};
use elliot_socks::StreamEvent;
use support::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn udp_associate_forwards_and_captures_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let echo = udp_echo().await;
    let (handle, mut rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let (control, relay, local) = udp_associate(handle.local_addr()).await;
    let target = Target::Ip(echo.ip(), echo.port());
    local
        .send_to(&protocol::encode_datagram(&target, b"dns?"), relay)
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), local.recv_from(&mut buf))
        .await
        .expect("the relay should answer")
        .unwrap();
    assert_eq!(from, relay, "the answer comes from the relay socket");
    let (reply_target, offset) = protocol::parse_datagram(&buf[..n]).unwrap();
    assert_eq!(reply_target, target, "the reply names the target that answered");
    assert_eq!(&buf[offset..n], b"dns?");

    let StreamEvent::StreamStarted(started) = next_event(&mut rx).await else {
        panic!("expected the stream to start");
    };
    assert_eq!(started.transport, Transport::Udp);
    assert_eq!(started.host, echo.ip().to_string());
    assert_eq!(started.port, echo.port());
    assert_eq!(started.scope, ScopeDecision::InScope);

    let StreamEvent::Message(to_target) = next_event(&mut rx).await else {
        panic!("expected the datagram towards the target");
    };
    assert_eq!(to_target.direction, Direction::ClientToServer);
    assert_eq!(&to_target.data[..], b"dns?", "the SOCKS header is stripped");

    let StreamEvent::Message(to_client) = next_event(&mut rx).await else {
        panic!("expected the datagram towards the client");
    };
    assert_eq!(to_client.direction, Direction::ServerToClient);
    assert_eq!(&to_client.data[..], b"dns?");

    // Closing the control connection ends the association.
    drop(control);
    let StreamEvent::StreamCompleted(done) = next_event(&mut rx).await else {
        panic!("expected the stream to complete");
    };
    assert_eq!(done.id, started.id);
    assert_eq!(done.state, FlowState::Completed);

    handle.stop().await;
}

#[tokio::test]
async fn out_of_scope_datagrams_are_dropped_and_never_captured() {
    let dir = tempfile::tempdir().unwrap();
    let echo = udp_echo().await;
    let policy = ScopePolicy::host_suffix("elsewhere.example");
    let (handle, mut rx) = start_listener(dir.path(), false, policy).await;

    let (control, relay, local) = udp_associate(handle.local_addr()).await;
    let target = Target::Ip(echo.ip(), echo.port());
    local
        .send_to(&protocol::encode_datagram(&target, b"nope"), relay)
        .await
        .unwrap();

    // Nothing comes back (the datagram was not forwarded) and nothing is
    // captured: an association with no in-scope traffic produces no stream at
    // all, so an out-of-scope peer is not even observable in the UI.
    let mut buf = vec![0u8; 512];
    let silence = tokio::time::timeout(Duration::from_millis(500), local.recv_from(&mut buf)).await;
    assert!(silence.is_err(), "an out-of-scope datagram must not be forwarded");
    expect_no_events(&mut rx).await;

    drop(control);
    handle.stop().await;
}

#[tokio::test]
async fn a_datagram_from_an_unknown_source_is_never_forwarded_to_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let echo = udp_echo().await;
    let (handle, _rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let (control, relay, local) = udp_associate(handle.local_addr()).await;
    let target = Target::Ip(echo.ip(), echo.port());
    local
        .send_to(&protocol::encode_datagram(&target, b"hi"), relay)
        .await
        .unwrap();

    // A third party (not the learned client address) talks to the relay; its
    // datagram must not reach the client.
    let outsider = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    outsider
        .send_to(&protocol::encode_datagram(&target, b"spoof"), relay)
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let spoofed = tokio::time::timeout(Duration::from_millis(300), outsider.recv_from(&mut buf)).await;
    assert!(spoofed.is_err(), "the relay never answers a second peer");

    drop(control);
    handle.stop().await;

    // The client still got its (legitimate) answer.
    let mut buf = vec![0u8; 512];
    let got = tokio::time::timeout(Duration::from_secs(5), local.recv_from(&mut buf)).await;
    assert!(got.is_ok(), "the legitimate datagram still round-trips");
}

#[tokio::test]
async fn fragmented_datagrams_are_dropped_without_ending_the_association() {
    let dir = tempfile::tempdir().unwrap();
    let echo = udp_echo().await;
    let (handle, _rx) = start_listener(dir.path(), false, ScopePolicy::new()).await;

    let (mut control, relay, local) = udp_associate(handle.local_addr()).await;
    let target = Target::Ip(echo.ip(), echo.port());

    let mut fragmented = protocol::encode_datagram(&target, b"frag");
    fragmented[2] = 0x01; // FRAG != 0
    local.send_to(&fragmented, relay).await.unwrap();

    // A normal datagram on the same association is still served.
    local
        .send_to(&protocol::encode_datagram(&target, b"fine"), relay)
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), local.recv_from(&mut buf))
        .await
        .expect("the association must survive a fragmented datagram")
        .unwrap();
    let (_, offset) = protocol::parse_datagram(&buf[..n]).unwrap();
    assert_eq!(&buf[offset..n], b"fine");

    control.write_all(b"").await.unwrap();
    drop(control);
    handle.stop().await;
}
