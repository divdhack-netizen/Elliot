//! Byte relay + capture.
//!
//! The relay is deliberately dumb: it reads blocks from one side, emits each
//! block as a [`Message`], writes it to the other side, and half-closes when a
//! direction ends. It never parses the payload — the whole point is to carry
//! traffic that is *not* HTTP, whose framing Elliot does not know.
//!
//! Consequences worth stating out loud:
//! - one message is one `read`, so message boundaries are the relay's, not the
//!   protocol's;
//! - `seq` is assigned from a shared counter, so across the two directions it
//!   reflects emission order, not arrival order;
//! - capture is back-pressured: if the event channel is full the relay waits,
//!   because dropping captured bytes silently would be worse than slowing down
//!   the connection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use elliot_httpraw::{Direction, FlowState, Message, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::StreamEvent;

/// Read size for each pump iteration, and therefore the largest single captured
/// message.
const RELAY_BUFFER: usize = 32 * 1024;

/// Assigns message ids/sequence numbers for one stream and sends the events.
#[derive(Clone)]
pub(crate) struct Capture {
    stream_id: Uuid,
    seq: Arc<AtomicU64>,
    events: mpsc::Sender<StreamEvent>,
}

impl Capture {
    pub(crate) fn new(stream_id: Uuid, events: mpsc::Sender<StreamEvent>) -> Self {
        Self {
            stream_id,
            seq: Arc::new(AtomicU64::new(0)),
            events,
        }
    }

    pub(crate) async fn started(&self, stream: &Stream) {
        send(&self.events, StreamEvent::StreamStarted(stream.clone())).await;
    }

    pub(crate) async fn completed(&self, stream: &Stream) {
        send(&self.events, StreamEvent::StreamCompleted(stream.clone())).await;
    }

    pub(crate) async fn message(&self, direction: Direction, data: &[u8]) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let msg = Message {
            id: Uuid::new_v4(),
            stream_id: self.stream_id,
            seq,
            at: SystemTime::now(),
            direction,
            data: Bytes::copy_from_slice(data),
        };
        send(&self.events, StreamEvent::Message(msg)).await;
    }
}

/// Send an event, ignoring a closed channel: the consumer going away (app quit,
/// listener stopped) must never leave the relay busy.
pub(crate) async fn send(events: &mpsc::Sender<StreamEvent>, ev: StreamEvent) {
    let _ = events.send(ev).await;
}

/// Mark a stream finished: `Some(error)` makes it an errored stream, `None` a
/// cleanly completed one.
pub(crate) fn finish(stream: &mut Stream, error: Option<String>) {
    stream.completed_at = Some(SystemTime::now());
    stream.state = if error.is_some() {
        FlowState::Error
    } else {
        FlowState::Completed
    };
    stream.error = error;
}

/// Copy one direction, emitting a message per read. `capture = None` makes it a
/// transparent tunnel (out-of-scope traffic is relayed but never recorded).
///
/// Returns `Ok(())` on clean EOF (or when asked to stop); an `Err` means one of
/// the two sides failed, which is reported on the stream.
pub(crate) async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    capture: Option<&Capture>,
    stop: &mut watch::Receiver<bool>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUFFER];
    loop {
        let n = tokio::select! {
            // `Err` means the sender was dropped, which is a shutdown too.
            _ = stop.changed() => return Ok(()),
            read = reader.read(&mut buf) => read?,
        };
        if n == 0 {
            break;
        }
        if let Some(capture) = capture {
            capture.message(direction, &buf[..n]).await;
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
    }
    // Half-close: the peer must see EOF, otherwise a client waiting for the
    // end of the response waits forever.
    let _ = writer.shutdown().await;
    Ok(())
}

/// Relay both directions of an already-established pair of streams, emitting
/// captured messages when `capture` is `Some`. Returns the error to report on
/// the stream, if any.
pub(crate) async fn both_ways<C, U>(
    client: C,
    upstream: U,
    capture: Option<&Capture>,
    stop: &mut watch::Receiver<bool>,
) -> Option<String>
where
    C: AsyncRead + AsyncWrite,
    U: AsyncRead + AsyncWrite,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let mut stop_other = stop.clone();
    let (to_server, to_client) = tokio::join!(
        pump(
            client_read,
            upstream_write,
            Direction::ClientToServer,
            capture,
            stop
        ),
        pump(
            upstream_read,
            client_write,
            Direction::ServerToClient,
            capture,
            &mut stop_other
        ),
    );

    match (to_server, to_client) {
        (Ok(()), Ok(())) => None,
        (Err(e), _) => Some(format!("client to server: {e}")),
        (_, Err(e)) => Some(format!("server to client: {e}")),
    }
}
