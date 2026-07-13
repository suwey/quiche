use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::inbound::Destination;
use crate::outbound::common::connect_tcp_bypass_sync;
use crate::tlsfragment::FragmentConfig;
use crate::outbound::vless::WsStream;
use crate::outbound::vless::{
    self,
};
use crate::protocol::vless::VlessCommand;
use crate::protocol::vless::encode_request_bytes;
use crate::relay::PacketRelay;
use crate::relay::StreamRelay;
use async_trait::async_trait;

/// Edgetunnel mux.cool frame format:
///   2 bytes: total_len (big-endian Uint16, = 4 + payload.len)
///   1 byte:  type
///   1 byte:  reserved (0)
///   2 bytes: stream_id (big-endian Uint16)
///   N bytes: payload
///
/// Types:
///   0x01 NEW  — open stream; payload = VLESS req
///   0x02 DATA — stream data
///   0x03 RST  — close stream
///   0x04 KEEPALIVE

const MUX_NEW: u8 = 0x01;
const MUX_DATA: u8 = 0x02;
const MUX_RST: u8 = 0x03;
const MUX_KEEPALIVE: u8 = 0x04;
/// Standard mux.cool frame header: 4 bytes length + 1 byte type + 4 bytes
/// stream_id.
const MUX_FRAME_HDR: usize = 9;
const MAX_STREAMS: usize = 256;

fn encode_mux_frame(type_: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let total = 5 + payload.len(); // 1 type + 4 stream_id + payload
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&(total as u32).to_be_bytes());
    buf.push(type_);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

struct MuxFrame {
    type_: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn try_parse_mux(buf: &[u8]) -> Option<(MuxFrame, usize)> {
    if buf.len() < MUX_FRAME_HDR {
        return None;
    }
    let total = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let frame_end = 4 + total;
    if buf.len() < frame_end {
        return None;
    }
    let type_ = buf[4];
    let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
    let payload = buf[9..frame_end].to_vec();
    Some((
        MuxFrame {
            type_,
            stream_id,
            payload,
        },
        frame_end,
    ))
}

// ---------------------------------------------------------------------------
// MuxSession
// ---------------------------------------------------------------------------

pub struct MuxSession {
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<io::Result<()>>>>>,
    next_id: AtomicU32,
    _uuid: [u8; 16],
}

impl MuxSession {
    pub fn spawn(
        addr: std::net::SocketAddr, uuid: [u8; 16], tls_server: &str,
        insecure: bool, tls_fp: bool,
        fragment: Option<&FragmentConfig>,
        path: &str, headers: &HashMap<String, String>,
    ) -> io::Result<Arc<Self>> {
        let tcp = connect_tcp_bypass_sync(addr)?;
        let ws =
            vless::build_ws(tcp, tls_server, insecure, tls_fp, fragment, path, headers)?;

        let (frame_tx, mut frame_rx) = mpsc::unbounded_channel();
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let next_id = AtomicU32::new(1);

        let s = streams.clone();
        let p = pending.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = io_loop(ws, &mut frame_rx, s, p) {
                log::error!("vless mux io: {e}");
            }
        });

        Ok(Arc::new(Self {
            frame_tx,
            streams,
            pending,
            next_id,
            _uuid: uuid,
        }))
    }

    pub async fn dial_stream(
        self: &Arc<Self>, uuid: &[u8; 16], command: VlessCommand,
        dest: &Destination,
    ) -> Result<Box<dyn StreamRelay>, Box<dyn std::error::Error>> {
        if self.pending.lock().await.len() >= MAX_STREAMS {
            return Err("vless mux: too many streams".into());
        }

        let stream_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let (resp_tx, resp_rx) = oneshot::channel();

        self.streams.lock().await.insert(stream_id, data_tx);
        self.pending.lock().await.insert(stream_id, resp_tx);

        let vless_req = encode_request_bytes(uuid, None, command, dest);
        let frame = encode_mux_frame(MUX_NEW, stream_id, &vless_req);
        let _ = self.frame_tx.send(frame);

        match resp_rx.await {
            Ok(Ok(())) => Ok(Box::new(VlessMuxStreamRelay {
                stream_id,
                frame_tx: self.frame_tx.clone(),
                data_rx,
            })),
            Ok(Err(e)) => {
                self.streams.lock().await.remove(&stream_id);
                Err(e.into())
            },
            Err(_) => {
                self.streams.lock().await.remove(&stream_id);
                Err("vless mux: session closed".into())
            },
        }
    }
}

// ---------------------------------------------------------------------------
// IO thread
// ---------------------------------------------------------------------------

fn io_loop(
    mut ws: WsStream, frame_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<io::Result<()>>>>>,
) -> io::Result<()> {
    ws.set_read_timeout(Duration::from_millis(100))?;
    let mut recv_buf = Vec::new();

    loop {
        // Drain outbound frames.
        loop {
            match frame_rx.try_recv() {
                Ok(frame) =>
                    if let Err(e) = ws.send_raw(&frame) {
                        log::error!("vless mux send: {e}");
                        break;
                    },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) =>
                    return Ok(()),
            }
        }

        // Read one WS frame.
        match ws.recv() {
            Ok(data) => {
                recv_buf.extend_from_slice(&data);
                loop {
                    let Some((frame, consumed)) = try_parse_mux(&recv_buf) else {
                        break;
                    };
                    recv_buf.drain(..consumed);
                    match frame.type_ {
                        MUX_DATA => dispatch_data(
                            frame.stream_id,
                            &frame.payload,
                            &streams,
                            &pending,
                        ),
                        MUX_RST => {
                            streams.blocking_lock().remove(&frame.stream_id);
                        },
                        MUX_KEEPALIVE => {
                            let resp = encode_mux_frame(MUX_KEEPALIVE, 0, &[]);
                            let _ = ws.send_raw(&resp);
                        },
                        _ => {},
                    }
                }
            },
            Err(ref e)
                if e.kind() == io::ErrorKind::TimedOut ||
                    e.kind() == io::ErrorKind::WouldBlock =>
                continue,
            Err(e) => {
                log::debug!("vless mux recv: {e}");
                break;
            },
        }
    }

    Ok(())
}

fn dispatch_data(
    stream_id: u32, payload: &[u8],
    streams: &Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    pending: &Mutex<HashMap<u32, oneshot::Sender<io::Result<()>>>>,
) {
    let mut p = pending.blocking_lock();
    if let Some(sender) = p.remove(&stream_id) {
        let rest = if payload.len() >= 2 && payload[0] == 0 && payload[1] == 0 {
            &payload[2..]
        } else {
            log::warn!("vless mux: stream #{stream_id} first frame not [0,0]");
            payload
        };
        let _ = sender.send(Ok(()));
        drop(p);
        if !rest.is_empty() {
            let s = streams.blocking_lock();
            if let Some(tx) = s.get(&stream_id) {
                let _ = tx.send(rest.to_vec());
            }
        }
        return;
    }
    drop(p);

    let s = streams.blocking_lock();
    if let Some(tx) = s.get(&stream_id) {
        let _ = tx.send(payload.to_vec());
    }
}

// ---------------------------------------------------------------------------
// VlessMuxStreamRelay
// ---------------------------------------------------------------------------

pub struct VlessMuxStreamRelay {
    stream_id: u32,
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

#[async_trait]
impl StreamRelay for VlessMuxStreamRelay {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.data_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            },
            None => Ok(0),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let frame = encode_mux_frame(MUX_DATA, self.stream_id, buf);
        self.frame_tx.send(frame).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "vless mux closed")
        })
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let frame = encode_mux_frame(MUX_RST, self.stream_id, &[]);
        let _ = self.frame_tx.send(frame);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Placeholder UDP relay (not supported in mux mode)
// ---------------------------------------------------------------------------

pub struct VlessMuxPacketRelay(());

impl VlessMuxPacketRelay {
    pub fn new() -> Self {
        Self(())
    }
}

#[async_trait]
impl PacketRelay for VlessMuxPacketRelay {
    async fn read_packet(
        &mut self, _buf: &mut [u8],
    ) -> io::Result<(usize, Destination)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP not supported over vless mux",
        ))
    }

    async fn write_packet(
        &mut self, _buf: &[u8], _dest: &Destination,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP not supported over vless mux",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: send_raw on WsStream
// ---------------------------------------------------------------------------

impl WsStream {
    pub fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WsStream::Plain(w) => w.send(data),
            WsStream::Tls(w) => w.send(data),
        }
    }
}
