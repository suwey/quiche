use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use log::LevelFilter;
use log::Metadata;
use log::Record;
use serde::Serialize;
use std::time::Instant;
use tokio::sync::broadcast;

use parking_lot::Mutex;

static LOG_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Global broadcast sender for log messages. Swapped on engine restart
/// so the WebSocket subscriber always gets the current channel.
static LOG_CHANNEL: Mutex<Option<broadcast::Sender<LogMsg>>> = Mutex::new(None);

/// Ensures the global logger is only installed once.
static LOGGER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Return the currently configured log level as a string (e.g. "error",
/// "info").
pub fn current_level() -> &'static str {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        5 => "trace",
        _ => "info",
    }
}

/// A log message forwarded to the UI via WebSocket,
/// pre-formatted as `{"type": level, "payload": "[tid elapsed] target:
/// message"}`.
#[derive(Clone, Debug, Serialize)]
pub struct LogMsg {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

/// Logger that forwards records to the global broadcast channel.
/// The channel is swappable via `LOG_CHANNEL` so engine restarts can
/// replace it without reinstalling the global logger.
struct ChannelLogger {
    start: Instant,
}

impl log::Log for ChannelLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let elapsed = self.start.elapsed();
        let tid = std::thread::current().id();
        let payload = format!(
            "[{tid:?} {elapsed:.1?}] {}: {}",
            record.target(),
            record.args()
        );

        let msg = LogMsg {
            level: record.level().to_string().to_lowercase(),
            payload,
        };
        let guard = LOG_CHANNEL.lock();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(msg);
        }
    }

    fn flush(&self) {}
}

/// Composite logger that dispatches to multiple inner loggers.
struct CompositeLogger {
    loggers: Vec<Box<dyn log::Log>>,
    max_level: LevelFilter,
}

impl log::Log for CompositeLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        for logger in &self.loggers {
            logger.log(record);
        }
    }

    fn flush(&self) {
        for logger in &self.loggers {
            logger.flush();
        }
    }
}

/// Android: create broadcast channel and install composite logger.
/// The logger (AndroidLogger for logcat + ChannelLogger for WebSocket)
/// is installed only once. On engine restart, `init_android()` is called
/// again - the global logger stays installed but `LOG_CHANNEL` is swapped
/// so the WebSocket subscriber gets the new channel.
#[cfg(target_os = "android")]
pub fn init_android() -> broadcast::Sender<LogMsg> {
    use android_logger::AndroidLogger;

    let (tx, _) = broadcast::channel(256);
    *LOG_CHANNEL.lock() = Some(tx.clone());

    if !LOGGER_INSTALLED.swap(true, Ordering::SeqCst) {
        let max_level = std::env::var("RUST_LOG")
            .ok()
            .and_then(|s| s.parse::<LevelFilter>().ok())
            .unwrap_or(LevelFilter::Info);

        let android_log = AndroidLogger::new(
            android_logger::Config::default()
                .with_max_level(max_level)
                .with_tag("anywhere"),
        );

        let channel_logger = ChannelLogger {
            start: Instant::now(),
        };

        let composite = CompositeLogger {
            loggers: vec![
                Box::new(android_log) as Box<dyn log::Log>,
                Box::new(channel_logger),
            ],
            max_level,
        };

        log::set_boxed_logger(Box::new(composite)).ok();
    }

    let max_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::Info);
    log::set_max_level(max_level);
    LOG_LEVEL.store(max_level as u8, Ordering::Relaxed);

    tx
}

/// Initialize logging with env_logger (stderr) and a broadcast channel
/// that WS clients can subscribe to. Returns the broadcast sender.
/// The logger is installed only once; on restart, only the channel is swapped.
#[cfg(not(target_os = "android"))]
pub fn init() -> broadcast::Sender<LogMsg> {
    let (tx, _) = broadcast::channel(256);
    *LOG_CHANNEL.lock() = Some(tx.clone());

    if !LOGGER_INSTALLED.swap(true, Ordering::SeqCst) {
        let env_logger = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .format(|buf, record| {
            use std::io::Write;
            let ts = chrono::Local::now();
            let level = record.level().as_str();
            let target = record.target();
            writeln!(
                buf,
                "{} [{level:5} {target}] {}",
                ts.format("%Y-%m-%d %H:%M:%S"),
                record.args()
            )
        })
        .build();

        let max_level = env_logger.filter();

        let channel_logger = ChannelLogger {
            start: Instant::now(),
        };

        let composite = CompositeLogger {
            loggers: vec![
                Box::new(env_logger) as Box<dyn log::Log>,
                Box::new(channel_logger),
            ],
            max_level,
        };

        log::set_boxed_logger(Box::new(composite)).ok();
    }

    // Read level from RUST_LOG for set_max_level (env_logger handles
    // per-module filtering internally, this is just the global ceiling)
    let max_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::Info);

    log::set_max_level(max_level);
    LOG_LEVEL.store(max_level as u8, Ordering::Relaxed);

    tx
}
