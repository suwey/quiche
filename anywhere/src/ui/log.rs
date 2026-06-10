use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use log::LevelFilter;
use log::Metadata;
use log::Record;
use serde::Serialize;
use std::time::Instant;
use tokio::sync::broadcast;

static LOG_LEVEL: AtomicU8 = AtomicU8::new(0);

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

/// Logger that forwards records to a broadcast channel.
struct ChannelLogger {
    tx: broadcast::Sender<LogMsg>,
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
        let _ = self.tx.send(msg);
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

/// Initialize logging with both env_logger (stderr) and a channel that WS
/// clients can subscribe to. Returns the broadcast sender for log messages.
///
/// This replaces the default env_logger; call it **instead of**
/// `env_logger::init()`.
pub fn init() -> broadcast::Sender<LogMsg> {
    let (tx, _) = broadcast::channel(256);

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
        tx: tx.clone(),
        start: Instant::now(),
    };

    let composite = CompositeLogger {
        loggers: vec![
            Box::new(env_logger) as Box<dyn log::Log>,
            Box::new(channel_logger),
        ],
        max_level,
    };

    log::set_boxed_logger(Box::new(composite)).expect("logger already set");
    log::set_max_level(max_level);

    LOG_LEVEL.store(max_level as u8, Ordering::Relaxed);

    tx
}
