// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Engine status cache — persistent state + runtime status for UI consumption.
//!
//! Architecture:
//!
//! ```text
//!   modules ──emit──→ StatusSink (trait)
//!                        │
//!                   CacheStore (impl)
//!                    ├── redb (persistent KV)
//!                    └── engine_status.json (Android UI sync)
//! ```
//!
//! - Modules only depend on `StatusSink`; they never touch redb or JSON.
//! - `CacheStore` is the single consumer that persists to redb and,
//!   on Android, syncs a JSON snapshot for Kotlin to read.
//! - Kotlin reads `engine_status.json` directly — no JNI needed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// StatusSink trait — what modules depend on
// ---------------------------------------------------------------------------

/// Trait for emitting engine status events.
///
/// Modules call `sink.emit(...)` without knowing where the data goes.
/// The concrete implementation (`CacheStore`) handles persistence.
pub trait StatusSink: Send + Sync {
    fn emit(&self, event: StatusEvent);
}

/// A no-op sink used when caching is not initialised (e.g. tests).
pub struct NullSink;

impl StatusSink for NullSink {
    fn emit(&self, _event: StatusEvent) {}
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Engine lifecycle phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePhase {
    Starting,
    LoadingConfig,
    LoadingRules,
    StartingInbound,
    Ready,
    Stopping,
}

/// Severity level for notices.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeLevel {
    Warning,
    Error,
}

/// Status events emitted by engine modules.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StatusEvent {
    Phase(EnginePhase),
    Notice { level: NoticeLevel, msg: String },
    NodeChanged { tag: String },
    ModeChanged { mode: String },
}

// ---------------------------------------------------------------------------
// JSON snapshot (what Kotlin reads)
// ---------------------------------------------------------------------------

/// A single notice line for the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notice {
    pub level: NoticeLevel,
    pub msg: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineStatus {
    pub running: bool,
    pub phase: String,
    pub started_at: Option<String>,
    pub notices: Vec<Notice>,
    pub selected_node: Option<String>,
    pub mode: String,
}

impl Default for EngineStatus {
    fn default() -> Self {
        Self {
            running: false,
            phase: "stopped".into(),
            started_at: None,
            notices: Vec::new(),
            selected_node: None,
            mode: "rule".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CacheStore — the concrete StatusSink + persistence
// ---------------------------------------------------------------------------

/// Persistent engine state stored in redb.
///
/// These survive engine restarts and process death.
mod keys {
    pub const SELECTED_NODE: &str = "selected_node";
    pub const MODE: &str = "mode";
}

/// In-memory status + persistence layer.
pub struct CacheStore {
    /// In-memory snapshot (cheap reads, no redb I/O for status queries).
    status: RwLock<EngineStatus>,
    /// redb handle for persistent KV (node selection, mode).
    db: Option<redb::Database>,
    /// Directory for `engine_status.json` (Android: filesDir; desktop: None).
    json_dir: Option<PathBuf>,
}

impl CacheStore {
    /// Open (or create) the cache store.
    ///
    /// `db_path` — path to the redb file (e.g. `filesDir/cache.db`).
    /// `json_dir` — directory to write `engine_status.json` (Android only).
    pub fn open(db_path: &Path, json_dir: Option<PathBuf>) -> Result<Self, String> {
        let db = redb::Database::create(db_path)
            .map_err(|e| format!("open cache.db: {e}"))?;

        // Ensure the "state" table exists.
        let table_def: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("state");
        let txn = db.begin_write().map_err(|e| e.to_string())?;
        txn.open_table(table_def).map_err(|e| e.to_string())?;
        txn.commit().map_err(|e| e.to_string())?;

        // Load persistent values.
        let (selected_node, mode) = {
            let table_def: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("state");
            let txn = db.begin_read().map_err(|e| e.to_string())?;
            let table = txn.open_table(table_def).map_err(|e| e.to_string())?;
            let node = table.get(keys::SELECTED_NODE)
                .ok()
                .flatten()
                .map(|v| v.value().to_string());
            let mode = table.get(keys::MODE)
                .ok()
                .flatten()
                .map(|v| v.value().to_string())
                .unwrap_or_else(|| "rule".into());
            (node, mode)
        };

        // Try to read the existing engine_status.json (written by Kotlin
        // before the engine started, e.g. permission errors).  We preserve
        // those errors so they survive the engine overwriting the file.
        let status = EngineStatus {
            selected_node,
            mode,
            ..Default::default()
        };

        Ok(Self {
            status: RwLock::new(status),
            db: Some(db),
            json_dir,
        })
    }

    /// Create a transient store with no persistence (for tests / fallback).
    pub fn ephemeral() -> Self {
        Self {
            status: RwLock::new(EngineStatus::default()),
            db: None,
            json_dir: None,
        }
    }

    /// Get a snapshot of the current engine status.
    pub fn status(&self) -> EngineStatus {
        self.status.read().clone()
    }

    // -- Persistent helpers --------------------------------------------------

    fn persist(&self, key: &str, value: &str) {
        if let Some(ref db) = self.db {
            let table_def: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("state");
            if let Ok(txn) = db.begin_write() {
                if let Ok(mut table) = txn.open_table(table_def) {
                    let _ = table.insert(key, value);
                }
                let _ = txn.commit();
            }
        }
    }

    // -- JSON sync (Android) -------------------------------------------------

    fn sync_json(&self) {
        if let Some(ref dir) = self.json_dir {
            let path = dir.join("engine_status.json");
            let snapshot = self.status.read().clone();
            if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
                let _ = std::fs::write(&path, json);
            }
        }
    }
}

impl StatusSink for CacheStore {
    fn emit(&self, event: StatusEvent) {
        {
            let mut s = self.status.write();
            match &event {
                StatusEvent::Phase(p) => {
                    s.phase = format!("{:?}", p).to_lowercase();
                    match p {
                        EnginePhase::Starting => {
                            s.running = true;
                            s.started_at = Some(chrono::Local::now().to_rfc3339());
                            s.notices.clear();
                        }
                        EnginePhase::Ready => {
                            s.phase = "ready".into();
                        }
                        EnginePhase::Stopping => {
                            s.phase = "stopping".into();
                        }
                        _ => {}
                    }
                }
                StatusEvent::Notice { level, msg } => {
                    s.notices.push(Notice {
                        level: level.clone(),
                        msg: msg.clone(),
                    });
                }
                StatusEvent::NodeChanged { tag } => {
                    s.selected_node = Some(tag.clone());
                }
                StatusEvent::ModeChanged { mode } => {
                    s.mode = mode.clone();
                }
            }
        }

        // Persist specific events to redb.
        match &event {
            StatusEvent::NodeChanged { tag } => {
                self.persist(keys::SELECTED_NODE, tag);
            }
            StatusEvent::ModeChanged { mode } => {
                self.persist(keys::MODE, mode);
            }
            _ => {}
        }

        // Sync JSON snapshot.
        self.sync_json();

        log::debug!("status event: {:?}", event);
    }
}

/// Convenience: Arc<dyn StatusSink> that modules hold.
pub type SharedSink = Arc<dyn StatusSink>;
