// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Global application context shared across inbounds, UI, and other subsystems.
//!
//! [`AppContext`] bundles the core singletons that every inbound and the UI
//! needs — outbound registry, rules engine, statistics, command bus, and TUN
//! routing control — into one `Arc`-wrappable struct.

use std::collections::HashMap;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;

use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::command::StateEvent;
use crate::command::UiCommand;
use crate::outbound::registry::OutboundRegistry;
use crate::outbound::urltest::UrlTestState;
use crate::rules::Rules;
use crate::ui::log::LogMsg;
use crate::ui::state::AppStats;

#[cfg(target_os = "linux")]
use crate::inbound::tun::TunRouteManager;

/// Global application context.
///
/// Every field is cheaply cloneable so the context can be shared across tasks
/// without additional `Arc` nesting.
pub struct AppContext {
    pub registry: Arc<OutboundRegistry>,
    pub rules: Arc<Rules>,
    pub stats: Arc<AppStats>,
    pub logs_tx: broadcast::Sender<LogMsg>,
    pub start_cmd: Option<String>,
    pub outbound_tags: Vec<(String, String)>,
    pub urltest_states: HashMap<String, Arc<UrlTestState>>,
    pub cmd_tx: mpsc::Sender<UiCommand>,
    pub event_tx: broadcast::Sender<StateEvent>,
    /// Absolute path to the config file (for reload/restart).
    /// Always set to an absolute path — resolved from -c argument,
    /// inline content fallback, or Android filesDir.
    pub config_path: Option<String>,
    #[cfg(target_os = "linux")]
    tun_mgr: Option<Arc<Mutex<TunRouteManager>>>,
}
impl Clone for AppContext {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            rules: self.rules.clone(),
            stats: self.stats.clone(),
            logs_tx: self.logs_tx.clone(),
            start_cmd: self.start_cmd.clone(),
            outbound_tags: self.outbound_tags.clone(),
            urltest_states: self.urltest_states.clone(),
            cmd_tx: self.cmd_tx.clone(),
            event_tx: self.event_tx.clone(),
            config_path: self.config_path.clone(),
            #[cfg(target_os = "linux")]
            tun_mgr: self.tun_mgr.clone(),
        }
    }
}

impl AppContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<OutboundRegistry>, rules: Arc<Rules>, stats: Arc<AppStats>,
        logs_tx: broadcast::Sender<LogMsg>, start_cmd: Option<String>,
        outbound_tags: Vec<(String, String)>,
        urltest_states: HashMap<String, Arc<UrlTestState>>,
        cmd_tx: mpsc::Sender<UiCommand>, event_tx: broadcast::Sender<StateEvent>,
    ) -> Self {
        Self {
            registry,
            rules,
            stats,
            logs_tx,
            start_cmd,
            outbound_tags,
            urltest_states,
            cmd_tx,
            event_tx,
            config_path: None,
            #[cfg(target_os = "linux")]
            tun_mgr: None,
        }
    }

    /// Inject the TUN manager after TUN initialization.
    #[cfg(target_os = "linux")]
    pub fn set_tun_mgr(&mut self, mgr: Arc<Mutex<TunRouteManager>>) {
        self.tun_mgr = Some(mgr);
    }

    /// Set the config file path (for reload support).
    pub fn set_config_path(&mut self, path: Option<String>) {
        self.config_path = path;
    }

    /// Set the routing mode. When TUN is active, automatically enables routing
    /// for `rule`/`global` modes and disables it for `direct` mode.
    pub fn set_mode(&self, mode: u8) -> bool {
        let changed = self.rules.set_mode(mode);
        if changed {
            match mode {
                // direct → disable TUN routing (traffic goes directly to WAN).
                1 => {
                    let _ = self.tun_routing_disable();
                },
                // rule / global → enable TUN routing.
                0 | 2 => {
                    let _ = self.tun_routing_enable();
                },
                _ => {},
            }
        }
        changed
    }

    /// Enable TUN capture using the manager's `auto_hijack` setting.
    #[cfg(target_os = "linux")]
    pub fn tun_routing_enable(&self) -> Result<(), String> {
        let mgr = self.tun_mgr.as_ref().ok_or("TUN manager not available")?;
        let mut mgr = mgr.lock().map_err(|e| e.to_string())?;
        let auto_hijack = mgr.auto_hijack;
        mgr.enable_tun_capture(auto_hijack).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Disable TUN capture without tearing down bypass rules.
    #[cfg(target_os = "linux")]
    pub fn tun_routing_disable(&self) -> Result<(), String> {
        let mgr = self.tun_mgr.as_ref().ok_or("TUN manager not available")?;
        let mut mgr = mgr.lock().map_err(|e| e.to_string())?;
        mgr.disable_tun_capture();
        Ok(())
    }

    /// Check whether TUN routing is currently enabled.
    #[cfg(target_os = "linux")]
    pub fn tun_routing_enabled(&self) -> bool {
        self.tun_mgr
            .as_ref()
            .and_then(|mgr| mgr.lock().ok())
            .map(|mgr| mgr.tun_capture.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// TUN routing is not available on non-Linux/Android.
    #[cfg(not(target_os = "linux"))]
    pub fn tun_routing_enabled(&self) -> bool {
        false
    }

    /// Enable TUN routing (no-op on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn tun_routing_enable(&self) -> Result<(), String> {
        Err("TUN routing is only supported on Linux".into())
    }

    /// Disable TUN routing (no-op on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn tun_routing_disable(&self) -> Result<(), String> {
        Err("TUN routing is only supported on Linux".into())
    }
}
