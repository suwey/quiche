// SPDX-License-Identifier: BSD-2-Clause
// Copyright © The anywhere project contributors.

//! Command bus types for UI-to-backend communication.

use tokio::sync::oneshot;

/// Commands sent from the UI to the backend actor.
pub enum UiCommand {
    SetMode(u8, oneshot::Sender<bool>),
    TunSetRouting(bool, oneshot::Sender<Result<(), String>>),
    /// Reload config and restart the engine (Android: stopEngine + startEngine).
    Reload,
}

/// Events broadcast from the backend to the UI.
#[derive(Clone)]
pub enum StateEvent {
    TunRoutingChanged(bool),
}
