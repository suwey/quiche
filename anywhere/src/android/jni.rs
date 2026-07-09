//! Android JNI bridge.
//!
//! This module is the entry point for Android. It exposes C functions
//! that Kotlin calls via `external fun` declarations.
//!
//! Lifecycle:
//!   1. Kotlin calls `Java_<pkg>_EngineBridge_startEngine` with config
//!      TOML string + TUN fd + protect callback object.
//!   2. The JNI layer starts a tokio runtime and calls `anywhere::runner::run()`.
//!   3. Kotlin calls `Java_<pkg>_EngineBridge_stopEngine` to shut down.

use std::os::fd::RawFd;
use std::sync::Arc;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jstring};

use crate::inbound::tun::platform::android::{SocketProtect, set_protector};

/// Set max log level early. The actual logger is installed later by
/// `ui::log::init_android()` which creates a CompositeLogger containing
/// both AndroidLogger (for logcat) and ChannelLogger (for WebSocket).
/// We must NOT call `android_logger::init_once()` here because it sets
/// the global logger, preventing `set_boxed_logger` in `init_android()`
/// from succeeding — which would silently kill WebSocket log forwarding.
fn init_android_logger() {
    log::set_max_level(log::LevelFilter::Info);
}

/// Global runtime handle — kept alive across JNI calls.
static RUNTIME: Mutex<Option<tokio::runtime::Runtime>> = Mutex::new(None);

/// Global shutdown channel — used by stopEngine to signal the engine.
static SHUTDOWN_TX: Mutex<Option<tokio::sync::oneshot::Sender<()>>> =
    Mutex::new(None);

/// Flag set by `request_restart()` to signal that the engine should restart
/// after shutting down (rather than stopping completely).
pub static RESTART_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Stored JavaVM + VpnService global ref for restart callback.
/// The VpnService must have an `onEngineRestart()V` method.
static RESTART_CALLBACK: Mutex<Option<(jni::JavaVM, GlobalRef)>> = Mutex::new(None);

/// Signal that a restart is requested. Called from the UI's `trigger_restart`
/// on Android. Sets the flag and sends the shutdown signal so the engine
/// exits cleanly. The JNI layer then calls `onEngineRestart()` on the Kotlin
/// VpnService to restart within the same process (no process kill needed).
pub fn request_restart() {
    log::info!("Restart requested, signaling engine shutdown");
    RESTART_REQUESTED.store(true, Ordering::SeqCst);
    if let Some(tx) = SHUTDOWN_TX.lock().take() {
        let _ = tx.send(());
    }
}

/// JNI socket protector — calls Kotlin's `VpnService.protect(int)`.
struct JniSocketProtector {
    /// Global reference to the Kotlin VpnService (or a protect callback object).
    vm: jni::JavaVM,
    /// Global ref to the object that has a `protect(I)Z` method.
    protect_obj: GlobalRef,
}

impl JniSocketProtector {
    fn new(env: &JNIEnv, protect_obj: JObject) -> Result<Self, jni::errors::Error> {
        let vm = env.get_java_vm()?;
        let protect_obj = env.new_global_ref(protect_obj)?;
        Ok(Self { vm, protect_obj })
    }
}

impl SocketProtect for JniSocketProtector {
    fn protect(&self, fd: RawFd) -> bool {
        let mut env = match self.vm.attach_current_thread() {
            Ok(e) => e,
            Err(e) => {
                log::error!("JNI attach_current_thread failed: {e}");
                return false;
            }
        };

        // Call boolean protect(int fd)
        // The Kotlin side must have a method: fun protect(fd: Int): Boolean
        match env.call_method(
            &self.protect_obj,
            "protect",
            "(I)Z",
            &[JValue::Int(fd as jint)],
        ) {
            Ok(val) => val.z().unwrap_or(false),
            Err(e) => {
                log::error!("VpnService.protect() JNI call failed: {e}");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JNI exported functions
// ---------------------------------------------------------------------------

/// Start the proxy engine.
///
/// Kotlin signature:
/// ```kotlin
/// external fun startEngine(
///     config: String,    // TOML config content
///     tunFd: Int,        // TUN file descriptor from VpnService.establish()
///     cacheDir: String,  // App's filesDir path for geo rule-set downloads
///     protectObj: Any    // object with `protect(I)Z` method (usually VpnService)
/// ): Int                 // 0 on success, non-zero error code
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_startEngine(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
    tun_fd: jint,
    cache_dir: JString,
    protect_obj: JObject,
) -> jint {
    init_android_logger();
    log::info!("startEngine called, tun_fd={tun_fd}");

    // 1. Extract config string.
    let config_str: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("Failed to get config string: {e}");
            return 1;
        }
    };

    // 1b. Extract cache_dir path.
    let cache_dir_str: String = match env.get_string(&cache_dir) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("Failed to get cache_dir string: {e}");
            return 1;
        }
    };

    // 1c. Compute config file path (filesDir/anywhere.toml).
    let config_path_str = format!("{cache_dir_str}/anywhere.toml");

    // 2a. Store restart callback (JavaVM + VpnService global ref).
    // The VpnService must have an `onEngineRestart()V` method that
    // Kotlin implements to stop+start the engine in-process.
    {
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                log::error!("Failed to get JavaVM: {e}");
                return 2;
            }
        };
        let callback_ref = match env.new_global_ref(&protect_obj) {
            Ok(r) => r,
            Err(e) => {
                log::error!("Failed to create restart callback global ref: {e}");
                return 2;
            }
        };
        *RESTART_CALLBACK.lock() = Some((vm, callback_ref));
    }

    // 2. Set up the socket protector.
    let protector = match JniSocketProtector::new(&env, protect_obj) {
        Ok(p) => Arc::new(p) as Arc<dyn SocketProtect>,
        Err(e) => {
            log::error!("Failed to create JNI socket protector: {e}");
            return 2;
        }
    };
    set_protector(protector);

    // 3. Create tokio runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Failed to create tokio runtime: {e}");
            return 3;
        }
    };

    // 4. Create shutdown channel.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Store runtime + shutdown sender globally.
    {
        let mut rt_guard = RUNTIME.lock();
        if rt_guard.is_some() {
            log::warn!("Engine already running, stopping previous instance");
            drop(rt_guard.take());
        }
        *rt_guard = Some(runtime);
    }
    {
        let mut tx_guard = SHUTDOWN_TX.lock();
        *tx_guard = Some(shutdown_tx);
    }

    // 5. Spawn the engine on the runtime.
    let runtime_handle = {
        let rt_guard = RUNTIME.lock();
        rt_guard.as_ref().unwrap().handle().clone()
    };

    runtime_handle.spawn(async move {
        let opts = crate::runner::RunOptions {
            config_path: Some(config_path_str),
            config_content: Some(config_str),
            tun_fd: Some(tun_fd as RawFd),
            cache_dir: Some(cache_dir_str),
            start_cmd: None,
        };

        tokio::select! {
            result = crate::runner::run(opts) => {
                match &result {
                    Ok(()) => log::info!("Engine exited normally"),
                    Err(e) => log::error!("Engine exited with error: {e}"),
                }
            }
            _ = shutdown_rx => {
                log::info!("Engine shutdown requested");
            }
        }

        // After the engine exits, check if a restart was requested.
        // If so, call onEngineRestart() on the Kotlin VpnService from a
        // separate thread (not a tokio task) to avoid deadlock when
        // stopEngine() drops the runtime.
        if RESTART_REQUESTED.swap(false, Ordering::SeqCst) {
            log::info!("Restart requested, calling Kotlin onEngineRestart()");
            std::thread::spawn(|| {
                // Small delay to let this spawned task exit before
                // stopEngine() drops the runtime (avoids deadlock).
                std::thread::sleep(std::time::Duration::from_millis(300));
                let guard = RESTART_CALLBACK.lock();
                if let Some((vm, callback)) = guard.as_ref() {
                    match vm.attach_current_thread() {
                        Ok(mut env) => {
                            match env.call_method(callback, "onEngineRestart", "()V", &[]) {
                                Ok(_) => log::info!("Kotlin onEngineRestart() called"),
                                Err(e) => log::error!("Failed to call onEngineRestart(): {e}"),
                            }
                        }
                        Err(e) => log::error!("Failed to attach thread for restart: {e}"),
                    }
                }
            });
        }
    });

    log::info!("Engine started (fd={})", tun_fd);
    0
}

/// Stop the proxy engine.
///
/// Kotlin signature:
/// ```kotlin
/// external fun stopEngine(): Int  // 0 on success
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_stopEngine(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    // Signal shutdown.
    if let Some(tx) = SHUTDOWN_TX.lock().take() {
        let _ = tx.send(());
    }

    // Drop the runtime — this will wait for all tasks to finish.
    if let Some(rt) = RUNTIME.lock().take() {
        // Give tasks a moment to shut down gracefully.
        rt.shutdown_timeout(std::time::Duration::from_secs(10));
    }

    log::info!("Engine stopped");
    0
}

/// Get the engine version string.
///
/// Kotlin signature:
/// ```kotlin
/// external fun engineVersion(): String
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_engineVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let version = format!("anywhere v{}", env!("CARGO_PKG_VERSION"));
    match env.new_string(version) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
