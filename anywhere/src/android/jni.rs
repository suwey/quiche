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
//!
//! jni 0.22 note: `JNIEnv` was split into `EnvUnowned` (FFI-safe, used for
//! native method args) and `Env` (full API, obtained via `with_env`).
//! `GlobalRef` became generic `Global<JObject<'static>>`.

use parking_lot::Mutex;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use jni::EnvUnowned;
use jni::Outcome;
use jni::objects::{Global, JClass, JObject, JString, JValue};
use jni::strings::JNIString;
use jni::sys::{jint, jstring};

use crate::inbound::tun::platform::android::{SocketProtect, set_protector};

/// Set max log level early. The actual logger is installed later by
/// `ui::log::init_android()`.
fn init_android_logger() {
    log::set_max_level(log::LevelFilter::Info);
}

/// Global runtime handle - kept alive across JNI calls.
static RUNTIME: Mutex<Option<tokio::runtime::Runtime>> = Mutex::new(None);

/// Global shutdown channel - used by stopEngine to signal the engine.
static SHUTDOWN_TX: Mutex<Option<tokio::sync::oneshot::Sender<()>>> =
    Mutex::new(None);

/// Stored JavaVM + VpnService global ref for restart callback.
/// The VpnService must have an `onEngineRestart()V` method.
static RESTART_CALLBACK: Mutex<Option<(jni::JavaVM, Global<JObject<'static>>)>> =
    Mutex::new(None);

/// Signal that a restart is requested. Called from the UI's `trigger_restart`
/// on Android.
pub fn request_restart() {
    log::info!("Restart requested, signaling engine shutdown");
    crate::runner::RESTART_REQUESTED.store(true, Ordering::SeqCst);
    if let Some(tx) = SHUTDOWN_TX.lock().take() {
        let _ = tx.send(());
    }
}

/// JNI socket protector - calls Kotlin's `VpnService.protect(int)`.
struct JniSocketProtector {
    vm: jni::JavaVM,
    protect_obj: Global<JObject<'static>>,
}

impl SocketProtect for JniSocketProtector {
    fn protect(&self, fd: RawFd) -> bool {
        // jni 0.22: attach_current_thread takes a closure with an owned Env.
        match self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<bool> {
                let val = env.call_method(
                    &self.protect_obj,
                    JNIString::from("protect"),
                    jni::jni_sig!((int) -> boolean),
                    &[JValue::Int(fd as jint)],
                )?;
                val.z()
            }) {
            Ok(b) => b,
            Err(e) => {
                log::error!("VpnService.protect() JNI call failed: {e}");
                false
            },
        }
    }
}

// ---------------------------------------------------------------------------
// JNI exported functions
// ---------------------------------------------------------------------------

/// Start the proxy engine. Returns 0 on success, non-zero error code.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_startEngine(
    mut env: EnvUnowned, _class: JClass, config: JString, tun_fd: jint,
    cache_dir: JString, protect_obj: JObject,
) -> jint {
    init_android_logger();
    log::info!("startEngine called, tun_fd={tun_fd}");

    // Extract strings + JavaVM + two global refs in one with_env closure.
    // JavaVM is not Clone, so we fetch it twice. All values are 'static/owned
    // and can escape the closure.
    let (
        config_str,
        cache_dir_str,
        vm_for_callback,
        callback_ref,
        vm_for_protector,
        protector_ref,
    ) = match env
        .with_env(|e| -> jni::errors::Result<_> {
            let config_str: String = config.try_to_string(&e)?;
            let cache_dir_str: String = cache_dir.try_to_string(&e)?;
            let vm_for_callback = e.get_java_vm()?;
            let vm_for_protector = e.get_java_vm()?;
            let callback_ref = e.new_global_ref(&protect_obj)?;
            let protector_ref = e.new_global_ref(&protect_obj)?;
            Ok((
                config_str,
                cache_dir_str,
                vm_for_callback,
                callback_ref,
                vm_for_protector,
                protector_ref,
            ))
        })
        .into_outcome()
    {
        Outcome::Ok(v) => v,
        Outcome::Err(e) => {
            log::error!("JNI setup failed: {e}");
            return 2;
        },
        Outcome::Panic(_) => {
            log::error!("JNI setup panicked");
            return 2;
        },
    };

    let config_path_str = format!("{cache_dir_str}/anywhere.toml");

    // Store restart callback.
    *RESTART_CALLBACK.lock() = Some((vm_for_callback, callback_ref));

    // Set up the socket protector.
    let protector = Arc::new(JniSocketProtector {
        vm: vm_for_protector,
        protect_obj: protector_ref,
    }) as Arc<dyn SocketProtect>;
    set_protector(protector);

    // Create tokio runtime.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Failed to create tokio runtime: {e}");
            return 3;
        },
    };

    // Create shutdown channel.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

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

    let runtime_handle = {
        let rt_guard = RUNTIME.lock();
        rt_guard.as_ref().unwrap().handle().clone()
    };

    runtime_handle.spawn(async move {
        let opts = crate::runner::RunOptions {
            config_path: Some(config_path_str),
            config_content: Some(config_str),
            #[cfg(unix)]
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
        if crate::runner::RESTART_REQUESTED.swap(false, Ordering::SeqCst) {
            log::info!("Restart requested, calling Kotlin onEngineRestart()");
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let guard = RESTART_CALLBACK.lock();
                if let Some((vm, callback)) = guard.as_ref() {
                    match vm.attach_current_thread(
                        |env| -> jni::errors::Result<()> {
                            env.call_method(
                                callback,
                                JNIString::from("onEngineRestart"),
                                jni::jni_sig!(() -> void),
                                &[],
                            )?;
                            Ok(())
                        },
                    ) {
                        Ok(_) => log::info!("Kotlin onEngineRestart() called"),
                        Err(e) => {
                            log::error!("Failed to call onEngineRestart(): {e}")
                        },
                    }
                }
            });
        }
    });

    log::info!("Engine started (fd={})", tun_fd);
    0
}

/// Stop the proxy engine. Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_stopEngine(
    _env: EnvUnowned, _class: JClass,
) -> jint {
    if let Some(tx) = SHUTDOWN_TX.lock().take() {
        let _ = tx.send(());
    }
    if let Some(rt) = RUNTIME.lock().take() {
        rt.shutdown_timeout(std::time::Duration::from_secs(10));
    }
    log::info!("Engine stopped");
    0
}

/// Get the engine version string.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_anywhere_android_EngineBridge_engineVersion(
    mut env: EnvUnowned, _class: JClass,
) -> jstring {
    let version = format!("anywhere v{}", env!("CARGO_PKG_VERSION"));
    match env
        .with_env(|e| -> jni::errors::Result<jstring> {
            Ok(e.new_string(version)?.into_raw())
        })
        .into_outcome()
    {
        Outcome::Ok(ptr) => ptr,
        _ => std::ptr::null_mut(),
    }
}
