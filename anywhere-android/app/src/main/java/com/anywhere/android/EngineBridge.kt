package com.anywhere.android

/**
 * JNI bridge to the Rust anywhere engine.
 *
 * The Rust side is compiled as a cdylib (libanywhere.so) and exposes
 * these C functions via `extern "C"`.
 *
 * Lifecycle:
 *   1. User taps "Start" → MainActivity starts ProxyVpnService
 *   2. ProxyVpnService calls VpnService.establish() to get a TUN fd
 *   3. ProxyVpnService calls EngineBridge.startEngine(config, fd, this)
 *   4. Rust engine runs the proxy loop on the TUN fd
 *   5. User taps "Stop" → ProxyVpnService calls EngineBridge.stopEngine()
 */
object EngineBridge {
    init {
        System.loadLibrary("anywhere")
    }

    /**
     * Start the proxy engine.
     *
     * @param config TOML configuration string (same format as desktop config.toml)
     * @param tunFd File descriptor from VpnService.establish()
     * @param cacheDir App's filesDir path (for geo rule-set downloads)
     * @param protectObj Object with a `protect(Int): Boolean` method (usually the VpnService itself)
     * @return 0 on success, non-zero error code
     */
    external fun startEngine(config: String, tunFd: Int, cacheDir: String, protectObj: Any): Int

    /**
     * Stop the proxy engine and clean up.
     *
     * @return 0 on success
     */
    external fun stopEngine(): Int

    /**
     * Get the engine version string.
     */
    external fun engineVersion(): String
}
