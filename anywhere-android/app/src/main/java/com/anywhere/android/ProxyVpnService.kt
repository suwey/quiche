package com.anywhere.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * VPN service that hosts the Rust anywhere engine.
 *
 * This service:
 *   1. Establishes a VPN interface via VpnService.Builder
 *   2. Passes the TUN fd to the Rust engine via JNI
 *   3. Provides socket protection via VpnService.protect()
 *   4. Runs as a foreground service to stay alive
 */
class ProxyVpnService : VpnService() {

    companion object {
        private const val TAG = "ProxyVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "anywhere_service"
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.0.0.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_ROUTE_PREFIX = 0
        private const val VPN_DNS = "10.0.0.2"

        const val ACTION_START = "com.anywhere.android.START"
        const val ACTION_STOP = "com.anywhere.android.STOP"
        private const val PREFS_NAME = "anywhere_state"
        private const val KEY_SHOULD_RUN = "should_run"
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var engineRunning = false

    /**
     * VpnService.protect(int) is inherited from the parent class.
     * The Rust JNI layer calls it directly on this object via reflection.
     */

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand (intent=${intent?.action ?: "null (system restart)"})")

        when (intent?.action) {
            ACTION_START -> {
                setShouldRun(true)
                startVpn()
            }
            ACTION_STOP -> {
                setShouldRun(false)
                stopVpn()
                stopSelf()
            }
            null -> {
                // System restart (START_STICKY) — check if we should auto-resume
                if (getShouldRun()) {
                    Log.i(TAG, "Auto-resuming VPN after system restart")
                    startVpn()
                } else {
                    Log.i(TAG, "System restart but VPN was not running, stopping")
                    stopSelf()
                }
            }
        }

        return START_STICKY
    }

    private fun startVpn() {
        createNotificationChannel()
        val notification = createNotification("Starting...")
        startForeground(NOTIFICATION_ID, notification)

        val builder = Builder()
            .setSession("Anywhere")
            .setMtu(1500)
            .addAddress(VPN_ADDRESS, 24)
            .addRoute(VPN_ROUTE, VPN_ROUTE_PREFIX)
            .addDnsServer(VPN_DNS)
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )

        // Ensure config file exists — copy bundled default if missing
        copyDefaultConfig()
        val config = getConfig()

        // Pre-download geo rule-set files BEFORE establishing the VPN tunnel.
        // Once the TUN interface is up, all unprotected sockets get routed
        // into the TUN — but the rules engine (which decides routing) hasn't
        // started yet, creating a deadlock.  By downloading now (while the
        // physical network is still directly accessible) we break the cycle.
        //
        // NOTE: Must run on a background thread — Android forbids network
        // operations on the main thread (NetworkOnMainThreadException).
        val prefetchLatch = java.util.concurrent.CountDownLatch(1)
        Thread {
            try {
                prefetchGeoRules(config)
            } finally {
                prefetchLatch.countDown()
            }
        }.start()
        prefetchLatch.await(60, java.util.concurrent.TimeUnit.SECONDS)

        // Establish the VPN tunnel AFTER geo rules are cached.
        tunFd = builder.establish()
        if (tunFd == null) {
            Log.e(TAG, "VpnService.establish() returned null — permission denied?")
            writeEngineStatus(running = false, errors = listOf("VPN permission denied or establish failed"))
            stopSelf()
            return
        }

        val fd = tunFd!!.fd
        val cacheDir = filesDir.absolutePath
        // Ensure cache dir exists for geo rule-set downloads
        java.io.File(cacheDir, "rule_set").mkdirs()
        // Copy bundled UI assets to filesDir/ui (for ServeDir)
        copyUiAssets()
        val ret = EngineBridge.startEngine(config, fd, cacheDir, this)

        if (ret == 0) {
            engineRunning = true
            Log.i(TAG, "Engine started successfully")
            // Clear any stale errors from a previous failed attempt —
            // the engine is now running and will take over the JSON file.
            writeEngineStatus(running = true, errors = emptyList())
            updateUiNotification()
        } else {
            Log.e(TAG, "Engine failed to start (error $ret)")
            writeEngineStatus(running = false, errors = listOf("Engine failed to start (error $ret)"))
            stopVpn()
            stopSelf()
        }
    }

    private fun stopVpn() {
        if (engineRunning) {
            EngineBridge.stopEngine()
            engineRunning = false
        }

        tunFd?.close()
        tunFd = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "Engine stopped")
    }

    /**
     * Called from JNI (via a background thread) when the Rust engine requests
     * a restart (e.g. after config edit via Web UI). Posts the actual
     * stop+start to the main thread to avoid concurrency issues.
     */
    fun onEngineRestart() {
        Handler(Looper.getMainLooper()).post {
            Log.i(TAG, "Engine requested restart, restarting VPN in-process")
            stopVpn()
            startVpn()
        }
    }

    private fun setShouldRun(value: Boolean) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_SHOULD_RUN, value)
            .apply()
    }

    private fun getShouldRun(): Boolean {
        return getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .getBoolean(KEY_SHOULD_RUN, false)
    }

    /**
     * Write a minimal engine_status.json for Kotlin-side errors that occur
     * before the Rust engine is running (e.g. establish() failure).
     * Once the engine starts, Rust overwrites this file with full status.
     */
    private fun writeEngineStatus(running: Boolean, errors: List<String> = emptyList()) {
        try {
            val noticeArr = org.json.JSONArray()
            errors.forEach { msg ->
                noticeArr.put(org.json.JSONObject().apply {
                    put("level", "error")
                    put("msg", msg)
                })
            }
            val json = org.json.JSONObject().apply {
                put("running", running)
                put("phase", if (running) "ready" else "stopped")
                put("started_at", JSONObject.NULL)
                put("notices", noticeArr)
                put("selected_node", JSONObject.NULL)
                put("mode", "rule")
            }
            java.io.File(filesDir, "engine_status.json").writeText(json.toString(2))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write engine_status.json: ${e.message}")
        }
    }

    private fun getConfig(): String {
        val configFile = java.io.File(filesDir, "anywhere.toml")
        return if (configFile.exists()) {
            val content = configFile.readText()
            // Parse UI port from config for notification display
            val listenRegex = Regex("""listen\s*=\s*["']?[\d.]+:(\d+)"""")
            uiPort = listenRegex.find(content)?.groupValues?.get(1)?.toIntOrNull() ?: 9090
            content
        } else {
            Log.w(TAG, "No config file found at ${configFile.absolutePath}, using minimal default")
            generateDefaultConfig()
        }
    }

    /**
     * Find an available TCP port starting from [start], trying up to [maxTries] ports.
     * Returns the available port number, or [start] if none found (fallback).
     */
    private fun findAvailablePort(start: Int = 9090, maxTries: Int = 20): Int {
        for (port in start until start + maxTries) {
            try {
                java.net.ServerSocket(port).use { it.reuseAddress = true }
                Log.i(TAG, "Found available UI port: $port")
                return port
            } catch (_: Exception) {
                Log.d(TAG, "Port $port in use, trying next...")
            }
        }
        Log.w(TAG, "No available port in range $start..${start + maxTries - 1}, using $start")
        return start
    }

    /**
     * Generate the default config with Android-appropriate paths.
     *
     * All paths are derived from the app's filesDir:
     *   - Config file:   filesDir/anywhere.toml
     *   - Cache dir:     filesDir/          (for geo rule-set downloads)
     *   - UI serve_path: filesDir/ui        (for static web assets, if any)
     *
     * The UI listen port is dynamically chosen to avoid conflicts.
     * The selected port is stored in [uiPort] for notification display.
     */
    private var uiPort: Int = 9090

    private fun generateDefaultConfig(): String {
        val baseDir = filesDir.absolutePath
        uiPort = findAvailablePort()
        return """
        [dns]
        remote = "1.1.1.1"
        direct = "223.5.5.5"

        [ui]
        listen = "0.0.0.0:$uiPort"
        secret = "admin"
        serve_path = "$baseDir/ui"

        [common]
        cache_dir = "$baseDir"

        [[inbounds]]
        type = "tun"
        addr = "10.0.0.1/24"
        mtu = 1500

        [[outbounds]]
        type = "direct"
        tag = "direct"

        [[rules]]
        type = "default"
        outbound = "direct"
        """.trimIndent()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Anywhere",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Proxy service"
            setShowBadge(false)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    /**
     * Get the device's primary local IP address (non-loopback, non-VPN).
     * Falls back to the VPN interface address if no other IP is found.
     */
    private fun getLocalIpAddress(): String {
        try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            var bestIp: String? = null
            for (intf in interfaces) {
                // Skip VPN interface and loopback
                if (intf.isUp && !intf.isLoopback) {
                    val name = intf.name.lowercase()
                    // Skip tun/wlan0 is fine but prefer wlan/eth over tun
                    val isVpn = name.contains("tun") || name.contains("ppp")
                    for (addr in intf.inetAddresses) {
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            val ip = addr.hostAddress ?: continue
                            if (!isVpn) {
                                // Prefer non-VPN interfaces (wifi/eth)
                                return ip
                            }
                            if (bestIp == null) {
                                bestIp = ip
                            }
                        }
                    }
                }
            }
            if (bestIp != null) return bestIp
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get local IP: ${e.message}")
        }
        return VPN_ADDRESS  // fallback to 10.0.0.1
    }

    private fun createNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Anywhere")
            .setContentText(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /**
     * Build a notification that shows process status + UI URL.
     * Tapping opens the management UI in browser.
     */
    private fun createUiNotification(): Notification {
        val ip = getLocalIpAddress()
        val url = "http://$ip:$uiPort"
        Log.i(TAG, "UI URL: $url")

        val openIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        val pendingIntent = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val status = if (engineRunning) "🟢 Running" else "🔴 Stopped"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Anywhere  ·  $status")
            .setContentText(url)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createNotification(text))
    }

    private fun updateUiNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createUiNotification())
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by user")
        stopVpn()
        stopSelf()
    }

    /**
     * Pre-download geo rule-set (.srs) files referenced in the config before
     * the VPN tunnel is established.
     *
     * This breaks the startup deadlock: once the TUN interface is up, all
     * unprotected sockets are routed into the TUN, but the rules engine
     * (which governs TUN routing) hasn't started yet.  By fetching the files
     * now — while the physical network is still directly reachable – the
     * Rust engine can load them from cache on startup.
     *
     * Files that already exist in the cache directory are skipped.
     */
    private fun prefetchGeoRules(config: String) {
        val ruleSetDir = java.io.File(filesDir, "rule_set")
        if (!ruleSetDir.exists()) ruleSetDir.mkdirs()

        // Extract geo_url values from the TOML config.
        val urlRegex = Regex("""geo_url\s*=\s*["']([^"']+)["']""")
        val urls = urlRegex.findAll(config).map { it.groupValues[1] }.toList()

        if (urls.isEmpty()) return

        for (url in urls) {
            // Derive the cache filename the same way the Rust engine does:
            // sanitize every non-alphanumeric char to '_', append ".srs".
            val filename = url.toCharArray().joinToString("") { c ->
                if (c.isLetterOrDigit() || c == '-' || c == '_' || c == '.') c.toString() else "_"
            } + ".srs"
            val cacheFile = java.io.File(ruleSetDir, filename)
            if (cacheFile.exists()) {
                Log.i(TAG, "Geo rule cache hit: $filename")
                continue
            }

            try {
                Log.i(TAG, "Pre-downloading geo rule: $url")
                val connection = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                connection.connectTimeout = 15_000
                connection.readTimeout = 30_000
                connection.requestMethod = "GET"
                connection.connect()

                if (connection.responseCode == 200) {
                    connection.inputStream.use { input ->
                        cacheFile.outputStream().use { output -> input.copyTo(output) }
                    }
                    Log.i(TAG, "Cached geo rule: $filename (${cacheFile.length()} bytes)")
                } else {
                    Log.w(TAG, "Failed to fetch $url: HTTP ${connection.responseCode}")
                }
                connection.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pre-download geo rule $url", e)
            }
        }
    }

    /**
     * Copy the bundled default config (assets/config/anywhere.toml) to
     * filesDir/anywhere.toml. Skipped if the user already has a config file
     * (e.g. from a previous run or manually edited via the Web UI).
     */
    private fun copyDefaultConfig() {
        val configFile = java.io.File(filesDir, "anywhere.toml")
        if (configFile.exists()) {
            Log.i(TAG, "Config file already exists at ${configFile.absolutePath}, skipping bundled copy")
            return
        }
        try {
            assets.open("config/anywhere.toml").use { input ->
                configFile.outputStream().use { output -> input.copyTo(output) }
            }
            Log.i(TAG, "Bundled config copied to ${configFile.absolutePath}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to copy bundled config: ${e.message}")
        }
    }

    /**
     * Copy bundled UI assets (metacubexd) to filesDir/ui.
     * Recursively copies all files from assets/ui/ to filesDir/ui/.
     * Existing files are skipped (idempotent across restarts).
     */
    private fun copyUiAssets() {
        val uiDir = java.io.File(filesDir, "ui")
        if (!uiDir.exists()) uiDir.mkdirs()
        var copied = 0

        // Map asset dir names to output dir names (handle AAPT excluding '_' prefix)
        val dirRename = mapOf("nuxt" to "_nuxt", "fonts" to "_fonts")

        fun copyTree(assetPrefix: String, outDir: java.io.File) {
            val children = assets.list(assetPrefix) ?: return
            for (name in children) {
                val assetPath = "$assetPrefix/$name"
                val subChildren = assets.list(assetPath) ?: emptyArray()
                if (subChildren.isEmpty()) {
                    // It's a file — always overwrite to ensure freshness
                    val outFile = java.io.File(outDir, name)
                    try {
                        outFile.parentFile?.mkdirs()
                        assets.open(assetPath).use { input ->
                            outFile.outputStream().use { output -> input.copyTo(output) }
                        }
                        copied++
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to copy: $assetPath — ${e.message}")
                    }
                } else {
                    // It's a directory — apply rename if needed
                    val outName = dirRename[name] ?: name
                    val subDir = java.io.File(outDir, outName)
                    if (!subDir.exists()) subDir.mkdirs()
                    copyTree(assetPath, subDir)
                }
            }
        }

        try {
            copyTree("ui", uiDir)
            Log.i(TAG, "UI assets copied: $copied files to ${uiDir.absolutePath}")
        } catch (e: Exception) {
            Log.e(TAG, "copyUiAssets failed: ${e.message}")
        }
    }
}
