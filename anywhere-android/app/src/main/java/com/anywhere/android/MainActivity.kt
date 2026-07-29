package com.anywhere.android

import android.content.Intent
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.PlatformTextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.net.InetAddress
import java.net.NetworkInterface

private val AnywhereBlack = Color(0xFF000000)
private val AnywhereWhite = Color(0xFFFFFFFF)
private val AnywhereYellow = Color(0xFFFF9900)
private const val UI_POLL_TIMEOUT_SEC = 90

/**
 * Main screen: Start/Stop VPN + Web UI access info.
 */
class MainActivity : ComponentActivity() {

    private var isRunning = mutableStateOf(false)
    private var uiUrl = mutableStateOf<String?>(null)
    private var uiReady = mutableStateOf(false)
    private var startCountdown = mutableStateOf(0) // 0=idle, 1-30=counting, -1=failed
    private var notices = mutableStateOf<List<Pair<String, String>>>(emptyList()) // (level, msg)
    private var uiPollThread: Thread? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = AnywhereBlack
                ) {
                    MainScreen(
                        isRunning = isRunning.value,
                        uiUrl = uiUrl.value,
                        uiReady = uiReady.value,
                        startCountdown = startCountdown.value,
                        notices = notices.value,
                        onStart = { startVpn() },
                        onStop = { stopVpn() },
                        onOpenUi = { url ->
                            startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
                        }
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Read engine status JSON for notices (always refresh).
        notices.value = readEngineNotices()

        // If a readiness poll is already running (started by startVpnService,
        // e.g. just after returning from the VPN permission dialog), do NOT
        // clobber it. isVpnServiceRunning() can transiently return false right
        // after startForegroundService (the service isn't registered with
        // ActivityManager until the next main-looper iteration), which would
        // otherwise interrupt the poll and clear state. Trust the running poll.
        if (uiPollThread?.isAlive == true) {
            return
        }

        // No active poll - (re)derive state. Handles Activity recreation,
        // process-death recovery, and resume-after-background.
        val running = isVpnServiceRunning()
        isRunning.value = running
        val port = if (running) getUiPort() else 9090
        uiUrl.value = if (running) "http://${getLanIp()}:$port" else null
        if (running) {
            if (uiReady.value) {
                // UI was ready - verify it's still up (the engine may have
                // restarted while we were backgrounded, e.g. after a config
                // edit via the Web UI). If it went down, re-poll until back.
                verifyUiAndRepollIfNeeded(port)
            } else {
                startUiPolling(port)
            }
        } else {
            uiReady.value = false
            startCountdown.value = 0
        }
    }

    /**
     * Read engine_status.json written by the Rust engine or Kotlin.
     * Returns a list of (level, message) pairs.
     */
    private fun readEngineNotices(): List<Pair<String, String>> {
        return try {
            val file = java.io.File(filesDir, "engine_status.json")
            if (!file.exists()) return emptyList()
            val json = org.json.JSONObject(file.readText())
            val arr = json.optJSONArray("notices") ?: return emptyList()
            (0 until arr.length()).map { i ->
                val n = arr.getJSONObject(i)
                Pair(n.optString("level"), n.getString("msg"))
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Check whether ProxyVpnService is currently running by querying
     * ActivityManager. This survives Activity recreation.
     */
    private fun isVpnServiceRunning(): Boolean {
        val manager = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
        for (service in manager.getRunningServices(Int.MAX_VALUE)) {
            if (ProxyVpnService::class.java.name == service.service.className) {
                return true
            }
        }
        return false
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_START
        }
        startForegroundService(intent)
        isRunning.value = true
        val port = getUiPort()
        uiUrl.value = "http://${getLanIp()}:$port"
        startUiPolling(port)
    }

    private fun stopVpn() {
        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_STOP
        }
        startService(intent)
        isRunning.value = false
        uiPollThread?.interrupt()
        uiReady.value = false
        startCountdown.value = 0
    }

    /**
     * Poll the Web UI TCP port until it's open.
     *
     * Uses 127.0.0.1 to bypass VPN TUN routing. Re-reads port from config
     * each iteration (config file may be created during polling). Runs on a
     * background thread; interrupted when VPN stops.
     *
     * The engine (and thus the Web UI server) can take a while to come up -
     * especially on a cold start or after a config-edit restart. So we poll
     * eagerly for [UI_POLL_TIMEOUT_SEC] seconds; if the service is *still*
     * running past that (proxy works, UI just not up yet) we do NOT mark the
     * start as failed - we keep retrying with a backoff until the UI appears.
     */
    private fun startUiPolling(port: Int) {
        uiPollThread?.interrupt()
        uiReady.value = false
        startCountdown.value = UI_POLL_TIMEOUT_SEC
        uiPollThread = Thread {
            var elapsed = 0
            while (!Thread.currentThread().isInterrupted && isRunning.value && !uiReady.value) {
                try {
                    val p = getUiPort()
                    java.net.Socket().use { s ->
                        s.connect(java.net.InetSocketAddress("127.0.0.1", p), 1000)
                    }
                    uiReady.value = true
                    startCountdown.value = 0
                    return@Thread
                } catch (_: Exception) {}
                elapsed++
                if (elapsed < UI_POLL_TIMEOUT_SEC) {
                    startCountdown.value = UI_POLL_TIMEOUT_SEC - elapsed
                } else {
                    // Timed out but the service is still running - the proxy
                    // works, the Web UI just isn't up yet. Show "Connected"
                    // (startCountdown = 0) and keep retrying with a backoff.
                    startCountdown.value = 0
                }
                try {
                    Thread.sleep(if (elapsed < UI_POLL_TIMEOUT_SEC) 1000 else 3000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }.also { it.start() }
    }

    /**
     * One-shot verify that the Web UI is still reachable; if not, start a
     * fresh poll loop. Used on resume when [uiReady] was already true, to
     * detect an engine restart that happened while backgrounded.
     */
    private fun verifyUiAndRepollIfNeeded(port: Int) {
        Thread {
            try {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress("127.0.0.1", port), 1000)
                }
                uiReady.value = true
                startCountdown.value = 0
            } catch (_: Exception) {
                uiReady.value = false
                startUiPolling(port)
            }
        }.start()
    }

    private fun getUiPort(): Int {
        return try {
            val configFile = java.io.File(filesDir, "anywhere.toml")
            if (!configFile.exists()) return 9090
            val content = configFile.readText()
            val listenRegex = Regex("""listen\s*=\s*["']?[\d.]+:(\d+)"""")
            listenRegex.find(content)?.groupValues?.get(1)?.toIntOrNull() ?: 9090
        } catch (_: Exception) {
            9090
        }
    }

    /**
     * Get the device's LAN IP address for Web UI access.
     */
    private fun getLanIp(): String {
        return try {
            val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as? WifiManager
            val ip = wifiManager?.connectionInfo?.ipAddress
            if (ip != null && ip != 0) {
                InetAddress.getByAddress(
                    byteArrayOf(
                        (ip and 0xff).toByte(),
                        (ip shr 8 and 0xff).toByte(),
                        (ip shr 16 and 0xff).toByte(),
                        (ip shr 24 and 0xff).toByte()
                    )
                ).hostAddress ?: "127.0.0.1"
            } else {
                // Fallback: enumerate network interfaces
                val interfaces = NetworkInterface.getNetworkInterfaces()
                for (intf in interfaces) {
                    val addrs = intf.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                            return addr.hostAddress ?: "127.0.0.1"
                        }
                    }
                }
                "127.0.0.1"
            }
        } catch (e: Exception) {
            "127.0.0.1"
        }
    }
}

@Composable
private fun MainScreen(
    isRunning: Boolean,
    uiUrl: String?,
    uiReady: Boolean,
    startCountdown: Int, // 0=idle, 1-30=counting, -1=failed
    notices: List<Pair<String, String>>, // (level, msg)
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenUi: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Logo: "Any" white + "where" yellow background black text with rounded corners
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Any",
                color = AnywhereWhite,
                fontSize = 42.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-1).sp,
                lineHeight = 42.sp,
                style = TextStyle(platformStyle = PlatformTextStyle(includeFontPadding = false)),
            )
            Box(
                modifier = Modifier
                    .height(64.dp)
                    .background(AnywhereYellow, RoundedCornerShape(8.dp))
                    .padding(horizontal = 6.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "where",
                    color = AnywhereBlack,
                    fontSize = 42.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = (-1).sp,
                    style = TextStyle(platformStyle = PlatformTextStyle(includeFontPadding = false)),
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Status text
        Text(
            text = when {
                startCountdown > 0 -> "🟡 Starting... ${startCountdown}s"
                startCountdown == -1 -> "🔴 Start failed!"
                isRunning -> "🟢 Connected"
                else -> "⚪ Disconnected"
            },
            style = MaterialTheme.typography.bodyLarge,
            color = when {
                startCountdown == -1 -> Color(0xFFFF4444)
                isRunning || startCountdown > 0 -> AnywhereYellow
                else -> AnywhereWhite.copy(alpha = 0.4f)
            }
        )

        Spacer(modifier = Modifier.height(36.dp))

        // Start / Stop button
        when {
            startCountdown > 0 -> {
                Button(
                    onClick = {},
                    enabled = false,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = AnywhereWhite.copy(alpha = 0.1f),
                        contentColor = AnywhereWhite.copy(alpha = 0.4f)
                    )
                ) {
                    Text("Starting... ${startCountdown}s", fontSize = 16.sp)
                }
            }
            startCountdown == -1 -> {
                Button(
                    onClick = onStart,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = AnywhereYellow,
                        contentColor = AnywhereBlack
                    )
                ) {
                    Text("Retry Start", fontSize = 16.sp)
                }
            }
            else -> {
                Button(
                    onClick = if (isRunning) onStop else onStart,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isRunning) AnywhereWhite.copy(alpha = 0.15f)
                                        else AnywhereYellow,
                        contentColor = if (isRunning) AnywhereWhite
                                       else AnywhereBlack
                    )
                ) {
                    Text(if (isRunning) "Stop" else "Start", fontSize = 16.sp)
                }
            }
        }

        // Notices (warnings + errors unified)
        if (notices.isNotEmpty()) {
            Spacer(modifier = Modifier.height(20.dp))
            notices.forEach { (level, msg) ->
                val (icon, color) = if (level == "error") {
                    Pair("✕", Color(0xFFFF4444))
                } else {
                    Pair("⚠", AnywhereYellow)
                }
                Text(
                    text = "$icon $msg",
                    style = MaterialTheme.typography.bodySmall,
                    color = color,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp)
                )
                Spacer(modifier = Modifier.height(4.dp))
            }
        }

        // Web UI section when running
        if (isRunning && uiUrl != null && startCountdown == 0 && uiReady) {
            Spacer(modifier = Modifier.height(28.dp))

            HorizontalDivider(color = AnywhereWhite.copy(alpha = 0.1f))

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "Web Management",
                style = MaterialTheme.typography.titleMedium,
                color = AnywhereWhite.copy(alpha = 0.6f)
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = uiUrl,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.Center,
                color = AnywhereYellow,
                modifier = Modifier.fillMaxWidth()
            )

            Text(
                text = "Password: admin",
                style = MaterialTheme.typography.bodySmall,
                color = AnywhereWhite.copy(alpha = 0.3f)
            )

            Spacer(modifier = Modifier.height(14.dp))

            OutlinedButton(
                onClick = { onOpenUi(uiUrl) },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = AnywhereYellow
                )
            ) {
                Text("Open Web UI")
            }
        }
    }
}
