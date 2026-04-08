package com.cavadvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Client-side telemetry collector for Android.
 *
 * Collects network performance metrics every 5 minutes and sends them to
 * /api/v1/telemetry for AI-powered analysis.
 *
 * After each send, polls /api/v1/telemetry/config/applied and fires
 * [onConfigUpdate] if the AI has changed any settings.
 */
class TelemetryCollector(
    private val serverUrl: String,           // e.g. "http://10.8.0.1:8080"
    private val context: Context? = null,    // nullable for unit tests
    private val collectIntervalMs: Long = 300_000L, // 5 minutes
    private val appVersion: String = "1.0.0",
    private val getVpnState: (() -> VpnState)? = null,
    /** Called on IO thread when AI changes the active config. */
    val onConfigUpdate: ((AiConfig) -> Unit)? = null,
) {
    // ── Inner types ────────────────────────────────────────────────────────────

    data class VpnState(
        val state: String = "disconnected",
        val serverAddr: String = "",
    )

    /**
     * Mirror of server-side ActionableConfig.
     * Fields that are absent/zero mean "no recommendation".
     */
    data class AiConfig(
        val transportMode: String  = "",   // "tcp" or "udp"
        val bondCount:     Int     = 0,
        val mtu:           Int     = 0,
        val paddingMode:   String  = "",   // "none","light","balanced","paranoid"
        val paddingEnabled: Boolean = false,
        val jitterMs:      Int     = 0,
        val sniHosts:      List<String> = emptyList(),
        val relayAddr:     String  = "",
    ) {
        companion object {
            fun fromJson(j: JSONObject): AiConfig {
                // Server wraps in {config:{…}, applied_at:…, reason:…}
                val cfg = if (j.has("config")) j.getJSONObject("config") else j
                val sniArr = cfg.optJSONArray("sni_hosts")
                val sniHosts = if (sniArr != null) {
                    (0 until sniArr.length()).map { sniArr.getString(it) }
                } else emptyList()
                return AiConfig(
                    transportMode  = cfg.optString("transport_mode"),
                    bondCount      = cfg.optInt("bond_count"),
                    mtu            = cfg.optInt("mtu"),
                    paddingMode    = cfg.optString("padding_mode"),
                    paddingEnabled = cfg.optBoolean("padding_enabled"),
                    jitterMs       = cfg.optInt("jitter_ms"),
                    sniHosts       = sniHosts,
                    relayAddr      = cfg.optString("relay_addr"),
                )
            }
        }
    }

    // ── Counters (thread-safe) ─────────────────────────────────────────────────

    private val bytesIn           = AtomicLong(0)
    private val bytesOut          = AtomicLong(0)
    private val reconnectCount    = AtomicInteger(0)
    private val tlsErrors         = AtomicInteger(0)
    private val dpiDetected       = AtomicBoolean(false)
    private val handshakeAttempts = AtomicInteger(0)

    @Volatile var handshakeMs: Double = 0.0
    @Volatile var connectedSince: Long = 0L   // System.nanoTime() or 0

    // Transport info set by service when connecting.
    @Volatile private var transportMode: String = ""
    @Volatile private var bondCount:     Int    = 0
    @Volatile private var paddingMode:   String = ""
    @Volatile private var sniHost:       String = ""

    // AI config tracking — detect changes.
    @Volatile private var lastConfigHash: Int = 0

    private val deviceId: String = generateDeviceId()
    private var job: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Ping jitter tracking.
    private val pingHistory = mutableListOf<Double>()

    // Throughput tracking.
    private var prevBytesIn    = 0L
    private var prevBytesOut   = 0L
    private var prevSampleTime = 0L

    // ── Public API: update counters ────────────────────────────────────────────

    fun updateBytes(inBytes: Long, outBytes: Long) {
        bytesIn.set(inBytes)
        bytesOut.set(outBytes)
    }

    fun recordReconnect()      { reconnectCount.incrementAndGet() }
    fun recordTlsError()       { tlsErrors.incrementAndGet() }
    fun recordDpiDetection()   { dpiDetected.set(true) }
    fun recordHandshakeAttempt() { handshakeAttempts.incrementAndGet() }
    fun resetHandshakeAttempts() { handshakeAttempts.set(0) }

    fun recordConnect()    { connectedSince = System.nanoTime() }
    fun recordDisconnect() { connectedSince = 0L }

    /** Call after connecting to record current transport parameters. */
    fun setTransportInfo(
        transport: String = "",
        bonds: Int = 0,
        padding: String = "",
        sni: String = "",
    ) {
        transportMode = transport
        bondCount     = bonds
        paddingMode   = padding
        sniHost       = sni
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    fun start() {
        if (job?.isActive == true) return
        job = scope.launch {
            delay(30_000) // let VPN establish before first send
            while (isActive) {
                try {
                    val report = collect()
                    if (send(report)) {
                        // Poll AI config after successful send.
                        fetchAndApplyConfig()
                    }
                } catch (e: Exception) {
                    // Telemetry must never crash VPN.
                }
                delay(collectIntervalMs)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    /** Collect and return report without sending (for testing). */
    fun collectNow(): JSONObject = collect()

    /** Collect and send immediately. Returns true on success. */
    fun sendNow(): Boolean {
        val report = collect()
        return send(report)
    }

    // ── AI config polling ──────────────────────────────────────────────────────

    /**
     * Fetches /api/v1/telemetry/config/applied and fires [onConfigUpdate]
     * when the config differs from the last known state.
     */
    fun fetchAndApplyConfig() {
        if (onConfigUpdate == null) return
        try {
            val url  = URL("${serverUrl.trimEnd('/')}/api/v1/telemetry/config/applied")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod  = "GET"
            conn.connectTimeout = 8_000
            conn.readTimeout    = 8_000
            if (conn.responseCode != 200) { conn.disconnect(); return }
            val body = conn.inputStream.bufferedReader().readText()
            conn.disconnect()

            val json   = JSONObject(body)
            val config = AiConfig.fromJson(json)
            val hash   = config.hashCode()
            if (hash != lastConfigHash) {
                lastConfigHash = hash
                onConfigUpdate.invoke(config)
            }
        } catch (_: Exception) {
            // Network unavailable — silently skip.
        }
    }

    // ── Internal ───────────────────────────────────────────────────────────────

    private fun collect(): JSONObject {
        val now = System.currentTimeMillis()

        // Measure ping.
        var pingMs     = 0.0
        var serverAddr = ""
        getVpnState?.invoke()?.let { state -> serverAddr = state.serverAddr }
        if (serverAddr.isNotEmpty()) {
            pingMs = measureTcpPing(serverAddr)
        }

        // Jitter.
        var jitterMs = 0.0
        if (pingMs > 0) {
            synchronized(pingHistory) {
                pingHistory.add(pingMs)
                if (pingHistory.size > 12) pingHistory.removeAt(0)
                if (pingHistory.size >= 2) {
                    val diffs = (1 until pingHistory.size).map {
                        kotlin.math.abs(pingHistory[it] - pingHistory[it - 1])
                    }
                    jitterMs = diffs.average()
                }
            }
        }

        // Throughput.
        val currentIn  = bytesIn.get()
        val currentOut = bytesOut.get()
        val elapsed    = if (prevSampleTime > 0) (now - prevSampleTime) / 1000.0 else 0.0
        var throughputIn  = 0.0
        var throughputOut = 0.0
        if (elapsed > 0) {
            throughputIn  = ((currentIn  - prevBytesIn)  * 8) / (elapsed * 1000)
            throughputOut = ((currentOut - prevBytesOut) * 8) / (elapsed * 1000)
        }
        prevBytesIn    = currentIn
        prevBytesOut   = currentOut
        prevSampleTime = now

        // Uptime.
        val cs = connectedSince
        val uptimeSec = if (cs > 0) (System.nanoTime() - cs) / 1_000_000_000.0 else 0.0

        val connState   = getVpnState?.invoke()?.state ?: "disconnected"
        val networkType = detectNetworkType()
        val batteryPct  = getBatteryPercent()

        val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        dateFormat.timeZone = TimeZone.getTimeZone("UTC")

        return JSONObject().apply {
            // Identity
            put("device_id",        deviceId)
            put("platform",         "android")
            put("app_version",      appVersion)
            put("timestamp",        dateFormat.format(Date(now)))
            // Connection
            put("server_addr",      serverAddr)
            put("connection_state", connState)
            put("uptime_sec",       uptimeSec)
            put("reconnect_count",  reconnectCount.get())
            // Latency
            put("handshake_ms",     handshakeMs)
            put("ping_ms",          pingMs)
            put("jitter_ms",        jitterMs)
            // Throughput
            put("bytes_in",              currentIn)
            put("bytes_out",             currentOut)
            put("throughput_in_kbps",    throughputIn)
            put("throughput_out_kbps",   throughputOut)
            // Packets
            put("packet_loss_percent",   0.0)
            put("retransmit_count",      0)
            put("out_of_order_count",    0)
            // Network
            put("network_type",    networkType)
            put("signal_strength", 0)
            put("carrier",         "")
            put("local_ip",        "")
            // TLS / DPI
            put("obfs_latency_ms",     0.0)
            put("dpi_detected",        dpiDetected.get())
            put("tls_errors",          tlsErrors.get())
            // Transport info (new fields for AI analysis)
            put("transport_mode",      transportMode)
            put("bond_count",          bondCount)
            put("padding_mode",        paddingMode)
            put("sni_host",            sniHost)
            put("handshake_attempts",  handshakeAttempts.get())
            // Device
            put("cpu_percent",     0.0)
            put("memory_mb",       0.0)
            put("battery_percent", batteryPct)
        }
    }

    private fun send(report: JSONObject): Boolean {
        return try {
            val url  = URL("${serverUrl.trimEnd('/')}/api/v1/telemetry")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.connectTimeout = 10_000
            conn.readTimeout    = 10_000
            conn.doOutput       = true
            OutputStreamWriter(conn.outputStream).use { it.write(report.toString()) }
            val code = conn.responseCode
            conn.disconnect()
            code == 200
        } catch (e: Exception) {
            false
        }
    }

    private fun generateDeviceId(): String {
        val raw    = "${Build.BOARD}|${Build.DEVICE}|${Build.MANUFACTURER}|${Build.MODEL}"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun detectNetworkType(): String {
        if (context == null) return "unknown"
        return try {
            val cm      = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return "none"
            val caps    = cm.getNetworkCapabilities(network) ?: return "unknown"
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)      -> "vpn"
                else                                                       -> "other"
            }
        } catch (e: Exception) {
            "unknown"
        }
    }

    private fun getBatteryPercent(): Int {
        if (context == null) return 0
        return try {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        } catch (e: Exception) {
            0
        }
    }

    companion object {
        fun measureTcpPing(serverAddr: String, timeoutMs: Int = 5000): Double {
            return try {
                val parts = serverAddr.split(":")
                if (parts.size != 2) return 0.0
                val host = parts[0]
                val port = parts[1].toInt()
                val start = System.nanoTime()
                val sock  = Socket()
                sock.connect(InetSocketAddress(host, port), timeoutMs)
                val elapsed = (System.nanoTime() - start) / 1_000_000.0
                sock.close()
                elapsed
            } catch (e: Exception) {
                0.0
            }
        }
    }
}
