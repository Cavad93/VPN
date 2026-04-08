package com.cavadvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import org.json.JSONArray
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
 * Test-runner version of TelemetryCollector (no kotlinx.coroutines).
 * Uses plain Java threads so it can run in the Maven test-runner.
 */
class TelemetryCollector(
    private val serverUrl: String,
    private val context: Context? = null,
    private val collectIntervalMs: Long = 300_000L,
    private val appVersion: String = "1.0.0",
    private val getVpnState: (() -> VpnState)? = null,
    val onConfigUpdate: ((AiConfig) -> Unit)? = null,
) {
    data class VpnState(
        val state: String = "disconnected",
        val serverAddr: String = "",
    )

    data class AiConfig(
        val transportMode: String   = "",
        val bondCount:     Int      = 0,
        val mtu:           Int      = 0,
        val paddingMode:   String   = "",
        val paddingEnabled: Boolean = false,
        val jitterMs:      Int      = 0,
        val sniHosts:      List<String> = emptyList(),
        val relayAddr:     String   = "",
    ) {
        companion object {
            fun fromJson(j: JSONObject): AiConfig {
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

    private val bytesIn           = AtomicLong(0)
    private val bytesOut          = AtomicLong(0)
    private val reconnectCount    = AtomicInteger(0)
    private val tlsErrors         = AtomicInteger(0)
    private val dpiDetected       = AtomicBoolean(false)
    private val handshakeAttempts = AtomicInteger(0)

    @Volatile var handshakeMs: Double = 0.0
    @Volatile var connectedSince: Long = 0L

    @Volatile private var transportMode: String = ""
    @Volatile private var bondCount:     Int    = 0
    @Volatile private var paddingMode:   String = ""
    @Volatile private var sniHost:       String = ""

    @Volatile private var lastConfigHash: Int = 0

    private val deviceId = generateDeviceId()

    private val pingHistory  = mutableListOf<Double>()
    private var prevBytesIn  = 0L
    private var prevBytesOut = 0L
    private var prevSampleTime = 0L

    @Volatile private var running = false
    private var thread: Thread? = null

    fun updateBytes(inBytes: Long, outBytes: Long) { bytesIn.set(inBytes); bytesOut.set(outBytes) }
    fun recordReconnect()        { reconnectCount.incrementAndGet() }
    fun recordTlsError()         { tlsErrors.incrementAndGet() }
    fun recordDpiDetection()     { dpiDetected.set(true) }
    fun recordHandshakeAttempt() { handshakeAttempts.incrementAndGet() }
    fun resetHandshakeAttempts() { handshakeAttempts.set(0) }
    fun recordConnect()          { connectedSince = System.nanoTime() }
    fun recordDisconnect()       { connectedSince = 0L }

    fun setTransportInfo(transport: String = "", bonds: Int = 0,
                         padding: String = "", sni: String = "") {
        transportMode = transport; bondCount = bonds
        paddingMode   = padding;   sniHost   = sni
    }

    fun start() {
        if (running) return
        running = true
        thread = Thread {
            Thread.sleep(30_000L.coerceAtMost(500L)) // short delay in tests
            while (running) {
                try {
                    val report = collect()
                    if (send(report)) fetchAndApplyConfig()
                } catch (_: Exception) {}
                try { Thread.sleep(collectIntervalMs) } catch (_: InterruptedException) { break }
            }
        }.also { it.isDaemon = true; it.start() }
    }

    fun stop() { running = false; thread?.interrupt(); thread = null }

    fun collectNow(): JSONObject = collect()
    fun sendNow(): Boolean = send(collect())

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
            val config = AiConfig.fromJson(JSONObject(body))
            val hash   = config.hashCode()
            if (hash != lastConfigHash) {
                lastConfigHash = hash
                onConfigUpdate.invoke(config)
            }
        } catch (_: Exception) {}
    }

    private fun collect(): JSONObject {
        val now = System.currentTimeMillis()
        var pingMs = 0.0
        var serverAddr = ""
        getVpnState?.invoke()?.let { serverAddr = it.serverAddr }
        if (serverAddr.isNotEmpty()) pingMs = measureTcpPing(serverAddr)

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

        val currentIn  = bytesIn.get()
        val currentOut = bytesOut.get()
        val elapsed    = if (prevSampleTime > 0) (now - prevSampleTime) / 1000.0 else 0.0
        var throughputIn  = 0.0
        var throughputOut = 0.0
        if (elapsed > 0) {
            throughputIn  = ((currentIn  - prevBytesIn)  * 8) / (elapsed * 1000)
            throughputOut = ((currentOut - prevBytesOut) * 8) / (elapsed * 1000)
        }
        prevBytesIn = currentIn; prevBytesOut = currentOut; prevSampleTime = now

        val cs        = connectedSince
        val uptimeSec = if (cs > 0) (System.nanoTime() - cs) / 1_000_000_000.0 else 0.0
        val connState = getVpnState?.invoke()?.state ?: "disconnected"

        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")

        return JSONObject().apply {
            put("device_id",           deviceId)
            put("platform",            "android")
            put("app_version",         appVersion)
            put("timestamp",           fmt.format(Date(now)))
            put("server_addr",         serverAddr)
            put("connection_state",    connState)
            put("uptime_sec",          uptimeSec)
            put("reconnect_count",     reconnectCount.get())
            put("handshake_ms",        handshakeMs)
            put("ping_ms",             pingMs)
            put("jitter_ms",           jitterMs)
            put("bytes_in",            currentIn)
            put("bytes_out",           currentOut)
            put("throughput_in_kbps",  throughputIn)
            put("throughput_out_kbps", throughputOut)
            put("packet_loss_percent", 0.0)
            put("retransmit_count",    0)
            put("out_of_order_count",  0)
            put("network_type",        detectNetworkType())
            put("signal_strength",     0)
            put("carrier",             "")
            put("local_ip",            "")
            put("obfs_latency_ms",     0.0)
            put("dpi_detected",        dpiDetected.get())
            put("tls_errors",          tlsErrors.get())
            put("transport_mode",      transportMode)
            put("bond_count",          bondCount)
            put("padding_mode",        paddingMode)
            put("sni_host",            sniHost)
            put("handshake_attempts",  handshakeAttempts.get())
            put("cpu_percent",         0.0)
            put("memory_mb",           0.0)
            put("battery_percent",     getBatteryPercent())
        }
    }

    private fun send(report: JSONObject): Boolean = try {
        val url  = URL("${serverUrl.trimEnd('/')}/api/v1/telemetry")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 10_000; conn.readTimeout = 10_000; conn.doOutput = true
        OutputStreamWriter(conn.outputStream).use { it.write(report.toString()) }
        val code = conn.responseCode; conn.disconnect(); code == 200
    } catch (_: Exception) { false }

    private fun generateDeviceId(): String {
        val raw    = "${Build.BOARD}|${Build.DEVICE}|${Build.MANUFACTURER}|${Build.MODEL}"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun detectNetworkType(): String {
        if (context == null) return "unknown"
        return try {
            val cm   = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val net  = cm.activeNetwork ?: return "none"
            val caps = cm.getNetworkCapabilities(net) ?: return "unknown"
            when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)      -> "vpn"
                else                                                       -> "other"
            }
        } catch (_: Exception) { "unknown" }
    }

    private fun getBatteryPercent(): Int {
        if (context == null) return 0
        return try {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        } catch (_: Exception) { 0 }
    }

    companion object {
        fun measureTcpPing(serverAddr: String, timeoutMs: Int = 5000): Double {
            return try {
                val parts = serverAddr.split(":")
                if (parts.size != 2) return 0.0
                val start = System.nanoTime()
                val sock  = Socket()
                sock.connect(InetSocketAddress(parts[0], parts[1].toInt()), timeoutMs)
                val ms = (System.nanoTime() - start) / 1_000_000.0
                sock.close(); ms
            } catch (_: Exception) { 0.0 }
        }
    }
}
