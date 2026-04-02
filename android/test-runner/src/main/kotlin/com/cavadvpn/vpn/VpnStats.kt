package com.cavadvpn.vpn

/**
 * Snapshot of VPN traffic statistics.
 *
 * @property bytesIn          Total bytes received from the server.
 * @property bytesOut         Total bytes sent to the server.
 * @property connectedSinceMs Wall-clock timestamp (ms) when the connection was established.
 * @property assignedIp       IP address assigned by the VPN server (e.g. "10.8.0.2").
 */
data class VpnStats(
    val bytesIn: Long,
    val bytesOut: Long,
    val connectedSinceMs: Long,
    val assignedIp: String
) {
    /** Elapsed time since connection, in milliseconds. */
    val uptimeMs: Long
        get() = if (connectedSinceMs <= 0L) 0L
                else System.currentTimeMillis() - connectedSinceMs

    /** Formatted uptime string "HH:MM:SS". */
    fun formatUptime(): String {
        val totalSeconds = (uptimeMs / 1000L).coerceAtLeast(0L)
        val hours   = totalSeconds / 3600
        val minutes = (totalSeconds % 3600) / 60
        val seconds = totalSeconds % 60
        return "%02d:%02d:%02d".format(hours, minutes, seconds)
    }

    companion object {
        /** An empty / zeroed-out stats object representing no active connection. */
        val EMPTY = VpnStats(
            bytesIn          = 0L,
            bytesOut         = 0L,
            connectedSinceMs = 0L,
            assignedIp       = ""
        )
    }
}

/**
 * Formats a byte count into a human-readable string with one decimal place.
 *
 * Examples:
 *   0         → "0 B"
 *   500       → "500 B"
 *   1500      → "1.5 KB"
 *   1_048_576 → "1.0 MB"
 *   1_073_741_824 → "1.0 GB"
 */
fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024L                -> "$bytes B"
        bytes < 1024L * 1024L       -> "%.1f KB".format(bytes / 1024.0)
        bytes < 1024L * 1024L * 1024L -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
        else                        -> "%.1f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
