package com.cavadvpn.config

/**
 * Parses and generates QR-code configuration for CavadVPN.
 *
 * Supported formats:
 *  1. Plain JSON: `{"server":"host:port","key":"hex64","dns":"8.8.8.8","name":"optional"}`
 *  2. URI format: `cavadvpn://config?server=host:port&key=hex64&dns=8.8.8.8`
 */
object QrConfig {

    private val URI_SCHEME = "cavadvpn://config"

    /**
     * Parses a QR-code text string into [VpnConfig].
     *
     * @throws IllegalArgumentException if required fields are missing or invalid.
     */
    fun parseQrCode(text: String): VpnConfig {
        val trimmed = text.trim()
        return if (trimmed.startsWith("cavadvpn://")) {
            parseUri(trimmed)
        } else {
            parseJson(trimmed)
        }
    }

    /**
     * Encodes a [VpnConfig] to the JSON format used by QR codes.
     */
    fun toQrJson(config: VpnConfig): String {
        val serverField = "${config.serverHost}:${config.serverPort}"
        return buildString {
            append("{")
            append("\"server\":\"$serverField\"")
            append(",\"key\":\"${config.privateKeyHex}\"")
            if (config.dnsServer.isNotBlank()) {
                append(",\"dns\":\"${config.dnsServer}\"")
            }
            append("}")
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private fun parseJson(text: String): VpnConfig {
        val map = parseSimpleJson(text)

        val server = map["server"]
            ?: throw IllegalArgumentException("QR config missing 'server' field")
        val key = map["key"]
            ?: throw IllegalArgumentException("QR config missing 'key' field")

        val (host, port) = splitHostPort(server)

        validateKey(key)

        return VpnConfig(
            serverHost        = host,
            serverPort        = port,
            privateKeyHex     = key,
            serverPublicKeyHex = map["server_key"] ?: "",
            dnsServer         = map["dns"] ?: "8.8.8.8"
        )
    }

    private fun parseUri(text: String): VpnConfig {
        // cavadvpn://config?server=host:port&key=hex64&dns=8.8.8.8
        val queryStart = text.indexOf('?')
        if (queryStart < 0) {
            throw IllegalArgumentException("URI format missing query string")
        }
        val query = text.substring(queryStart + 1)
        val params = mutableMapOf<String, String>()
        for (pair in query.split("&")) {
            val eqIdx = pair.indexOf('=')
            if (eqIdx < 0) continue
            val k = uriDecode(pair.substring(0, eqIdx))
            val v = uriDecode(pair.substring(eqIdx + 1))
            params[k] = v
        }

        val server = params["server"]
            ?: throw IllegalArgumentException("URI config missing 'server' parameter")
        val key = params["key"]
            ?: throw IllegalArgumentException("URI config missing 'key' parameter")

        val (host, port) = splitHostPort(server)
        validateKey(key)

        return VpnConfig(
            serverHost        = host,
            serverPort        = port,
            privateKeyHex     = key,
            serverPublicKeyHex = params["server_key"] ?: "",
            dnsServer         = params["dns"] ?: "8.8.8.8"
        )
    }

    /**
     * Minimal JSON parser that handles flat string/number objects.
     * Avoids requiring a JSON library.
     */
    private fun parseSimpleJson(text: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        // Strip outer braces
        val inner = text.trim().trimStart('{').trimEnd('}')
        // Match "key":"value" pairs — simple regex-free state machine
        var i = 0
        while (i < inner.length) {
            // Skip whitespace
            while (i < inner.length && inner[i].isWhitespace()) i++
            if (i >= inner.length) break
            if (inner[i] != '"') { i++; continue }

            // Read key
            val (key, afterKey) = readJsonString(inner, i)
            i = afterKey

            // Skip whitespace and colon
            while (i < inner.length && (inner[i].isWhitespace() || inner[i] == ':')) i++

            // Read value (string or unquoted)
            val value: String
            val afterValue: Int
            if (i < inner.length && inner[i] == '"') {
                val (v, av) = readJsonString(inner, i)
                value = v
                afterValue = av
            } else {
                // Read until comma or end
                val start = i
                while (i < inner.length && inner[i] != ',' && inner[i] != '}') i++
                value = inner.substring(start, i).trim()
                afterValue = i
            }
            i = afterValue

            result[key] = value

            // Skip comma
            while (i < inner.length && (inner[i].isWhitespace() || inner[i] == ',')) i++
        }
        return result
    }

    /** Reads a JSON string starting at position [start] (which must point to opening '"'). */
    private fun readJsonString(s: String, start: Int): Pair<String, Int> {
        var i = start + 1 // skip opening quote
        val sb = StringBuilder()
        while (i < s.length) {
            when {
                s[i] == '\\' && i + 1 < s.length -> {
                    when (s[i + 1]) {
                        '"'  -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/'  -> sb.append('/')
                        'n'  -> sb.append('\n')
                        'r'  -> sb.append('\r')
                        't'  -> sb.append('\t')
                        else -> { sb.append('\\'); sb.append(s[i + 1]) }
                    }
                    i += 2
                }
                s[i] == '"' -> {
                    i++ // skip closing quote
                    return Pair(sb.toString(), i)
                }
                else -> {
                    sb.append(s[i])
                    i++
                }
            }
        }
        throw IllegalArgumentException("Unterminated JSON string")
    }

    private fun splitHostPort(serverField: String): Pair<String, Int> {
        val lastColon = serverField.lastIndexOf(':')
        if (lastColon < 0) throw IllegalArgumentException("server field must be host:port, got '$serverField'")
        val host = serverField.substring(0, lastColon)
        val portStr = serverField.substring(lastColon + 1)
        val port = portStr.toIntOrNull()
            ?: throw IllegalArgumentException("invalid port '$portStr' in server field '$serverField'")
        if (port !in 1..65535) throw IllegalArgumentException("port $port out of range")
        if (host.isBlank()) throw IllegalArgumentException("server host is empty")
        return Pair(host, port)
    }

    private fun validateKey(key: String) {
        if (key.length != 64) {
            throw IllegalArgumentException("key must be 64 hex characters, got ${key.length}")
        }
        if (!key.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            throw IllegalArgumentException("key must be hex-encoded")
        }
    }

    private fun uriDecode(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            if (s[i] == '+') {
                sb.append(' ')
                i++
            } else if (s[i] == '%' && i + 2 < s.length) {
                val hex = s.substring(i + 1, i + 3)
                val code = hex.toIntOrNull(16)
                if (code != null) {
                    sb.append(code.toChar())
                    i += 3
                } else {
                    sb.append(s[i])
                    i++
                }
            } else {
                sb.append(s[i])
                i++
            }
        }
        return sb.toString()
    }
}
