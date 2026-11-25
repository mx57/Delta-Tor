package io.deltator.tunnel

/**
 * Strict validator for Tor bridge lines to prevent directive injection into torrc.
 * Rejects control characters (\r, \n, \u0000), torrc config directives, and enforces
 * proper bridge line structure (known transport + endpoint, or vanilla endpoint).
 */
object BridgeLineValidator {
    private val KNOWN_TRANSPORTS = setOf(
        "obfs4", "webtunnel", "snowflake", "meek", "meek_lite", "scramblesuit", "fte", "conjure"
    )

    private val FORBIDDEN_TOKENS = setOf(
        "controlport", "socksport", "datadirectory", "exitnodes", "strictnodes",
        "cookieauthentication", "cookieauthfile", "hiddenservicedir", "hiddenserviceport"
    )

    fun isValidBridgeLine(line: String): Boolean {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.length > 2048) return false
        if (trimmed.startsWith("#") || trimmed.startsWith("//")) return false

        // Forbid newline, carriage return, null byte, or any control characters
        for (ch in trimmed) {
            if (ch < ' ' || ch > '~') return false
        }

        val tokens = trimmed.split("\\s+".toRegex()).filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return false

        // Check for injected torrc directives in tokens
        for (token in tokens) {
            val lower = token.lowercase()
            if (lower in FORBIDDEN_TOKENS || lower.startsWith("controlport=") || lower.startsWith("socksport=")) {
                return false
            }
        }

        val firstToken = tokens[0].lowercase()
        return if (firstToken in KNOWN_TRANSPORTS) {
            if (tokens.size < 2) return false
            isValidEndpoint(tokens[1])
        } else {
            // Vanilla bridge: first token must be valid endpoint (ip:port or [ipv6]:port)
            isValidEndpoint(tokens[0])
        }
    }

    private fun isValidEndpoint(endpoint: String): Boolean {
        val colon = endpoint.lastIndexOf(':')
        if (colon <= 0 || colon == endpoint.length - 1) return false
        val portStr = endpoint.substring(colon + 1)
        val port = portStr.toIntOrNull() ?: return false
        if (port !in 1..65535) return false

        val host = endpoint.substring(0, colon)
        if (host.startsWith("[") && host.endsWith("]")) {
            val ipv6 = host.substring(1, host.length - 1)
            return ipv6.isNotEmpty() && ipv6.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' }
        }
        return host.isNotEmpty() && host.all { it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' || it == '.' || it == '-' }
    }
}
