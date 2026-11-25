package io.deltator.tunnel

import io.deltator.util.AppLog as Log
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Shared SOCKS5 local proxy authentication handler.
 *
 * Implements RFC 1929 Username/Password Authentication for the local SOCKS5
 * listener side. When auth is enabled, clients must provide valid credentials
 * before the proxy will accept CONNECT or FWD_UDP requests.
 *
 * Uses constant-time MessageDigest.isEqual comparison to resist timing attacks.
 * Disallows silent fallback to NO AUTH (0x05, 0x00) unless explicitly allowed (allowNoAuth = true).
 */
object LocalProxyAuth {
    private const val TAG = "LocalProxyAuth"

    /**
     * Generates random one-time session credentials via CSPRNG.
     */
    fun generateSessionCredentials(): Pair<String, String> {
        val random = SecureRandom()
        val userBytes = ByteArray(16)
        val passBytes = ByteArray(16)
        random.nextBytes(userBytes)
        random.nextBytes(passBytes)
        val user = userBytes.joinToString("") { "%02x".format(it) }
        val pass = passBytes.joinToString("") { "%02x".format(it) }
        return user to pass
    }

    /**
     * Handle SOCKS5 greeting authentication after VER, NMETHODS, and METHODS
     * have been read from the client.
     *
     * @param methods The authentication methods offered by the client
     * @param input Client input stream
     * @param output Client output stream
     * @param username Required username
     * @param password Required password
     * @param allowNoAuth Whether unauthenticated NO AUTH (0x05, 0x00) is permitted
     * @return true if authentication succeeded (or was explicitly allowed without auth), false if rejected
     */
    fun handleGreeting(
        methods: ByteArray,
        input: InputStream,
        output: OutputStream,
        username: String?,
        password: String?,
        allowNoAuth: Boolean = false
    ): Boolean {
        val hasCredentials = !username.isNullOrEmpty() && !password.isNullOrEmpty()

        if (!hasCredentials) {
            if (allowNoAuth && methods.contains(0x00.toByte())) {
                output.write(byteArrayOf(0x05, 0x00))
                output.flush()
                return true
            }
            Log.w(TAG, "Rejecting client: credentials required but not configured (NO AUTH disabled)")
            output.write(byteArrayOf(0x05, 0xFF.toByte()))
            output.flush()
            return false
        }

        // Check if client supports USERNAME/PASSWORD (0x02)
        if (!methods.contains(0x02.toByte())) {
            Log.d(TAG, "Client does not support USERNAME/PASSWORD auth, rejecting")
            output.write(byteArrayOf(0x05, 0xFF.toByte()))
            output.flush()
            return false
        }

        // Select USERNAME/PASSWORD auth method
        output.write(byteArrayOf(0x05, 0x02))
        output.flush()

        // RFC 1929 subnegotiation
        val authVer = input.read()
        if (authVer != 0x01) {
            Log.w(TAG, "Invalid auth subnegotiation version: $authVer")
            output.write(byteArrayOf(0x01, 0x01)) // failure
            output.flush()
            return false
        }

        val uLen = input.read()
        if (uLen < 0) return false
        val uBytes = ByteArray(uLen)
        readExactly(input, uBytes)

        val pLen = input.read()
        if (pLen < 0) return false
        val pBytes = ByteArray(pLen)
        readExactly(input, pBytes)

        val expectedUser = username.toByteArray(Charsets.UTF_8)
        val expectedPass = password.toByteArray(Charsets.UTF_8)

        val userMatch = MessageDigest.isEqual(uBytes, expectedUser)
        val passMatch = MessageDigest.isEqual(pBytes, expectedPass)

        return if (userMatch && passMatch) {
            output.write(byteArrayOf(0x01, 0x00))
            output.flush()
            true
        } else {
            Log.w(TAG, "Authentication failed for local proxy client")
            output.write(byteArrayOf(0x01, 0x01))
            output.flush()
            false
        }
    }

    private fun readExactly(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.IOException("Unexpected end of stream during auth")
            off += n
        }
    }
}
