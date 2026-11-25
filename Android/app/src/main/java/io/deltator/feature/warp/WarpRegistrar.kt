package io.deltator.feature.warp

import org.bouncycastle.util.encoders.Base64
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * WarpProfile: holds Cloudflare WARP client configuration and WireGuard credentials.
 */
data class WarpProfile(
    val privateKey: String,
    val publicKey: String,
    val addressV4: String,
    val addressV6: String,
    val peerPublicKey: String,
    val endpoint: String,
    val reserved: ByteArray,
    val accountId: String,
    val token: String
) {
    fun toJson(): String {
        val obj = JSONObject()
        obj.put("privateKey", privateKey)
        obj.put("publicKey", publicKey)
        obj.put("addressV4", addressV4)
        obj.put("addressV6", addressV6)
        obj.put("peerPublicKey", peerPublicKey)
        obj.put("endpoint", endpoint)
        obj.put("reserved", Base64.toBase64String(reserved))
        obj.put("accountId", accountId)
        obj.put("token", token)
        return obj.toString()
    }

    companion object {
        fun fromJson(jsonStr: String): WarpProfile? = try {
            val obj = JSONObject(jsonStr)
            val reservedBytes = Base64.decode(obj.optString("reserved", ""))
            WarpProfile(
                privateKey = obj.getString("privateKey"),
                publicKey = obj.getString("publicKey"),
                addressV4 = obj.optString("addressV4", "172.16.0.2/32"),
                addressV6 = obj.optString("addressV6", ""),
                peerPublicKey = obj.optString("peerPublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
                endpoint = obj.optString("endpoint", "162.159.192.1:2408"),
                reserved = reservedBytes,
                accountId = obj.optString("accountId", ""),
                token = obj.optString("token", "")
            )
        } catch (_: Exception) {
            null
        }
    }
}

/**
 * 1-Click Cloudflare WARP Auto-Registrar & Anycast Endpoint Manager.
 *
 * Proposal #3:
 * Generates Curve25519 / X25519 keypair, registers via Cloudflare client API,
 * extracts client_id (reserved bytes), and provides Anycast endpoint rotation
 * when certain IP ranges are throttled or blocked by DPI.
 */
object WarpRegistrar {
    private const val TAG = "WarpRegistrar"
    private const val REGISTRATION_URL = "https://api.cloudflareclient.com/v0a2158/reg"

    // Official Cloudflare Anycast IP pool for DPI bypass rotation
    val ANYCAST_ENDPOINTS = listOf(
        "engage.cloudflareclient.com:2408",
        "162.159.192.1:2408",
        "162.159.193.1:2408",
        "162.159.195.1:2408",
        "188.114.96.1:2408",
        "188.114.97.1:2408",
        "188.114.98.1:2408",
        "188.114.99.1:2408",
        "162.159.204.1:2408",
        "162.159.192.1:500",
        "162.159.193.1:1701",
        "162.159.195.1:4500"
    )

    /**
     * Clamps a 32-byte private key per RFC 7748.
     */
    fun clampPrivateKey(privateKey: ByteArray): ByteArray {
        val clamped = privateKey.copyOf(32)
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127).toByte()
        clamped[31] = (clamped[31].toInt() or 64).toByte()
        return clamped
    }

    /**
     * Standard constant-time Montgomery Curve25519 scalar multiplication (RFC 7748):
     * Derives public key (32 bytes) from private key (32 bytes).
     */
    fun derivePublicKey(privateKey: ByteArray): ByteArray {
        val clamped = clampPrivateKey(privateKey)
        val privParams = org.bouncycastle.crypto.params.X25519PrivateKeyParameters(clamped, 0)
        return privParams.generatePublicKey().encoded
    }

    /**
     * Generate a new Curve25519 keypair with proper RFC 7748 clamping prior to Base64 encoding.
     * Returns Pair(privateKeyBase64, publicKeyBase64).
     */
    fun generateKeyPair(): Pair<String, String> {
        val random = SecureRandom()
        val rawPriv = ByteArray(32)
        random.nextBytes(rawPriv)
        val clampedPriv = clampPrivateKey(rawPriv)
        val pub = derivePublicKey(clampedPriv)
        return Base64.toBase64String(clampedPriv) to Base64.toBase64String(pub)
    }

    /**
     * Registers a new WARP profile via official API.
     */
    suspend fun registerWarp(): Result<WarpProfile> = withContext(Dispatchers.IO) {
        try {
            val (privKey, pubKey) = generateKeyPair()
            val df = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            df.timeZone = TimeZone.getTimeZone("UTC")
            val nowIso = df.format(Date())

            val payload = JSONObject().apply {
                put("key", pubKey)
                put("install_id", "")
                put("fcm_token", "")
                put("tos", nowIso)
                put("model", "Android")
                put("type", "Android")
                put("locale", "en_US")
            }

            Log.i(TAG, "Registering Cloudflare WARP client with public key $pubKey")
            val url = URL(REGISTRATION_URL)
            val proxy = if (io.deltator.AppState.state.value.torRunning) {
                java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", io.deltator.Config.proxyPort))
            } else {
                java.net.Proxy.NO_PROXY
            }
            var conn: HttpURLConnection? = null
            try {
                conn = url.openConnection(proxy) as HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 15000
                conn.readTimeout = 15000
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
                conn.setRequestProperty("User-Agent", "okhttp/3.12.1")

                conn.outputStream.use { os ->
                    OutputStreamWriter(os, Charsets.UTF_8).use { it.write(payload.toString()) }
                }

                val code = conn.responseCode
                if (code !in 200..204) {
                    val err = conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $code"
                    Log.e(TAG, "WARP registration failed: $code $err")
                    return@withContext Result.failure(RuntimeException("WARP registration error: $code $err"))
                }

                val body = conn.inputStream.bufferedReader().readText()
                val json = JSONObject(body)

                val id = json.optString("id", "")
                val token = json.optString("token", "")
                val config = json.getJSONObject("config")
                val iface = config.getJSONObject("interface")
                val addrs = iface.getJSONObject("addresses")
                val v4 = addrs.optString("v4", "172.16.0.2/32")
                val v6 = addrs.optString("v6", "")

                val peers = config.getJSONArray("peers")
                val peer0 = peers.getJSONObject(0)
                val peerPubKey = peer0.optString("public_key", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
                val endpointObj = peer0.optJSONObject("endpoint")
                val endpointHost = endpointObj?.optString("host", "162.159.192.1:2408") ?: "162.159.192.1:2408"

                // Extract reserved bytes: client_id in Cloudflare API is 3 bytes (encoded in base64 or hex)
                val clientIdRaw = config.optString("client_id", "")
                val reservedBytes = if (clientIdRaw.isNotEmpty()) {
                    try { Base64.decode(clientIdRaw) } catch (_: Exception) { ByteArray(3) }
                } else {
                    ByteArray(3)
                }

                val profile = WarpProfile(
                    privateKey = privKey,
                    publicKey = pubKey,
                    addressV4 = v4,
                    addressV6 = v6,
                    peerPublicKey = peerPubKey,
                    endpoint = endpointHost,
                    reserved = reservedBytes,
                    accountId = id,
                    token = token
                )

                Log.i(TAG, "WARP profile successfully registered! Address: $v4, Reserved: ${reservedBytes.size} bytes")
                Result.success(profile)
            } finally {
                try { conn?.disconnect() } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            Log.e(TAG, "WARP registration exception", e)
            Result.failure(e)
        }
    }

    /**
     * Binds a WARP+ license key to an existing account.
     */
    suspend fun bindLicenseKey(accountId: String, token: String, licenseKey: String): Result<Boolean> = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        try {
            val url = URL("$REGISTRATION_URL/$accountId/account")
            conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "PUT"
            conn.connectTimeout = 15000
            conn.readTimeout = 15000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            conn.setRequestProperty("Authorization", "Bearer $token")
            val payload = JSONObject().apply {
                put("license", licenseKey)
            }
            conn.outputStream.use { os ->
                OutputStreamWriter(os, Charsets.UTF_8).use { it.write(payload.toString()) }
            }
            val code = conn.responseCode
            if (code in 200..204) {
                Log.i(TAG, "WARP+ license key successfully bound!")
                Result.success(true)
            } else {
                val err = conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $code"
                Log.w(TAG, "Failed to bind WARP+ license: $code $err")
                Result.failure(RuntimeException("License bind failed: $code $err"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error binding WARP+ license", e)
            Result.failure(e)
        } finally {
            try { conn?.disconnect() } catch (_: Exception) {}
        }
    }
}
