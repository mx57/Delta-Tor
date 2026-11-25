package io.deltator

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest

/**
 * Checks GitHub for a newer DeltaTor release and takes the update the rest of
 * the way instead of only pointing at the release page: the APK matching this
 * device's ABI is downloaded into the private updates folder while the in-app
 * banner shows the progress, and the finished file is handed to the system
 * installer -- on the tap after the download, and by itself on every later
 * launch while the file is still there.
 */
object ReleaseChecker {
    private const val TAG = "ReleaseChecker"
    private val REPO: String = BuildConfig.RELEASE_REPO.ifBlank { "mx57/Delta-Tor" }
    private val API_LATEST: String get() = "https://api.github.com/repos/$REPO/releases/latest"
    private val GITHUB_URL: String get() = "https://github.com/$REPO"
    private const val UPDATES_DIR = "updates"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stateMutex = Mutex()

    private var downloadJob: Job? = null
    private var apkUrl = ""
    private var apkSize = 0L
    private var apkFile: File? = null
    private var apkTag = ""
    private var apkExpectedSha256 = ""

    private fun getProxy(): Proxy {
        return if (AppState.state.value.torRunning) {
            Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", Config.proxyPort))
        } else {
            Proxy.NO_PROXY
        }
    }

    fun openInBrowser(context: Context, url: String) {
        try {
            val target = if (url.isNotBlank() && url.startsWith("https://github.com/")) {
                url
            } else {
                GITHUB_URL
            }
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(target))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        } catch (e: Exception) {
            Log.w(TAG, "Could not open browser: ${e.message}")
        }
    }

    suspend fun check(context: Context): Boolean = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        try {
            conn = URL(API_LATEST).openConnection(getProxy()) as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "DeltaTor-Android")
            val code = conn.responseCode
            if (code != 200) {
                Log.w(TAG, "Update check HTTP $code")
                AppState.updateRelease { it.copy(checking = false) }
                return@withContext false
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val tag = json.optString("tag_name").trim().removePrefix("v")
            var htmlUrl = json.optString("html_url").trim()
            if (!htmlUrl.startsWith("https://github.com/$REPO/releases/")) {
                htmlUrl = "$GITHUB_URL/releases/tag/$tag"
            }
            val assetInfo = pickAsset(json, tag)
            val name = assetInfo?.first ?: ""
            val url = assetInfo?.second ?: ""
            val size = assetInfo?.third ?: 0L

            val current = BuildConfig.VERSION_NAME.trim().removePrefix("v")
            val newer = tag.isNotEmpty() && name.isNotEmpty() && compareVersions(current, tag) < 0
            Log.i(TAG, "Latest release: $tag (current $current, newer=$newer, apk=$name)")

            if (!newer) {
                AppState.updateRelease {
                    it.copy(
                        checking = false,
                        latestVersion = tag,
                        latestUrl = htmlUrl,
                        newer = false,
                        phase = "idle",
                        bytes = 0L,
                        totalBytes = 0L,
                        autoPrompt = false,
                        lastError = ""
                    )
                }
                pruneUpdates(context, keep = null)
                return@withContext true
            }

            val dir = File(context.filesDir, UPDATES_DIR)
            dir.mkdirs()
            val cleanName = File(name).name
            val file = File(dir, cleanName)
            if (!file.canonicalPath.startsWith(dir.canonicalPath + File.separator)) {
                Log.e(TAG, "Path traversal attempt detected in asset: $name")
                AppState.updateRelease { it.copy(checking = false, lastError = "Invalid asset filename") }
                return@withContext false
            }

            stateMutex.withLock {
                apkUrl = url
                apkSize = size
                apkTag = tag
                apkFile = file
                apkExpectedSha256 = ""
            }

            File(dir, "$cleanName.part").delete()

            if (file.exists() && (size <= 0L || file.length() == size)) {
                if (verifyApkSignature(context, file)) {
                    AppState.updateRelease {
                        it.copy(
                            checking = false,
                            latestVersion = tag,
                            latestUrl = htmlUrl,
                            newer = true,
                            phase = "ready",
                            bytes = file.length(),
                            totalBytes = file.length(),
                            autoPrompt = true,
                            lastError = ""
                        )
                    }
                    notifyReady(context, tag)
                    Log.i(TAG, "Update apk already on disk and verified: ${file.name}")
                    return@withContext true
                } else {
                    Log.w(TAG, "Existing cached apk failed signature check; re-downloading")
                    file.delete()
                }
            }

            AppState.updateRelease {
                it.copy(
                    checking = false,
                    latestVersion = tag,
                    latestUrl = htmlUrl,
                    newer = true,
                    phase = "downloading",
                    bytes = 0L,
                    totalBytes = size,
                    autoPrompt = false,
                    lastError = ""
                )
            }
            startDownload(context)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Update check failed: ${e.message}")
            AppState.updateRelease { it.copy(checking = false) }
            false
        } finally {
            try { conn?.disconnect() } catch (_: Exception) {}
        }
    }

    private fun pickAsset(json: JSONObject, tag: String): Triple<String, String, Long>? {
        val assets = json.optJSONArray("assets") ?: return null
        val apks = mutableMapOf<String, Pair<String, Long>>()
        for (i in 0 until assets.length()) {
            val asset = assets.optJSONObject(i) ?: continue
            val rawName = asset.optString("name")
            val name = File(rawName).name
            if (!name.endsWith(".apk")) continue
            apks[name] = asset.optString("browser_download_url") to asset.optLong("size")
        }
        for (abi in Build.SUPPORTED_ABIS) {
            val target = "deltator-$tag-$abi.apk"
            apks[target]?.let { (u, s) -> return Triple(target, u, s) }
        }
        val universal = "deltator-$tag-universal.apk"
        apks[universal]?.let { (u, s) -> return Triple(universal, u, s) }
        val any = apks.entries.firstOrNull() ?: return null
        return Triple(any.key, any.value.first, any.value.second)
    }

    fun retryDownload(context: Context) {
        scope.launch {
            val hasUrl = stateMutex.withLock { apkUrl.isNotEmpty() }
            if (hasUrl) startDownload(context)
        }
    }

    @Suppress("DEPRECATION")
    fun verifyApkSignature(context: Context, apkFile: File): Boolean {
        try {
            val pm = context.packageManager
            val currentSignatures: Array<ByteArray> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pkgInfo = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = pkgInfo.signingInfo ?: return false
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners.map { it.toByteArray() }.toTypedArray()
                } else {
                    signingInfo.signingCertificateHistory.map { it.toByteArray() }.toTypedArray()
                }
            } else {
                val pkgInfo = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                pkgInfo.signatures?.map { it.toByteArray() }?.toTypedArray() ?: return false
            }

            val archiveInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.GET_SIGNATURES)
            } ?: return false

            if (archiveInfo.packageName != context.packageName) {
                Log.e(TAG, "Downloaded APK packageName (${archiveInfo.packageName}) does not match current app (${context.packageName})")
                return false
            }

            val archiveSignatures: Array<ByteArray> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = archiveInfo.signingInfo ?: return false
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners.map { it.toByteArray() }.toTypedArray()
                } else {
                    signingInfo.signingCertificateHistory.map { it.toByteArray() }.toTypedArray()
                }
            } else {
                archiveInfo.signatures?.map { it.toByteArray() }?.toTypedArray() ?: return false
            }

            if (currentSignatures.isEmpty() || archiveSignatures.isEmpty()) return false

            for (cur in currentSignatures) {
                for (arch in archiveSignatures) {
                    if (MessageDigest.isEqual(cur, arch)) {
                        return true
                    }
                }
            }
            Log.e(TAG, "Downloaded APK signature does not match installed application certificate")
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to verify APK signature: ${e.message}")
            return false
        }
    }

    fun computeSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val r = input.read(buf)
                if (r < 0) break
                digest.update(buf, 0, r)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    fun installLatest(context: Context) {
        scope.launch {
            val (file, tag) = stateMutex.withLock { apkFile to apkTag }
            if (file == null || !file.exists() || file.length() == 0L) {
                val msg = "The downloaded file is gone \u00b7 tap to download it again."
                AppState.updateRelease { it.copy(phase = "error", lastError = msg) }
                notifyError(context, tag, msg)
                return@launch
            }

            // Cryptographically verify APK signature before initiating package installation!
            if (!verifyApkSignature(context, file)) {
                val msg = "Downloaded update APK failed signature verification."
                Log.e(TAG, msg)
                file.delete()
                AppState.updateRelease { it.copy(phase = "error", lastError = msg) }
                notifyError(context, tag, msg)
                return@launch
            }

            if (!canInstall(context)) {
                val msg = "Allow installing from this source for DeltaTor, then try again."
                AppState.updateRelease { it.copy(lastError = msg) }
                notifyError(context, tag, msg)
                return@launch
            }

            var session: PackageInstaller.Session? = null
            try {
                val installer = context.packageManager.packageInstaller
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                val sessionId = installer.createSession(params)
                session = installer.openSession(sessionId)
                session.openWrite("DeltaTor", 0, file.length()).use { out ->
                    file.inputStream().use { input -> input.copyTo(out) }
                    session.fsync(out)
                }
                val intent = Intent(context, InstallResultReceiver::class.java)
                val pendingIntent = PendingIntent.getBroadcast(
                    context,
                    sessionId,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                )
                session.commit(pendingIntent.intentSender)
                session = null
                AppState.updateRelease { it.copy(lastError = "") }
                Log.i(TAG, "Install session $sessionId committed")
            } catch (e: Exception) {
                try { session?.abandon() } catch (_: Exception) {}
                Log.w(TAG, "Install session failed: ${e.message}")
                val msg = "Could not start the installer: ${e.message}"
                AppState.updateRelease { it.copy(lastError = msg) }
                notifyError(context, tag, msg)
            }
        }
    }

    fun canInstall(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
            context.packageManager.canRequestPackageInstalls()

    fun openUnknownSources(context: Context) {
        try {
            context.startActivity(
                Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}")
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } catch (e: Exception) {
            Log.w(TAG, "Could not open unknown-sources settings: ${e.message}")
        }
    }

    private fun startDownload(context: Context) {
        scope.launch {
            val (url, file, tag, size) = stateMutex.withLock {
                if (downloadJob?.isActive == true) return@launch
                val currentJob = Job()
                downloadJob = currentJob
                Quadruple(apkUrl, apkFile, apkTag, apkSize)
            }
            if (url.isEmpty() || file == null) return@launch

            val part = File(file.parentFile, "${file.name}.part")
            var conn: HttpURLConnection? = null
            try {
                conn = URL(url).openConnection(getProxy()) as HttpURLConnection
                conn.connectTimeout = 15_000
                conn.readTimeout = 30_000
                conn.connect()
                if (conn.responseCode != 200) throw IOException("HTTP ${conn.responseCode}")
                val total = if (size > 0L) size else conn.contentLengthLong
                part.parentFile?.mkdirs()
                var done = 0L
                var lastPost = 0L
                conn.inputStream.use { input ->
                    part.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                            done += n
                            val now = System.currentTimeMillis()
                            if (now - lastPost >= 250) {
                                lastPost = now
                                publishProgress(context, tag, done, total)
                            }
                        }
                        out.flush()
                    }
                }
                if (total > 0L && part.length() != total) {
                    throw IOException("got ${part.length()} of $total bytes")
                }
                file.delete()
                if (!part.renameTo(file)) throw IOException("could not move download into place")

                // Signature verification
                if (!verifyApkSignature(context, file)) {
                    file.delete()
                    throw IOException("Downloaded APK failed signature verification")
                }

                publishProgress(context, tag, file.length(), file.length())
                AppState.updateRelease { it.copy(phase = "ready", autoPrompt = false) }
                notifyReady(context, tag)
                pruneUpdates(context, keep = file)
                Log.i(TAG, "Update apk downloaded and verified: ${file.name} (${file.length()} bytes, SHA-256: ${computeSha256(file)})")
            } catch (e: Exception) {
                part.delete()
                Log.w(TAG, "Update download failed: ${e.message}")
                val msg = "Download failed \u00b7 open the app to retry."
                AppState.updateRelease { it.copy(phase = "error", lastError = msg) }
                notifyError(context, tag, msg)
            } finally {
                try { conn?.disconnect() } catch (_: Exception) {}
            }
        }
    }

    private data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

    private fun publishProgress(context: Context, tag: String, bytes: Long, total: Long) {
        AppState.updateRelease { it.copy(bytes = bytes, totalBytes = total) }
        val pct = if (total > 0L) (bytes * 100 / total).toInt().coerceIn(0, 100) else -1
        post(
            context,
            NotificationCompat.Builder(context, TorVpnService.CHANNEL_UPDATES)
                .setSmallIcon(R.drawable.ic_tor)
                .setContentTitle("DeltaTor $tag downloading")
                .setContentText(if (pct >= 0) "$pct% downloaded" else "Downloading update\u2026")
                .setProgress(if (total > 0L) 100 else 0, pct.coerceAtLeast(0), total <= 0L)
                .setContentIntent(openAppIntent(context))
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_PROGRESS)
        )
    }

    private fun notifyReady(context: Context, version: String) {
        val tap = PendingIntent.getBroadcast(
            context,
            41,
            Intent(context, InstallTriggerReceiver::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        post(
            context,
            NotificationCompat.Builder(context, TorVpnService.CHANNEL_UPDATES)
                .setSmallIcon(R.drawable.ic_tor)
                .setContentTitle("DeltaTor $version ready")
                .setContentText("Tap to install the new version.")
                .setContentIntent(tap)
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        )
    }

    private fun notifyError(context: Context, version: String, text: String) {
        post(
            context,
            NotificationCompat.Builder(context, TorVpnService.CHANNEL_UPDATES)
                .setSmallIcon(R.drawable.ic_tor)
                .setContentTitle("DeltaTor $version update")
                .setContentText(text)
                .setContentIntent(openAppIntent(context))
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_ERROR)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        )
    }

    private fun openAppIntent(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        42,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun post(context: Context, builder: NotificationCompat.Builder) {
        try {
            context.getSystemService(NotificationManager::class.java).notify(NOTIFICATION_UPDATE_ID, builder.build())
        } catch (e: Exception) {
            Log.w(TAG, "Update notification failed: ${e.message}")
        }
    }

    private fun pruneUpdates(context: Context, keep: File?) {
        File(context.filesDir, UPDATES_DIR).listFiles()?.forEach { f ->
            if (f.absolutePath != keep?.absolutePath && f.name != "${keep?.name}.part") {
                runCatching { f.delete() }
            }
        }
    }

    fun compareVersions(a: String, b: String): Int {
        val pa = a.split(".").mapNotNull { it.toIntOrNull() }
        val pb = b.split(".").mapNotNull { it.toIntOrNull() }
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val x = pa.getOrElse(i) { 0 }
            val y = pb.getOrElse(i) { 0 }
            if (x != y) return x - y
        }
        return 0
    }

    private const val NOTIFICATION_UPDATE_ID = 42
}
