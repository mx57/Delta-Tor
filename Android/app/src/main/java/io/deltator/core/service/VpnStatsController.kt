package io.deltator.core.service

import android.content.Context
import io.deltator.AppState
import io.deltator.Config
import io.deltator.core.backend.BackendStats
import io.deltator.core.backend.TunnelBackend
import io.deltator.tunnel.BridgeCountries
import io.deltator.tunnel.ExitLocator
import io.deltator.tunnel.ExitNodes
import io.deltator.tunnel.HevSocks5Tunnel
import io.deltator.ProxyChainManager
import io.deltator.tunnel.TorRunner
import io.deltator.tunnel.TorrcSettings
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class VpnStatsController(
    private val context: Context,
    private val scope: CoroutineScope,
    private val notificationController: VpnNotificationController,
    private val getCurrentBackend: () -> TunnelBackend?,
    private val isScreenOff: () -> Boolean,
    private val isLinkUp: () -> Boolean,
    private val onTransportRecoveryNeeded: suspend () -> Unit
) {
    companion object {
        private const val TAG = "VpnStatsController"

        private const val PROBE_INTERVAL_MS = 5_000L
        private const val PROBE_INTERVAL_HEALTHY_MS = 20_000L
        private const val PROBE_INTERVAL_QUIET_MS = 45_000L
        private const val PROBE_INTERVAL_IDLE_MS = 90_000L
        private const val PROBES_BEFORE_RECOVERY = 2
        private const val PROBES_TO_IGNORE_GRACE = 6
        private const val PROBE_GRACE_MARGIN_MS = 5_000L
        private const val PROBE_RECOVERY_COOLDOWN_MS = 90_000L
        private const val PROBE_TIMEOUT_MS = 6_000
        private const val ROTATION_GRACE_MS = 55_000L
        private const val STATS_INTERVAL_BUSY_MS = 1_000L
        private const val STATS_INTERVAL_IDLE_MS = 5_000L
    }

    enum class ProbeResult { Ok, Live, Dead }

    private var statsJob: Job? = null
    private var linkWatchJob: Job? = null
    private var exitLocatorJob: Job? = null
    private var exitWatchJob: Job? = null

    private val recovering = AtomicBoolean(false)
    private var failedProbes = 0
    private var deadSince = 0L
    private var lastRecoveryAt = 0L
    @Volatile private var quietProbes = 0
    @Volatile private var bytesAtLastProbe = 0L
    @Volatile private var rotationQuietUntilMs = 0L
    @Volatile private var lastAppliedExitCodes: List<String> = emptyList()

    fun resetState() {
        failedProbes = 0
        deadSince = 0L
        quietProbes = 0
        bytesAtLastProbe = 0L
        rotationQuietUntilMs = 0L
    }

    fun noteRotationEvent() {
        rotationQuietUntilMs = System.currentTimeMillis() + ROTATION_GRACE_MS
        deadSince = 0L
        failedProbes = 0
    }

    fun setLastAppliedExitCodes(codes: List<String>) {
        lastAppliedExitCodes = codes.toList()
    }

    fun startStatsPolling() {
        statsJob?.cancel()
        notificationController.setLastRenderedText("")
        statsJob = scope.launch(Dispatchers.IO) {
            var lastTx = 0L
            var lastRx = 0L
            var lastTime = 0L
            while (isActive) {
                if (isScreenOff()) {
                    delay(STATS_INTERVAL_IDLE_MS)
                    continue
                }
                val stats = getCurrentBackend()?.getStats()
                    ?: HevSocks5Tunnel.getStats()?.let { BackendStats(it.rxBytes, it.txBytes) }

                if (stats == null) {
                    delay(STATS_INTERVAL_IDLE_MS)
                    continue
                }

                val now = System.currentTimeMillis()
                val dtSeconds = ((now - lastTime).coerceAtLeast(1000) / 1000f).coerceAtLeast(0.001f)
                val upSpeed = if (lastTime > 0) (stats.txBytes - lastTx).toFloat() / dtSeconds else 0f
                val downSpeed = if (lastTime > 0) (stats.rxBytes - lastRx).toFloat() / dtSeconds else 0f
                val moving = stats.txBytes != lastTx || stats.rxBytes != lastRx
                lastTx = stats.txBytes
                lastRx = stats.rxBytes
                lastTime = now

                AppState.update {
                    it.copy(
                        txBytes = stats.txBytes,
                        rxBytes = stats.rxBytes,
                        txSpeed = upSpeed,
                        rxSpeed = downSpeed
                    )
                }

                val busy = moving || AppState.state.value.reconnecting
                val text = notificationController.trafficText(upSpeed, downSpeed, stats.txBytes, stats.rxBytes)
                if (busy || text != notificationController.getLastRenderedText()) {
                    notificationController.notifyTraffic(text)
                    notificationController.setLastRenderedText(text)
                }
                delay(if (busy) STATS_INTERVAL_BUSY_MS else STATS_INTERVAL_IDLE_MS)
            }
        }
    }

    fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
    }

    fun startLinkWatch() {
        linkWatchJob?.cancel()
        linkWatchJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                val before = AppState.state.value
                val linkUp = isLinkUp()
                val urgent = before.reconnecting || !linkUp || failedProbes > 0
                delay(if (urgent) PROBE_INTERVAL_MS else healthyInterval())

                val state = AppState.state.value
                if (!state.connected || recovering.get()) continue

                if (!linkUp) {
                    quietProbes = 0
                    if (!state.reconnecting) {
                        AppState.update { it.copy(reconnecting = true) }
                        notificationController.updateNotification("Reconnecting\u2026", progress = false, progressValue = 0)
                    }
                    continue
                }

                val bytes = AppState.state.value.txBytes + AppState.state.value.rxBytes
                val carried = bytes != bytesAtLastProbe
                bytesAtLastProbe = bytes

                when (probeTunnelUsable()) {
                    ProbeResult.Ok -> {
                        deadSince = 0
                        failedProbes = 0
                        lastRecoveryAt = 0
                        quietProbes = if (carried) 0 else quietProbes + 1
                        if (state.reconnecting) {
                            Log.i(TAG, "Tunnel usable again")
                            AppState.update { it.copy(reconnecting = false) }
                        }
                        continue
                    }
                    ProbeResult.Live -> {
                        failedProbes = 0
                        quietProbes = 0
                        continue
                    }
                    ProbeResult.Dead -> quietProbes = 0
                }

                val since = System.currentTimeMillis()
                if (since < rotationQuietUntilMs) {
                    deadSince = 0
                    failedProbes = 0
                    Log.i(TAG, "Tunnel quiet after rotation; waiting for circuits (${(rotationQuietUntilMs - since) / 1000}s grace left)")
                    delay(3_000)
                    continue
                }
                if (deadSince == 0L) deadSince = since
                failedProbes++
                val deadForMs = since - deadSince
                Log.w(TAG, "Tunnel silent for ${deadForMs / 1000}s ($failedProbes probe(s))")

                val mustRebuild = failedProbes >= PROBES_BEFORE_RECOVERY &&
                    (deadForMs >= probeGraceMs() || failedProbes >= PROBES_TO_IGNORE_GRACE)

                if (!mustRebuild) continue

                failedProbes = 0
                deadSince = 0
                if (since - lastRecoveryAt < PROBE_RECOVERY_COOLDOWN_MS) {
                    Log.i(
                        TAG,
                        "Not rebuilding transport again so soon, ${(PROBE_RECOVERY_COOLDOWN_MS - (since - lastRecoveryAt)) / 1000}s left of cooldown"
                    )
                    continue
                }
                lastRecoveryAt = since
                onTransportRecoveryNeeded()
            }
        }
    }

    fun stopLinkWatch() {
        linkWatchJob?.cancel()
        linkWatchJob = null
    }

    private fun healthyInterval(): Long = when {
        quietProbes < 2 -> PROBE_INTERVAL_HEALTHY_MS
        quietProbes < 5 -> PROBE_INTERVAL_QUIET_MS
        else -> PROBE_INTERVAL_IDLE_MS
    }

    fun probeTunnelUsable(): ProbeResult {
        var stage = "connect"
        return try {
            Socket().use { s ->
                stage = "bridge"
                s.connect(InetSocketAddress("127.0.0.1", Config.proxyPort), PROBE_TIMEOUT_MS)
                s.soTimeout = PROBE_TIMEOUT_MS
                val out = s.getOutputStream()
                val input = s.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val version = input.read()
                val method = input.read()
                if (version != 0x05 || method != 0x00) {
                    return logProbe("bridge rejected greeting: $version/$method", ProbeResult.Dead)
                }
                stage = "tor"
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50))
                out.flush()
                val reply = input.read()
                if (reply == 0x00) {
                    ProbeResult.Ok
                } else if (reply < 0) {
                    logProbe("Tor closed without answering", ProbeResult.Dead)
                } else {
                    logProbe(
                        "Tor answered 0x%02x, destination refused it".format(reply),
                        ProbeResult.Live
                    )
                }
            }
        } catch (e: Exception) {
            logProbe("no answer at $stage: ${e.message}", ProbeResult.Dead)
        }
    }

    private fun logProbe(detail: String, result: ProbeResult): ProbeResult {
        Log.d(TAG, "probe ($detail)")
        return result
    }

    private fun probeGraceMs(): Long =
        (TorrcSettings.intValue("CircuitBuildTimeout", 40) +
            TorrcSettings.intValue("SocksTimeout", 30)) * 1000L + PROBE_GRACE_MARGIN_MS

    fun startExitLocator(proxyHost: String, proxyPort: Int, getTorPort: () -> Int) {
        exitLocatorJob?.cancel()
        exitLocatorJob = scope.launch(Dispatchers.IO) {
            val chainMode = Config.torChainMode
            val isChained = chainMode != Config.TOR_CHAIN_NONE
            val selected = if (isChained) emptyList() else ExitNodes.currentCodes()
                .map { it.trim().uppercase() }
                .filter { it.length == 2 && it.all { c -> c in 'A'..'Z' } }
                .distinct()

            try {
                if (isChained) {
                    when (chainMode) {
                        Config.TOR_CHAIN_FREE_NODES -> {
                            val curHost = AppState.chainState.value.host
                            val srv = ProxyChainManager.listState.value.servers.find { it.host == curHost }
                            if (srv != null && srv.countryCode.isNotBlank()) {
                                AppState.update {
                                    if (it.chainExitCode.isBlank()) it.copy(
                                        chainExitCode = srv.countryCode, chainExitName = srv.countryName, chainExitIp = srv.host
                                    ) else it
                                }
                            }
                        }
                        Config.TOR_CHAIN_AMNEZIA -> {
                            val prof = io.deltator.feature.chain.ChainProfileManager.amneziaProfiles.value.find { it.isSelected }
                            val epIp = prof?.endpoint?.substringBefore(":") ?: ""
                            val offline = try { BridgeCountries.countryInfo(context, epIp) } catch (_: Exception) { null }
                            val cc = offline?.first ?: ""
                            val cName = offline?.second ?: if (cc.isNotBlank()) java.util.Locale("", cc).displayCountry else ""
                            if (cc.isNotBlank()) AppState.update {
                                if (it.chainExitCode.isBlank()) it.copy(chainExitCode = cc, chainExitName = "AmneziaWG ($cName)") else it
                            }
                        }
                        Config.TOR_CHAIN_MASQUE -> {
                            val epHost = Config.masqueEndpoint.substringAfter("://", Config.masqueEndpoint).substringBefore('/')
                            val offline = try { BridgeCountries.countryInfo(context, epHost) } catch (_: Exception) { null }
                            val cc = offline?.first ?: ""
                            val cName = offline?.second ?: if (cc.isNotBlank()) java.util.Locale("", cc).displayCountry else ""
                            if (cc.isNotBlank()) AppState.update {
                                if (it.chainExitCode.isBlank()) it.copy(chainExitCode = cc, chainExitName = "MASQUE H3 ($cName)") else it
                            }
                        }
                    }
                    delay(2_500)
                } else if (selected.isNotEmpty()) {
                    Log.i("ExitNode", "waiting for live exit switch before locating (selected: ${selected.joinToString(",")})")
                    delay(5_000)
                }

                val tries = when {
                    selected.isNotEmpty() -> 8
                    isChained -> 8
                    else -> 3
                }
                for (attempt in 1..tries) {
                    val torPort = getTorPort()
                    val finalInfo = ExitLocator.locate(context, proxyHost, proxyPort, timeoutMs = 10_000)
                    val torInfo = if (isChained && torPort > 0) {
                        try { ExitLocator.locate(context, "127.0.0.1", torPort, timeoutMs = 10_000) } catch (_: Exception) { null }
                    } else null

                    if (finalInfo == null && torInfo == null) {
                        Log.w("ExitNode", "location probe attempt $attempt/$tries failed (chain=$chainMode)")
                    } else {
                        val currentChain = Config.torChainMode
                        val cs = AppState.chainState.value
                        val broken = cs.status == AppState.ChainStatus.FAILED ||
                            cs.message.contains("traffic left via Tor", true) ||
                            cs.message.contains("upstream refused", true) ||
                            cs.message.contains("not supported", true)
                        fun gl(code: String, name: String, city: String) = name.ifBlank { city.ifBlank { code } }

                        var tCode = torInfo?.countryCode ?: ""; var tName = torInfo?.let { gl(it.countryCode, it.countryName, it.city) } ?: ""; var tIp = torInfo?.ip ?: ""
                        var cCode = ""; var cName = ""; var cIp = ""

                        if (currentChain == Config.TOR_CHAIN_NONE) {
                            val i = finalInfo ?: torInfo
                            if (i != null) { tCode = i.countryCode; tName = gl(i.countryCode, i.countryName, i.city); tIp = i.ip }
                        } else if (currentChain == Config.TOR_CHAIN_FREE_NODES) {
                            val srv = ProxyChainManager.listState.value.servers.find { it.host == AppState.chainState.value.host }
                            cCode = srv?.countryCode ?: ""; cName = srv?.countryName?.ifBlank { srv.host } ?: (AppState.chainState.value.host)
                            cIp = srv?.host ?: AppState.chainState.value.host
                            if (tCode.isBlank() && finalInfo != null) { tCode = finalInfo.countryCode; tName = gl(finalInfo.countryCode, finalInfo.countryName, finalInfo.city); tIp = finalInfo.ip }
                        } else if (broken) {
                            val i = finalInfo ?: torInfo
                            if (i != null) { tCode = i.countryCode; tName = gl(i.countryCode, i.countryName, i.city); tIp = i.ip }
                        } else {
                            val i = finalInfo
                            if (i != null) { cCode = i.countryCode; cName = gl(i.countryCode, i.countryName, i.city); cIp = i.ip }
                            if (tCode.isBlank() && torInfo != null) { tCode = torInfo.countryCode; tName = gl(torInfo.countryCode, torInfo.countryName, torInfo.city); tIp = torInfo.ip }
                        }

                        val chainLabel = when (currentChain) {
                            Config.TOR_CHAIN_WARP -> "WARP"; Config.TOR_CHAIN_AMNEZIA -> "AmneziaWG"
                            Config.TOR_CHAIN_MASQUE -> "MASQUE"; Config.TOR_CHAIN_FREE_NODES -> "VPN Gate"; else -> "Chain"
                        }
                        val (eCode, eName, eIp) = when {
                            currentChain == Config.TOR_CHAIN_NONE -> Triple(tCode, tName, tIp)
                            broken -> Triple(tCode, "Tor (${chainLabel} broken) \u00b7 $tName".trim(' ', '·'), tIp)
                            cCode.isNotBlank() || cName.isNotBlank() -> Triple(cCode, "$chainLabel \u00b7 ${if (cName.isNotBlank()) cName else cCode}", cIp)
                            else -> Triple(tCode, tName, tIp)
                        }

                        AppState.update {
                            it.copy(
                                exitIp = eIp, exitCode = eCode, exitName = eName,
                                torExitIp = tIp, torExitCode = tCode, torExitName = tName,
                                chainExitIp = cIp, chainExitCode = cCode, chainExitName = cName
                            )
                        }
                        val curHint = AppState.hint.value.text
                        if (curHint.contains("Rotating", true) || curHint.contains("rebuilding", true) || curHint.contains("waiting for the new exit", true)) {
                            if (tCode.isNotBlank() || tIp.isNotBlank()) AppState.setHint("Exit: ${flagLine(tCode, tName)} \u00b7 $tIp")
                        }
                        val match = (if (isChained) eCode else tCode).uppercase() in selected
                        Log.i("ExitNode", "exit tor=${tCode}/${tIp} chain=${cCode}/${cIp} effective=${eCode} $eName (mode=$currentChain broken=$broken)")
                        if (selected.isEmpty() || match) return@launch
                    }
                    if (attempt < tries) delay(if (isChained) 5_000 else 4_000)
                }
                if (selected.isNotEmpty()) Log.w("ExitNode", "did not observe a ${selected.joinToString(",")} exit after $tries tries; connection still up")
                else if (isChained) Log.w("ExitNode", "could not determine $chainMode exit after $tries tries (chain may be broken/fallback)")
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.w("ExitNode", "exit locator failed: ${e.message}")
            }
        }
    }

    fun stopExitLocator() {
        exitLocatorJob?.cancel()
        exitLocatorJob = null
    }

    suspend fun locateDirectExit(label: String) {
        try {
            val info = ExitLocator.locateDirect(context, timeoutMs = 12_000) ?: return
            val geo = info.countryName.ifBlank { info.city.ifBlank { info.countryCode } }
            AppState.update {
                it.copy(
                    exitIp = info.ip, exitCode = info.countryCode, exitName = "$label \u00b7 $geo",
                    chainExitIp = info.ip, chainExitCode = info.countryCode, chainExitName = "$label \u00b7 $geo",
                    torExitIp = "", torExitCode = "", torExitName = ""
                )
            }
            Log.i("ExitNode", "direct exit ($label) ${info.ip} ${info.countryCode} $geo")
        } catch (e: Exception) {
            Log.w("ExitNode", "direct exit locate failed: ${e.message}")
        }
    }

    fun startExitWatch(getActiveRunner: () -> TorRunner?) {
        exitWatchJob?.cancel()
        exitWatchJob = scope.launch(Dispatchers.IO) {
            val cur = ExitNodes.codes.value
            if (cur != lastAppliedExitCodes) {
                Log.i(TAG, "exit watch: reconciling [${cur.joinToString(",").ifEmpty { "any" }}]")
                applyExitCodesLive(cur, "reconcile", getActiveRunner())
            } else {
                Log.i(TAG, "exit watch: up to date [${cur.joinToString(",").ifEmpty { "any" }}]")
            }
            var last = cur
            ExitNodes.codes.collect { codes ->
                if (codes == last) return@collect
                last = codes
                applyExitCodesLive(codes, "changed", getActiveRunner())
            }
        }
    }

    fun stopExitWatch() {
        exitWatchJob?.cancel()
        exitWatchJob = null
    }

    fun applyExitCodesLive(codes: List<String>, reason: String, activeRunner: TorRunner?): Boolean {
        val s = AppState.state.value
        val live = (s.torRunning || s.connected) && !s.stopping
        val chained = Config.torChainMode != Config.TOR_CHAIN_NONE
        if (!live) {
            Log.i(TAG, "exit apply ($reason): not live")
            return false
        }
        if (chained && reason != "action" && reason != "auto-match") {
            Log.i(TAG, "exit apply ($reason): chain owns exit (${Config.torChainMode})")
            return false
        }
        if (activeRunner == null) {
            Log.w(TAG, "exit apply ($reason): no active runner")
            return false
        }
        if (activeRunner.controlPortLive <= 0) {
            Log.w(TAG, "exit apply ($reason): ${activeRunner.name} has no control port")
            return false
        }
        Log.i(TAG, "exit apply ($reason): [${codes.joinToString(",").ifEmpty { "any" }}] via ${activeRunner.name}:${activeRunner.controlPortLive}")
        val ok = try {
            activeRunner.liveSteerExit(codes)
        } catch (e: Exception) {
            Log.w(TAG, "exit apply ($reason) threw: ${e.message}")
            false
        }
        Log.i(TAG, "exit apply ($reason): ${if (ok) "applied" else "FAILED"}")
        if (ok) {
            lastAppliedExitCodes = codes.toList()
            noteRotationEvent()
            AppState.setHint(
                if (codes.isEmpty()) "Exit freed — circuits leave anywhere"
                else "Exit set to ${codes.joinToString(", ")} — rebuilding circuits"
            )
        } else {
            AppState.setHint("Could not steer the live session — applies on next connect")
        }
        if (AppState.state.value.connected) startExitLocator("127.0.0.1", Config.proxyPort) { activeRunner.torSocksPort }
        return ok
    }

    fun flagLine(code: String, name: String): String {
        val cc = code.trim().uppercase()
        val flag = if (cc.length == 2 && cc.all { it in 'A'..'Z' }) {
            val a = 0x1F1E6 + (cc[0].code - 'A'.code)
            val b = 0x1F1E6 + (cc[1].code - 'A'.code)
            String(Character.toChars(a)) + String(Character.toChars(b))
        } else ""
        val label = if (name.isNotBlank()) name else cc
        return if (flag.isNotBlank()) "$flag $label" else label
    }

    fun stopAll() {
        stopStatsPolling()
        stopLinkWatch()
        stopExitLocator()
        stopExitWatch()
        resetState()
    }
}
