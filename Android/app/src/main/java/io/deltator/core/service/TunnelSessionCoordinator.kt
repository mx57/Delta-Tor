package io.deltator.core.service

import android.app.Notification
import android.content.Context
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import io.deltator.AppState
import io.deltator.Config
import io.deltator.core.backend.AmneziaTunnelBackend
import io.deltator.core.backend.EngineMode
import io.deltator.core.backend.MasqueTunnelBackend
import io.deltator.core.backend.TorTunnelBackend
import io.deltator.core.backend.TunnelBackend
import io.deltator.core.backend.WarpTunnelBackend
import io.deltator.tunnel.BridgeMemory
import io.deltator.tunnel.ConnectCleanup
import io.deltator.tunnel.ExitNodes
import io.deltator.ProxyChainManager
import io.deltator.TorVpnService
import io.deltator.tunnel.HevSocks5Tunnel
import io.deltator.tunnel.ParallelTorManager
import io.deltator.tunnel.SstpChainEngine
import io.deltator.tunnel.TorControl
import io.deltator.tunnel.TorRunner
import io.deltator.tunnel.TorSocksBridge
import io.deltator.tunnel.TorrcSettings
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

class RestartInAuto(val recovery: AppState.NoticeKind) :
    RuntimeException("connect restarted via $recovery")

class TunnelSessionCoordinator(
    private val context: Context,
    private val serviceScope: CoroutineScope,
    private val notificationController: VpnNotificationController,
    private val establishVpnInterface: () -> ParcelFileDescriptor?,
    private val getEstablishFailureReason: () -> String?,
    private val chainBuilderFactory: () -> VpnService.Builder,
    private val startForegroundService: (id: Int, notification: Notification) -> Unit,
    private val stopForegroundService: (removeNotification: Boolean) -> Unit,
    private val stopServiceSelf: () -> Unit
) {
    companion object {
        private const val TAG = "TunnelSessionCoord"
        const val RECOVERY_TITLE = "DELTATOR CHANGED THE CONNECTION MODE"
        private const val STALL_RECOVERY_AFTER_MS = 60_000L
        private const val WAKE_LOCK_TIMEOUT_MS = 10 * 60 * 1000L
        private const val STOPPING_MIN_MS = 3_000L
        private const val VPN_MTU = 1280
        private const val VPN_ADDRESS = "10.255.255.1"
    }

    private val lifecycleMutex = Mutex()
    @Volatile var vpnInterface: ParcelFileDescriptor? = null
        private set
    @Volatile var activeRunner: TorRunner? = null
        private set
    @Volatile var currentBackend: TunnelBackend? = null
        private set

    lateinit var networkMonitor: VpnNetworkMonitor
    lateinit var statsController: VpnStatsController

    private var wakeLock: PowerManager.WakeLock? = null
    private var cpuHolds = 0

    private var stallBest = -1
    private var stallSince = 0L
    private var stallFired = false
    private val recoveriesSpent = mutableSetOf<AppState.NoticeKind>()

    @Volatile private var currentSession: Int = 0
    @Volatile private var safeTorrcArmed = false
    private val recovering = AtomicBoolean(false)

    private var chainEngine: SstpChainEngine? = null
    private var lastIdentityAtMillis: Long = 0L
    private val identityCooldownMs: Long = 15_000L

    init {
        statsController = VpnStatsController(
            context = context,
            scope = serviceScope,
            notificationController = notificationController,
            getCurrentBackend = { currentBackend },
            isScreenOff = { networkMonitor.isScreenOff },
            isLinkUp = { networkMonitor.linkUp },
            onTransportRecoveryNeeded = { recoverTransport() }
        )

        networkMonitor = VpnNetworkMonitor(
            context = context,
            onScreenStateChanged = { _ -> },
            onNetworkLost = {
                if (AppState.state.value.connected) {
                    markReconnecting("network down")
                }
            },
            onNetworkAvailable = { wasDown, switched ->
                if (AppState.state.value.connected && (wasDown || switched)) {
                    serviceScope.launch {
                        val probe = statsController.probeTunnelUsable()
                        if (probe == VpnStatsController.ProbeResult.Dead) {
                            Log.w(TAG, "Network changed and tunnel dead, triggering fast recovery")
                            recoverTransport()
                        } else {
                            statsController.startExitLocator("127.0.0.1", Config.proxyPort) { activeRunner?.torSocksPort ?: -1 }
                        }
                    }
                }
            }
        )
    }

    @Synchronized
    fun holdCpu() {
        if (cpuHolds == 0) {
            if (wakeLock == null) {
                wakeLock = (context.getSystemService(Context.POWER_SERVICE) as PowerManager)
                    .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DeltaTor:vpn")
                    .apply { setReferenceCounted(false) }
            }
            try {
                wakeLock?.acquire(WAKE_LOCK_TIMEOUT_MS)
            } catch (e: Exception) {
                Log.w(TAG, "Could not take the CPU lock: ${e.message}")
            }
        }
        cpuHolds++
    }

    @Synchronized
    fun releaseCpu() {
        if (cpuHolds == 0) return
        cpuHolds--
        if (cpuHolds == 0) dropCpu()
    }

    @Synchronized
    fun dropCpu() {
        cpuHolds = 0
        try {
            wakeLock?.takeIf { it.isHeld }?.release()
        } catch (_: Exception) {}
        wakeLock = null
    }

    @Synchronized
    fun getChainEngine(): SstpChainEngine {
        var engine = chainEngine
        if (engine == null) {
            engine = SstpChainEngine(context as TorVpnService)
            chainEngine = engine
        }
        return engine
    }

    fun start() {
        networkMonitor.start()
    }

    fun stop() {
        networkMonitor.stop()
        teardown()
    }

    fun connect() {
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring connect: a stop is still tearing the cores down")
            return
        }
        if (AppState.vpnStarted) {
            Log.i(TAG, "Already running")
            return
        }
        AppState.markStarted()
        safeTorrcArmed = true
        currentSession = Log.beginSession("connect")
        recoveriesSpent.clear()
        AppState.update {
            it.copy(
                connecting = true,
                connected = false,
                reconnecting = false,
                torRunning = false,
                error = null,
                transports = emptyMap(),
                transport = "",
                socksEndpoint = ""
            )
        }
        AppState.setMode(Config.transportMode)

        startForegroundService(
            VpnNotificationController.NOTIFICATION_ID,
            notificationController.buildNotification("Connecting\u2026", progress = true, progressValue = 0)
        )

        holdCpu()

        serviceScope.launch {
            lifecycleMutex.withLock {
                try {
                    runConnectFlow()
                } catch (e: Exception) {
                    Log.e(TAG, "Connect failed", e)
                    fail("Connect failed: ${e.message}")
                } finally {
                    releaseCpu()
                }
            }
        }
    }

    private suspend fun runConnectFlow() {
        while (true) {
            val recovery = runConnectAttempt() ?: return
            applyRecovery(recovery)
        }
    }

    private suspend fun runConnectAttempt(): AppState.NoticeKind? {
        val proxyPort = Config.proxyPort
        val proxyHost = "127.0.0.1"

        Log.i(TAG, "Checking for leftovers of previous runs")
        val leftovers = withContext(Dispatchers.IO) {
            ConnectCleanup.run(context, proxyPort)
        }
        Log.i(
            TAG,
            "Pre-connect cleanup: ${leftovers.orphanCoresKilled} orphan core(s) killed, " +
                "${leftovers.ownHoldersKilled} own port holder(s) freed, " +
                "${leftovers.blocked.size} port(s) blocked"
        )
        leftovers.blocked.firstOrNull { it.port == proxyPort }?.let { holder ->
            val what = when {
                holder.ours == true -> "a leftover DeltaTor process that would not exit"
                holder.pid != null -> "another app (${holder.describe()})"
                else -> "an unknown process"
            }
            val advice = if (holder.ours == true) "Force-stop DeltaTor from the system app info, or" else "Close that app, or"
            fail("SOCKS5 port $proxyPort on 127.0.0.1 is held by $what and could not be freed. $advice pick a different port in the app settings.")
            return null
        }

        TorSocksBridge.debugLogging = Config.debugMode
        TorSocksBridge.domainRouter = io.deltator.tunnel.DomainRouter.DISABLED

        val engineMode = EngineMode.fromId(Config.engineMode)
        if (engineMode != EngineMode.TOR_RACING) {
            notificationController.updateNotification("Connecting via ${engineMode.title} \u2026", progress = true, progressValue = 0)
            val backend: TunnelBackend = when (engineMode) {
                EngineMode.AMNEZIA_WG -> AmneziaTunnelBackend(context as VpnService)
                EngineMode.WARP_ANYCAST -> WarpTunnelBackend(context as VpnService)
                EngineMode.MASQUE -> MasqueTunnelBackend(context as VpnService)
                else -> throw IllegalStateException("engine ${engineMode.id} reached hybrid dispatch in Tor branch")
            }
            currentBackend = backend
            vpnInterface = establishVpnInterface()
            if (vpnInterface == null) {
                fail(getEstablishFailureReason() ?: "Failed to establish VPN interface")
                return null
            }
            val started = backend.start(vpnInterface!!)
            if (!started) {
                try { vpnInterface?.close() } catch (_: Exception) {}
                vpnInterface = null
                fail("Failed to start ${backend.displayName} backend")
                return null
            }

            AppState.update {
                it.copy(
                    connecting = false,
                    connected = true,
                    reconnecting = false,
                    torRunning = false,
                    error = null,
                    transport = engineMode.title,
                    connectedAtMillis = System.currentTimeMillis(),
                    exitCode = "", exitName = "", exitIp = "",
                    torExitCode = "", torExitName = "", torExitIp = "",
                    chainExitCode = "", chainExitName = "", chainExitIp = ""
                )
            }
            startForegroundService(
                VpnNotificationController.NOTIFICATION_ID,
                notificationController.buildNotification("Connected via ${engineMode.title}", progress = false)
            )
            statsController.startStatsPolling()
            serviceScope.launch { try { statsController.locateDirectExit(engineMode.title) } catch (_: Exception) {} }
            Log.i(TAG, "Hybrid engine connected: ${engineMode.title}")
            return null
        }

        val mode = ParallelTorManager.MODES.firstOrNull { it == Config.transportMode } ?: ParallelTorManager.TRANSPORT_AUTO
        val autoNames = Config.autoTransports.filter { it in ParallelTorManager.AUTO_SOURCES }.ifEmpty { ParallelTorManager.AUTO_SOURCES.toList() }
        val modeLabel = if (mode == ParallelTorManager.TRANSPORT_AUTO) {
            autoNames.joinToString(" / ") + (if (BridgeMemory.countAll(context) > 0) " / memory" else "")
        } else {
            mode + (if (BridgeMemory.count(context, mode) > 0) " + memory" else "")
        }
        Log.i(TAG, "Transport mode: $modeLabel")
        notificationController.updateNotification("Connecting via $modeLabel \u2026", progress = true, progressValue = 0)

        stallBest = -1
        stallSince = SystemClock.elapsedRealtime()
        stallFired = false

        val w = try {
            ParallelTorManager.race(
                context = context,
                basePort = proxyPort,
                sessionId = currentSession,
                transportMode = Config.transportMode,
                customBridges = Config.customBridges,
                autoTransports = Config.autoTransports,
                runMemory = Config.runMemory
            ) { snapshot ->
                val progress = snapshot.mapValues { (_, r) -> if (r.failed != null) -1 else r.progress() }
                AppState.update { it.copy(transports = progress) }
                val maxProg = (progress.values.maxOrNull() ?: 0).coerceAtLeast(0)
                val detail = progress.entries.joinToString("  ") { (n, p) -> "$n=${if (p < 0) "FAIL" else "$p%"}" }
                notificationController.updateNotification(detail, progress = true, progressValue = maxProg)

                val live = progress.values.filter { it >= 0 }.maxOrNull() ?: 0
                if (live > stallBest) {
                    stallBest = live
                    stallSince = SystemClock.elapsedRealtime()
                }
                if (!stallFired && live < 100 &&
                    SystemClock.elapsedRealtime() - stallSince >= STALL_RECOVERY_AFTER_MS
                ) {
                    stallFired = true
                    if (!Config.autoRecovery) {
                        Log.w(TAG, "no progress past $live% for ${STALL_RECOVERY_AFTER_MS / 1000}s in $mode, autoRecovery off")
                    } else {
                        val recovery = if (mode != ParallelTorManager.TRANSPORT_AUTO) AppState.NoticeKind.AutoRecovery else null
                        if (recovery != null && recoveriesSpent.add(recovery)) {
                            Log.w(TAG, "no progress past $live% for ${STALL_RECOVERY_AFTER_MS / 1000}s in $mode; recovering via $recovery")
                            ParallelTorManager.stopAll()
                            throw RestartInAuto(recovery)
                        }
                    }
                }
            }
        } catch (e: RestartInAuto) {
            return e.recovery
        } catch (e: Exception) {
            fail(e.message ?: "All transports failed to bootstrap")
            return null
        }
        activeRunner = w
        AppState.update { it.copy(transports = mapOf(w.name to 100), transport = w.name) }
        Log.i(TAG, "Winner transport: ${w.name} (SOCKS5 $proxyHost:${w.torSocksPort})")

        withContext(Dispatchers.IO) {
            ParallelTorManager.awaitPortFree(proxyHost, proxyPort)
        }
        TorSocksBridge.upstreamMode = TorSocksBridge.UpstreamMode.TOR
        TorSocksBridge.chainMode = when (Config.torChainMode) {
            Config.TOR_CHAIN_WARP -> TorSocksBridge.ChainMode.WARP
            Config.TOR_CHAIN_AMNEZIA -> TorSocksBridge.ChainMode.AMNEZIA
            Config.TOR_CHAIN_MASQUE -> TorSocksBridge.ChainMode.MASQUE
            Config.TOR_CHAIN_FREE_NODES -> TorSocksBridge.ChainMode.FREE_NODES
            else -> TorSocksBridge.ChainMode.NONE
        }
        val bridgeResult = TorSocksBridge.start(
            torSocksPort = w.torSocksPort,
            torHost = "127.0.0.1",
            listenPort = proxyPort,
            listenHost = proxyHost
        )
        if (bridgeResult.isFailure) {
            fail(bridgeResult.exceptionOrNull()?.message ?: "Failed to start bridge")
            return null
        }
        AppState.update { it.copy(torRunning = true) }

        establishTunnel(w, proxyHost, proxyPort)

        when (Config.torChainMode) {
            Config.TOR_CHAIN_WARP -> AppState.updateChain {
                it.copy(status = AppState.ChainStatus.CONNECTED, host = "WARP Anycast", message = "Tor \u2192 Cloudflare WARP")
            }
            Config.TOR_CHAIN_AMNEZIA -> AppState.updateChain {
                it.copy(status = AppState.ChainStatus.CONNECTED, host = "AmneziaWG", message = "Tor \u2192 AmneziaWG")
            }
            Config.TOR_CHAIN_MASQUE -> AppState.updateChain {
                it.copy(status = AppState.ChainStatus.CONNECTED, host = "MASQUE H3", message = "Tor \u2192 MASQUE")
            }
        }
        return null
    }

    private fun applyRecovery(recovery: AppState.NoticeKind) {
        val wasMode = Config.transportMode
        when (recovery) {
            AppState.NoticeKind.AutoRecovery -> {
                Config.transportMode = ParallelTorManager.TRANSPORT_AUTO
                AppState.setMode(Config.transportMode)
                Log.i(TAG, "Recovery: $wasMode stalled, switching to auto")
            }
            else -> return
        }

        AppState.update {
            it.copy(transports = emptyMap(), transport = "", error = null, connecting = true)
        }
        currentSession = Log.beginSession("connect")

        AppState.postNotice(
            recovery,
            RECOVERY_TITLE,
            "$wasMode made no progress for a minute, which on this network usually means it is blocked.\n\n" +
                "DeltaTor stopped that attempt, switched the connection mode to Auto and started again.\n\n" +
                "Auto is now your connection mode. If you would rather pick the transport yourself again, change it in Settings."
        )
        notificationController.updateNotification("Restarting in auto \u2026", progress = true, progressValue = 0)
    }

    private suspend fun establishTunnel(w: TorRunner, proxyHost: String, proxyPort: Int) {
        if (Config.proxyOnlyMode) {
            val endpoint = "socks5://$proxyHost:$proxyPort"
            AppState.update {
                it.copy(
                    connecting = false,
                    connected = false,
                    reconnecting = false,
                    error = null,
                    transports = mapOf(w.name to 100),
                    connectedAtMillis = System.currentTimeMillis(),
                    socksEndpoint = endpoint
                )
            }
            startForegroundService(
                VpnNotificationController.NOTIFICATION_ID,
                notificationController.buildNotification("Proxy ready \u00b7 $endpoint", progress = false)
            )
            statsController.resetState()
            statsController.setLastAppliedExitCodes(ExitNodes.currentCodes())
            statsController.startExitLocator(proxyHost, proxyPort) { w.torSocksPort }
            statsController.startExitWatch { activeRunner }
            Log.i(TAG, "Proxy mode ready. Winner: ${w.name}, SOCKS5 at $endpoint")
            Log.endSession("proxy ready via ${w.name}")
            return
        }

        notificationController.updateNotification("Establishing VPN \u2026", progress = true, progressValue = 0)

        vpnInterface = establishVpnInterface()
        if (vpnInterface == null) {
            fail(getEstablishFailureReason() ?: "Failed to establish VPN interface")
            return
        }

        delay(200)

        val tunResult = HevSocks5Tunnel.start(
            tunFd = vpnInterface!!,
            socksAddress = proxyHost,
            socksPort = proxyPort,
            enableUdpTunneling = true,
            mtu = VPN_MTU,
            ipv4Address = VPN_ADDRESS,
            disableQuic = true,
            rejectNonDnsUdp = true
        )
        if (tunResult.isFailure) {
            fail(tunResult.exceptionOrNull()?.message ?: "Failed to start tunnel")
            return
        }

        AppState.update {
            it.copy(
                connecting = false,
                connected = true,
                reconnecting = false,
                error = null,
                transports = mapOf(w.name to 100),
                connectedAtMillis = System.currentTimeMillis(),
                exitCode = "", exitName = "", exitIp = "",
                torExitCode = "", torExitName = "", torExitIp = "",
                chainExitCode = "", chainExitName = "", chainExitIp = "",
                socksEndpoint = ""
            )
        }
        safeTorrcArmed = false
        startForegroundService(
            VpnNotificationController.NOTIFICATION_ID,
            notificationController.buildNotification("Connected via ${w.name} \u00b7 Tor Network", progress = false)
        )
        statsController.resetState()
        statsController.setLastAppliedExitCodes(ExitNodes.currentCodes())
        statsController.startStatsPolling()
        statsController.startLinkWatch()
        statsController.startExitLocator(proxyHost, proxyPort) { w.torSocksPort }
        statsController.startExitWatch { activeRunner }
        Log.i(TAG, "DeltaTor connected. Winner: ${w.name}, SOCKS5 at $proxyHost:$proxyPort")
        Log.endSession("connected via ${w.name}")
    }

    fun startVpn() {
        safeTorrcArmed = true
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring start: a stop is still tearing the cores down")
            return
        }
        if (AppState.state.value.connected) {
            Log.i(TAG, "VPN already active")
            return
        }
        if (Config.proxyOnlyMode) {
            Log.i(TAG, "Ignoring start: proxy mode is on, there is no VPN to start")
            return
        }
        val w = activeRunner
        if (w == null || !w.isReady() || !TorSocksBridge.isRunning()) {
            Log.e(TAG, "Tor not running; full reconnect required")
            fail("Tor is not running. Reconnect.")
            return
        }
        serviceScope.launch {
            try {
                AppState.update { it.copy(connecting = true, connected = false, error = null) }
                establishTunnel(w, "127.0.0.1", Config.proxyPort)
            } catch (e: Exception) {
                Log.e(TAG, "Start VPN failed", e)
                fail("Start VPN failed: ${e.message}")
            }
        }
    }

    fun stopVpn() {
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring stop: a stop is already tearing the cores down")
            return
        }
        if (Config.proxyOnlyMode) {
            Log.i(TAG, "Ignoring stop: proxy mode is on, use Disconnect to shut proxy down")
            return
        }
        val chain = chainEngine
        if (chain != null && chain.isActive) {
            Log.i(TAG, "Stopping chain; plain Tor VPN restored")
            chain.stop()
            return
        }
        val s = AppState.state.value
        if (!s.connected && !s.connecting && !s.reconnecting) {
            Log.i(TAG, "Nothing to stop: VPN not up")
            return
        }
        Log.i(TAG, "Stopping VPN only; Tor stays running")
        AppState.update {
            it.copy(
                stopping = true,
                connecting = false,
                connected = false,
                reconnecting = false,
                error = null,
                socksEndpoint = ""
            )
        }
        notificationController.updateNotification("Turning the VPN off \u2026", progress = true, progressValue = 0)
        serviceScope.launch {
            teardownVpn()
            AppState.update { it.copy(stopping = false, torRunning = activeRunner != null) }
            Log.endSession("VPN off \u00b7 Tor still running")
            if (activeRunner != null) {
                notificationController.updateNotification("Tor running \u00b7 VPN off", progress = false, progressValue = 0)
            } else {
                stopForegroundService(true)
                stopServiceSelf()
            }
        }
    }

    fun disconnect() {
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring disconnect: a stop is already tearing the cores down")
            return
        }
        val chainLive = chainEngine?.isActive == true
        val s = AppState.state.value
        if (!chainLive && !s.connected && !s.connecting && !s.reconnecting && !s.torRunning && s.socksEndpoint.isEmpty()) {
            Log.i(TAG, "Nothing to disconnect")
            return
        }
        val startedAt = SystemClock.elapsedRealtime()
        Log.i(TAG, "Disconnecting: TUN, tunnel and every Tor core")
        AppState.update {
            it.copy(
                stopping = true,
                connecting = false,
                connected = false,
                reconnecting = false,
                error = null,
                socksEndpoint = ""
            )
        }
        notificationController.updateNotification("Stopping", progress = true, progressValue = 0)
        ProxyChainManager.clearProbes()
        serviceScope.launch {
            lifecycleMutex.withLock {
                teardown()
            }
            val left = STOPPING_MIN_MS - (SystemClock.elapsedRealtime() - startedAt)
            if (left > 0) {
                Log.i(TAG, "cores are gone, holding STOPPING for another ${left}ms")
                delay(left)
            }
            Log.endSession("disconnected by user")
            Log.i(TAG, "disconnected: no Tor core is left running")
            AppState.update { it.copy(stopping = false, torRunning = false) }
            stopForegroundService(true)
            stopServiceSelf()
        }
    }

    fun teardownVpn() {
        statsController.stopAll()
        try { currentBackend?.stop() } catch (_: Exception) {}
        currentBackend = null
        try { HevSocks5Tunnel.stop() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        if (AppState.vpnStarted) {
            AppState.markStopped()
        }
    }

    fun teardown() {
        chainEngine?.shutdown()
        teardownVpn()
        try { TorSocksBridge.stop() } catch (_: Exception) {}
        try { ParallelTorManager.stopAllAndWait(Config.proxyPort) } catch (_: Exception) {}
        activeRunner = null
        dropCpu()
        if (AppState.vpnStarted) {
            AppState.markStopped()
        }
    }

    fun fail(message: String) {
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring '$message': a stop is already tearing the cores down")
            return
        }
        if (safeTorrcArmed) {
            safeTorrcArmed = false
            if (TorrcSettings.applyErrorFallback()) {
                Log.w(TAG, "connect failed ($message) \u2014 retrying once with the fallback torrc")
                Log.endSession("failed \u00b7 retrying with fallback torrc")
                teardown()
                AppState.markStopped()
                connect()
                return
            }
        }
        Log.e(TAG, message)
        Log.endSession("failed \u00b7 $message")
        AppState.update {
            it.copy(
                connecting = false,
                connected = false,
                reconnecting = false,
                torRunning = false,
                stopping = false,
                error = message,
                socksEndpoint = ""
            )
        }
        stopForegroundService(true)
        stopServiceSelf()
        AppState.markStopped()
        teardown()
    }

    suspend fun recoverTransport() {
        if (!recovering.compareAndSet(false, true)) return
        val startedAt = System.currentTimeMillis()
        holdCpu()
        try {
            val previous = activeRunner
            if (previous == null) {
                escalateToFullReconnect("no active transport")
                return
            }
            markReconnecting("rebuilding ${previous.name}")
            val winner = try {
                ParallelTorManager.restartTransport(
                    context = context,
                    basePort = Config.proxyPort,
                    sessionId = currentSession,
                    name = previous.name
                ) { snapshot ->
                    AppState.update {
                        it.copy(
                            transports = snapshot.mapValues { (_, r) ->
                                if (r.failed != null) -1 else r.progress()
                            }
                        )
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Transport rebuild failed: ${e.message}")
                escalateToFullReconnect(e.message ?: "transport rebuild failed")
                return
            }

            TorSocksBridge.repoint(winner.torSocksPort)
            activeRunner = winner
            AppState.update {
                it.copy(
                    transports = mapOf(winner.name to 100),
                    transport = winner.name,
                    reconnecting = false
                )
            }
            val seconds = (System.currentTimeMillis() - startedAt) / 1000
            Log.i(TAG, "Recovered via ${winner.name} in ${seconds}s (SOCKS5 ${winner.torSocksPort})")
            startForegroundService(
                VpnNotificationController.NOTIFICATION_ID,
                notificationController.buildNotification("Reconnected via ${winner.name} \u00b7 ${seconds}s", progress = false)
            )
            statsController.resetState()
            statsController.setLastAppliedExitCodes(ExitNodes.currentCodes())
            statsController.startExitLocator("127.0.0.1", Config.proxyPort) { winner.torSocksPort }
            statsController.startExitWatch { activeRunner }
        } catch (e: Exception) {
            Log.e(TAG, "Recovery failed", e)
            escalateToFullReconnect(e.message ?: "recovery failed")
        } finally {
            recovering.set(false)
            releaseCpu()
        }
    }

    private fun escalateToFullReconnect(reason: String) {
        Log.w(TAG, "Falling back to full reconnect ($reason)")
        markReconnecting("reconnecting")
        serviceScope.launch {
            teardown()
            connect()
        }
    }

    fun markReconnecting(reason: String) {
        if (AppState.state.value.stopping) {
            Log.w(TAG, "Ignoring reconnect ($reason): a stop is tearing cores down")
            return
        }
        Log.w(TAG, "Reconnecting: $reason")
        AppState.update { it.copy(reconnecting = true) }
        notificationController.updateNotification("Reconnecting\u2026", progress = false, progressValue = 0)
    }

    fun newIdentity() {
        val s = AppState.state.value
        if (!s.torRunning && !s.connected) {
            AppState.setHint(if (s.stopping) "Tor is restarting — press again in a moment" else "Tor is not running — connect first")
            return
        }
        if (Config.torChainMode != Config.TOR_CHAIN_NONE) {
            AppState.setHint("A proxy chain owns the exit — end the chain to rotate")
            return
        }
        val idle = SystemClock.elapsedRealtime() - lastIdentityAtMillis
        if (idle < identityCooldownMs) {
            AppState.setHint("Identity rotated ${(identityCooldownMs - idle) / 1000}s ago — try again shortly")
            return
        }
        val w = activeRunner
        if (w == null || w.controlPortLive <= 0) {
            AppState.setHint("No control port on the running client")
            Log.w(TAG, "New identity ignored: runner ${w?.name ?: "null"}, controlPort=${w?.controlPortLive ?: 0}")
            return
        }
        val beforeFlag = if (s.exitCode.isNotBlank()) statsController.flagLine(s.exitCode, s.exitName) else ""
        AppState.setIdentityBusy(true)
        AppState.setHint(if (beforeFlag.isBlank()) "Rotating identity\u2026" else "Rotating away from $beforeFlag\u2026")
        serviceScope.launch {
            val ok = runCatching {
                TorControl.signalNewIdentity(w.controlPortLive, w.controlDataDir, "NewIdentity")
            }.getOrElse { e ->
                Log.w(TAG, "New identity failed: ${e.message}")
                false
            }
            lastIdentityAtMillis = SystemClock.elapsedRealtime()
            AppState.setIdentityBusy(false)
            if (ok) {
                statsController.noteRotationEvent()
                delay(4_000)
                statsController.startExitLocator("127.0.0.1", Config.proxyPort) { w.torSocksPort }
                AppState.setHint("Fresh circuits requested — waiting for new exit")
            } else {
                AppState.setHint("Tor refused rotation (control port)")
            }
        }
    }

    fun chainConnect(host: String, port: Int) {
        if (host.isBlank()) {
            Log.w(TAG, "chain connect without a host; ignoring")
            return
        }
        if (AppState.state.value.stopping) {
            Log.i(TAG, "Ignoring chain connect: a stop is tearing cores down")
            return
        }
        if (!TorSocksBridge.isRunning()) {
            Log.w(TAG, "chain connect without a Tor bridge; ignoring")
            return
        }
        serviceScope.launch {
            val engine = getChainEngine()
            if (engine.isActive) {
                engine.switchTo(host, port)
                return@launch
            }
            Log.i(TAG, "chain connect: $host:$port via SOCKS 127.0.0.1:${Config.proxyPort}")
            teardownVpn()
            engine.start(host, port)
        }
    }

    fun switchTorChainMode(mode: String) {
        Config.torChainMode = mode
        val engine = chainEngine
        if (engine != null && engine.isActive) {
            engine.stopWithoutRestore()
        }
        val targetMode = when (mode) {
            Config.TOR_CHAIN_WARP -> TorSocksBridge.ChainMode.WARP
            Config.TOR_CHAIN_AMNEZIA -> TorSocksBridge.ChainMode.AMNEZIA
            Config.TOR_CHAIN_MASQUE -> TorSocksBridge.ChainMode.MASQUE
            else -> TorSocksBridge.ChainMode.NONE
        }
        TorSocksBridge.chainMode = targetMode

        if (vpnInterface == null && activeRunner != null && TorSocksBridge.isRunning()) {
            serviceScope.launch {
                establishTunnel(activeRunner!!, "127.0.0.1", Config.proxyPort)
            }
        }

        val (hostLabel, desc) = when (mode) {
            Config.TOR_CHAIN_WARP -> "WARP Anycast" to "Tor \u2192 Cloudflare WARP"
            Config.TOR_CHAIN_AMNEZIA -> "AmneziaWG" to "Tor \u2192 AmneziaWG"
            Config.TOR_CHAIN_MASQUE -> "MASQUE H3" to "Tor \u2192 MASQUE"
            else -> "" to ""
        }
        if (targetMode != TorSocksBridge.ChainMode.NONE) {
            val needsTorTcp = mode == Config.TOR_CHAIN_WARP || mode == Config.TOR_CHAIN_AMNEZIA || mode == Config.TOR_CHAIN_MASQUE
            AppState.updateChain {
                it.copy(
                    status = if (needsTorTcp) AppState.ChainStatus.FAILED else AppState.ChainStatus.CONNECTED,
                    host = hostLabel,
                    port = 0,
                    message = if (needsTorTcp) "WG/QUIC-over-Tor not supported \u00b7 egress falls to Tor (use standalone engine or Free Nodes)" else desc
                )
            }
        } else {
            AppState.updateChain { AppState.ChainState() }
        }
        AppState.update { it.copy(exitCode = "", exitName = "", exitIp = "", torExitCode = "", torExitName = "", torExitIp = "", chainExitCode = "", chainExitName = "", chainExitIp = "") }
        statsController.startExitLocator("127.0.0.1", Config.proxyPort) { activeRunner?.torSocksPort ?: -1 }
        Log.i(TAG, "Switched Tor chain mode to: $mode")
    }

    fun chainDisconnect() {
        val engine = chainEngine
        if (engine != null && engine.isActive) {
            Log.i(TAG, "chain disconnect requested")
            engine.stop()
        }
        Config.torChainMode = Config.TOR_CHAIN_NONE
        TorSocksBridge.chainMode = TorSocksBridge.ChainMode.NONE
        AppState.updateChain { AppState.ChainState() }
        AppState.update { it.copy(exitCode = "", exitName = "", exitIp = "", torExitCode = "", torExitName = "", torExitIp = "", chainExitCode = "", chainExitName = "", chainExitIp = "") }
        statsController.startExitLocator("127.0.0.1", Config.proxyPort) { activeRunner?.torSocksPort ?: -1 }
    }

    fun onChainEstablished(host: String, port: Int) {
        if (!AppState.vpnStarted) AppState.markStarted()
        Log.i(TAG, "chain established: $host:$port")
        statsController.startExitLocator("127.0.0.1", Config.proxyPort) { activeRunner?.torSocksPort ?: -1 }
        serviceScope.launch {
            val ms = ProxyChainManager.measureChainUrl()
            AppState.updateChain { it.copy(urlMs = ms) }
            onChainStateChanged()
        }
    }

    fun onChainExhausted(reason: String) {
        Log.w(TAG, "chain exhausted: $reason — restoring plain Tor VPN")
        AppState.updateChain {
            it.copy(status = AppState.ChainStatus.FAILED, message = "back to Tor: $reason")
        }
        restoreTorVpn()
    }

    fun onChainStoppedByUser() {
        Log.i(TAG, "chain stopped by user — restoring plain Tor VPN")
        ProxyChainManager.clearProbes()
        AppState.updateChain { AppState.ChainState() }
        restoreTorVpn()
    }

    fun restoreTorVpn() {
        serviceScope.launch {
            if (AppState.vpnStarted) AppState.markStopped()
            val w = activeRunner
            if (w == null || !w.isReady() || !TorSocksBridge.isRunning()) {
                Log.i(TAG, "chain restore: engines not reusable, running a full connect")
                connect()
            } else {
                Log.i(TAG, "chain restore: establishing VPN on live engines")
                AppState.update {
                    it.copy(
                        stopping = false,
                        connecting = false,
                        reconnecting = false,
                        torRunning = true,
                        connected = false,
                        error = null,
                        socksEndpoint = ""
                    )
                }
                notificationController.updateNotification("Tor running \u00b7 VPN on", progress = false, progressValue = 0)
                try {
                    establishTunnel(w, "127.0.0.1", Config.proxyPort)
                } catch (e: Exception) {
                    Log.e(TAG, "chain restore failed", e)
                    fail("Restore failed: ${e.message}")
                }
            }
        }
    }

    fun onChainStateChanged() {
        val chain = AppState.chainState.value
        when (chain.status) {
            AppState.ChainStatus.CONNECTING -> notificationController.updateNotification(
                "Chain → ${chain.host}:${chain.port}" + (if (chain.message.isNotBlank()) " · ${chain.message}" else ""),
                progress = true,
                progressValue = 0
            )
            AppState.ChainStatus.CONNECTED -> notificationController.updateNotification(
                "DeltaTor · chain → ${chain.host}" + (if (chain.urlMs >= 0) " · ${chain.urlMs}ms" else ""),
                progress = false,
                progressValue = 0
            )
            AppState.ChainStatus.STOPPING -> notificationController.updateNotification(
                "Chain stopping…", progress = true, progressValue = 0
            )
            else -> Unit
        }
    }
}
