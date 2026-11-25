package io.deltator

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.deltator.core.service.TunnelSessionCoordinator
import io.deltator.core.service.VpnNotificationController
import io.deltator.tunnel.ExitNodes
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class TorVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "io.deltator.CONNECT"
        const val ACTION_DISCONNECT = "io.deltator.DISCONNECT"
        const val ACTION_START_VPN = "io.deltator.START_VPN"
        const val ACTION_STOP_VPN = "io.deltator.STOP_VPN"
        const val ACTION_CHAIN_CONNECT = "io.deltator.CHAIN_CONNECT"
        const val ACTION_CHAIN_DISCONNECT = "io.deltator.CHAIN_DISCONNECT"
        const val ACTION_NEW_IDENTITY = "io.deltator.NEW_IDENTITY"
        const val ACTION_OPEN_EXIT_SHEET = "io.deltator.OPEN_EXIT_SHEET"
        const val ACTION_APPLY_EXIT = "io.deltator.APPLY_EXIT"
        const val ACTION_LOCATE_EXIT = "io.deltator.LOCATE_EXIT"
        internal const val EXTRA_CHAIN_HOST = "io.deltator.extra.chain_host"
        internal const val EXTRA_CHAIN_PORT = "io.deltator.extra.chain_port"
        internal const val EXTRA_CHAIN_MODE = "io.deltator.extra.chain_mode"
        const val CHANNEL_VPN_STATUS = VpnNotificationController.CHANNEL_VPN_STATUS
        const val CHANNEL_UPDATES = VpnNotificationController.CHANNEL_UPDATES
        const val NOTIFICATION_ID = VpnNotificationController.NOTIFICATION_ID

        private const val TAG = "TorVpnService"
        private const val VPN_MTU = 1280
        private const val VPN_ADDRESS = "10.255.255.1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val DEFAULT_DNS = "8.8.8.8"
        const val RECOVERY_TITLE = TunnelSessionCoordinator.RECOVERY_TITLE
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var notificationController: VpnNotificationController
    private lateinit var coordinator: TunnelSessionCoordinator

    private var establishFailureReason: String? = null

    override fun onCreate() {
        super.onCreate()
        notificationController = VpnNotificationController(this)
        coordinator = TunnelSessionCoordinator(
            context = this,
            serviceScope = serviceScope,
            notificationController = notificationController,
            establishVpnInterface = { establishVpnInterface() },
            getEstablishFailureReason = { establishFailureReason },
            chainBuilderFactory = { chainBuilderForSstp() },
            startForegroundService = { id, notif -> startForeground(id, notif) },
            stopForegroundService = { remove -> stopForeground(if (remove) STOP_FOREGROUND_REMOVE else STOP_FOREGROUND_DETACH) },
            stopServiceSelf = { stopSelf() }
        )
        coordinator.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            val state = AppState.state.value
            if (!AppState.vpnStarted && !state.connected && !state.connecting && !state.reconnecting) {
                Log.i(TAG, "onStartCommand received null intent and VPN is inactive; stopping service")
                stopSelf(startId)
                return START_NOT_STICKY
            }
            return START_STICKY
        }
        when (intent.action) {
            ACTION_CONNECT -> coordinator.connect()
            ACTION_DISCONNECT -> coordinator.disconnect()
            ACTION_START_VPN -> coordinator.startVpn()
            ACTION_STOP_VPN -> coordinator.stopVpn()
            ACTION_CHAIN_CONNECT -> {
                val mode = intent.getStringExtra(EXTRA_CHAIN_MODE)
                val host = intent.getStringExtra(EXTRA_CHAIN_HOST) ?: ""
                val port = intent.getIntExtra(EXTRA_CHAIN_PORT, Config.sstpPort)
                if (mode != null && mode != Config.TOR_CHAIN_FREE_NODES) {
                    coordinator.switchTorChainMode(mode)
                } else {
                    Config.torChainMode = Config.TOR_CHAIN_FREE_NODES
                    coordinator.chainConnect(host, port)
                }
            }
            ACTION_CHAIN_DISCONNECT -> coordinator.chainDisconnect()
            ACTION_NEW_IDENTITY -> coordinator.newIdentity()
            ACTION_APPLY_EXIT -> serviceScope.launch {
                coordinator.statsController.applyExitCodesLive(
                    ExitNodes.currentCodes(), "action", coordinator.activeRunner
                )
            }
            ACTION_LOCATE_EXIT -> coordinator.statsController.startExitLocator("127.0.0.1", Config.proxyPort) {
                coordinator.activeRunner?.torSocksPort ?: -1
            }
            "io.deltator.ACTION_DEBUG_SET_WARP" -> {
                val json = intent.getStringExtra("warp_config")
                if (!json.isNullOrBlank()) {
                    Config.warpConfig = json
                    Log.i(TAG, "Debug: WARP config set (${json.length} chars)")
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        try {
            coordinator.stop()
        } catch (e: Exception) {
            Log.e(TAG, "teardown failed during onDestroy", e)
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        if (Config.proxyOnlyMode) {
            Log.i(TAG, "onRevoke ignored: proxy mode holds no VPN interface")
            return
        }
        super.onRevoke()
    }

    fun chainBuilderForSstp(): Builder = Builder().also {
        it.setSession("DeltaTor SSTP")
    }

    fun onChainEstablished(host: String, port: Int) = coordinator.onChainEstablished(host, port)
    fun onChainExhausted(reason: String) = coordinator.onChainExhausted(reason)
    fun onChainStoppedByUser() = coordinator.onChainStoppedByUser()
    fun onChainStateChanged() = coordinator.onChainStateChanged()

    private fun establishVpnInterface(): ParcelFileDescriptor? {
        establishFailureReason = null
        if (Config.proxyOnlyMode) {
            Log.i(TAG, "Proxy mode: not establishing a TUN, SOCKS5 stays on 127.0.0.1:${Config.proxyPort}")
            return null
        }
        if (Config.dualStackIpv6) {
            val tun = tryCreateVpnInterface(enableIpv6 = true)
            if (tun != null) return tun
            Log.w(TAG, "Failed to establish Dual-Stack IPv6 TUN; falling back to IPv4-only")
        }
        return tryCreateVpnInterface(enableIpv6 = false)
    }

    private fun tryCreateVpnInterface(enableIpv6: Boolean): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession("DeltaTor")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(DEFAULT_DNS)

            if (enableIpv6) {
                try {
                    builder.addAddress("fd00::1", 64)
                    builder.addRoute("::", 0)
                    builder.addDnsServer("2001:4860:4860::8888")
                    Log.i(TAG, "Dual-Stack IPv6 configured (fd00::1/64, route ::/0)")
                } catch (e: Exception) {
                    Log.w(TAG, "Dual-Stack IPv6 not supported or refused: ${e.message}")
                }
            }
            val picks = Config.splitTunnelSelected.filter { it != packageName }
            val vpnOnly = Config.splitTunnelMode == Config.SPLIT_MODE_VPN
            val usingAllowList = Config.splitTunnelEnabled && vpnOnly

            if (usingAllowList) {
                Log.i(TAG, tunSection { line("self", "$packageName kept off tunnel by not being allow-listed") })
            } else {
                try {
                    builder.addDisallowedApplication(packageName)
                    Log.i(TAG, tunSection { line("self", "$packageName disallowed from VPN") })
                } catch (e: Exception) {
                    Log.e(TAG, tunSection { line("self", "could not be excluded: ${e.javaClass.name}: ${e.message}") }, e)
                }
            }

            Log.i(TAG, tunSection { tunSectionHeader(this, picks, vpnOnly) })
            if (Config.splitTunnelEnabled) {
                var applied = 0
                var failed = 0
                for (pkg in picks) {
                    Log.i(TAG, tunSection {
                        line("resolve", resolvePick(pkg))
                        line("codePoints", pkg.codePoints().toArray().joinToString(" ") { "U+%04X".format(it) })
                    })
                    val verb = if (vpnOnly) "addAllowedApplication" else "addDisallowedApplication"
                    try {
                        if (vpnOnly) builder.addAllowedApplication(pkg) else builder.addDisallowedApplication(pkg)
                        applied++
                        Log.i(TAG, tunSection { line(verb, "ok '$pkg'") })
                    } catch (e: Exception) {
                        failed++
                        Log.e(TAG, tunSection { line(verb, "FAILED '$pkg' -> ${e.javaClass.name}: ${e.message}") }, e)
                    }
                }
                builder.addRoute(VPN_ROUTE, 0)
                Log.i(TAG, "Split tunnel: ${if (vpnOnly) "VPN-only" else "Bypass"}, $applied of ${picks.size} applied, $failed failed")
                if (vpnOnly && applied == 0) {
                    val reason = if (picks.isEmpty()) {
                        "VPN-only split tunnelling has no apps picked, so nothing would go through Tor. Pick at least one app, or let picked apps bypass Tor."
                    } else {
                        "None of the ${picks.size} app(s) picked for VPN-only split tunnelling could be routed, so nothing would go through Tor. Re-pick them."
                    }
                    establishFailureReason = reason
                    Log.e(TAG, reason)
                    return null
                }
            } else {
                builder.addRoute(VPN_ROUTE, 0)
                Log.i(TAG, "Split tunnel: off, every app goes through Tor")
            }
            builder.setBlocking(Config.strictKillswitch)
            val tun = builder.establish()
            Log.i(TAG, tunSection {
                line("establish", if (tun == null) "returned null" else "ok fd=${tun.fd}")
                line("session", "DeltaTor mtu=$VPN_MTU addr=$VPN_ADDRESS/32 dns=$DEFAULT_DNS ipv6=$enableIpv6")
            })
            tun
        } catch (e: Exception) {
            Log.e(TAG, tunSection { line("establish", "threw ${e.javaClass.name}: ${e.message}") }, e)
            null
        }
    }

    private fun tunSection(body: StringBuilder.() -> Unit): String {
        val sb = StringBuilder()
        sb.appendLine("tun | ---- begin ----")
        sb.body()
        sb.append("tun | ---- end ----")
        return sb.toString()
    }

    private fun StringBuilder.line(label: String, value: String) {
        appendLine("tun | $label: $value")
    }

    private fun tunSectionHeader(sb: StringBuilder, picks: List<String>, vpnOnly: Boolean) {
        sb.line("self", "$packageName (uid=${android.os.Process.myUid()})")
        sb.line("device", "${Build.MANUFACTURER} ${Build.MODEL} android=${Build.VERSION.SDK_INT} release=${Build.VERSION.RELEASE}")
        sb.line("proxyOnly", Config.proxyOnlyMode.toString())
        sb.line("splitEnabled", Config.splitTunnelEnabled.toString())
        sb.line("mode", Config.splitTunnelMode)
        sb.line("meaning", if (vpnOnly) "picks go through Tor, all other apps direct" else "picks stay off Tor, all other apps tunnelled")
        sb.line("storedPickCount", Config.splitTunnelSelected.size.toString())
        sb.line("storedPicks", Config.splitTunnelSelected.joinToString(" ") { "[$it]" })
        sb.line("picksAfterSelfFilter", picks.size.toString())
        sb.line("picksAfterSelfFilterList", picks.joinToString(" ") { "[$it]" })
        sb.line("route", "$VPN_ROUTE/0")
        sb.line("blocking", "false")
    }

    private fun resolvePick(pkg: String): String {
        val pm = packageManager
        val plain = runCatching { pm.getApplicationInfo(pkg, 0) }
        val installed = runCatching { pm.getApplicationInfo(pkg, PackageManager.MATCH_UNINSTALLED_PACKAGES) }
        val launchable = runCatching { pm.getLaunchIntentForPackage(pkg) != null }
        val label = runCatching { pm.getApplicationLabel(plain.getOrThrow()).toString() }
        return buildString {
            append("pkg='").append(pkg).append("' len=").append(pkg.length)
            append(" isSelf=").append(pkg == packageName)
            append(" builderWouldSee=").append(if (plain.isSuccess) "yes" else "NO(${plain.exceptionOrNull()?.javaClass?.simpleName})")
            append(" uid=").append(plain.getOrNull()?.uid?.toString() ?: "?")
            append(" system=").append(((plain.getOrNull()?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0)
            append(" enabled=").append(plain.getOrNull()?.enabled?.toString() ?: "?")
            append(" launchable=").append(launchable.getOrNull()?.toString() ?: "?")
            append(" label='").append(label.getOrNull() ?: "?").append("'")
            append(" notFullyInstalled=").append(
                if (installed.isFailure) "lookup-error(${installed.exceptionOrNull()?.javaClass?.simpleName})" else "no"
            )
        }
    }
}