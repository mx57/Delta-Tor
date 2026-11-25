package io.deltator.core.backend

import android.content.Context
import android.os.ParcelFileDescriptor
import io.deltator.Config
import io.deltator.tunnel.HevSocks5Tunnel
import io.deltator.tunnel.ParallelTorManager
import io.deltator.tunnel.TorRunner
import io.deltator.tunnel.TorSocksBridge
import io.deltator.util.AppLog as Log

/**
 * TunnelBackend implementation wrapping the Tor Racing core + HevSocks5Tunnel.
 *
 * Guarantees atomic rollback of [ParallelTorManager] and [TorSocksBridge] on partial
 * startup failures or cancellation to prevent leaking child processes or TUN descriptors.
 */
class TorTunnelBackend(
    private val context: Context,
    private val activeRunnerProvider: () -> TorRunner?
) : TunnelBackend {

    override val id: String = EngineMode.TOR_RACING.id
    override val displayName: String = EngineMode.TOR_RACING.title

    @Volatile
    private var running = false

    override val isRunning: Boolean
        get() = running

    override suspend fun start(tunFd: ParcelFileDescriptor): Boolean {
        return try {
            val runner = activeRunnerProvider()
            if (runner == null) {
                Log.e(TAG, "Cannot start TorTunnelBackend: no active Tor runner bootstrapped")
                rollback()
                return false
            }

            val res = HevSocks5Tunnel.start(
                tunFd = tunFd,
                socksAddress = "127.0.0.1",
                socksPort = Config.proxyPort,
                enableUdpTunneling = true,
                mtu = 1280
            )
            if (res.isFailure) {
                Log.e(TAG, "HevSocks5Tunnel failed to start with Tor backend: ${res.exceptionOrNull()?.message}; rolling back")
                rollback()
                return false
            }

            running = true
            Log.i(TAG, "TorTunnelBackend successfully started on tunFd=${tunFd.fd}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Exception starting TorTunnelBackend; executing fail-closed rollback", e)
            rollback()
            false
        }
    }

    private fun rollback() {
        try { HevSocks5Tunnel.stop() } catch (e: Exception) { Log.w(TAG, "Error stopping HevSocks5Tunnel", e) }
        try { TorSocksBridge.stop() } catch (e: Exception) { Log.w(TAG, "Error stopping TorSocksBridge", e) }
        try { ParallelTorManager.stopAll() } catch (e: Exception) { Log.w(TAG, "Error stopping ParallelTorManager", e) }
        running = false
    }

    override fun stop() {
        rollback()
    }

    override fun getStats(): BackendStats? {
        val s = HevSocks5Tunnel.getStats() ?: return null
        return BackendStats(s.rxBytes, s.txBytes)
    }

    companion object {
        private const val TAG = "TorTunnelBackend"
    }
}
