package io.deltator.core.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import io.deltator.util.AppLog as Log

class VpnNetworkMonitor(
    private val context: Context,
    private val onScreenStateChanged: (isScreenOff: Boolean) -> Unit,
    private val onNetworkLost: () -> Unit,
    private val onNetworkAvailable: (wasDown: Boolean, switched: Boolean) -> Unit
) {
    companion object {
        private const val TAG = "VpnNetworkMonitor"
    }

    private var screenReceiver: BroadcastReceiver? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    var isScreenOff: Boolean = false
        private set

    @Volatile
    var linkUp: Boolean = true
        private set

    fun start() {
        registerScreenReceiver()
        registerNetworkCallback()
    }

    fun stop() {
        unregisterScreenReceiver()
        unregisterNetworkCallback()
    }

    private fun registerScreenReceiver() {
        if (screenReceiver != null) return
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        isScreenOff = true
                        Log.i(TAG, "Battery Guard: screen off, switching to low-power profile")
                        onScreenStateChanged(true)
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        isScreenOff = false
                        Log.i(TAG, "Battery Guard: screen on, active profile restored")
                        onScreenStateChanged(false)
                    }
                }
            }
        }
        screenReceiver = receiver
        try {
            context.registerReceiver(receiver, filter)
        } catch (e: Exception) {
            Log.w(TAG, "Could not register screen receiver: ${e.message}")
        }
    }

    private fun unregisterScreenReceiver() {
        val receiver = screenReceiver ?: return
        screenReceiver = null
        try {
            context.unregisterReceiver(receiver)
        } catch (_: Exception) {}
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            private var lastNetwork: Network? = null

            override fun onLost(network: Network) {
                if (cm.activeNetwork != null) return
                linkUp = false
                Log.w(TAG, "Network lost")
                onNetworkLost()
            }

            override fun onAvailable(network: Network) {
                val switched = lastNetwork != null && lastNetwork != network
                lastNetwork = network
                val wasDown = !linkUp
                linkUp = true
                Log.i(TAG, "Network available (switched=$switched, wasDown=$wasDown)")
                onNetworkAvailable(wasDown, switched)
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
            linkUp = cm.activeNetwork != null
        } catch (e: Exception) {
            Log.w(TAG, "Network callback unavailable: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            (context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager)
                ?.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            Log.d(TAG, "unregisterNetworkCallback: ${e.message}")
        }
    }
}
