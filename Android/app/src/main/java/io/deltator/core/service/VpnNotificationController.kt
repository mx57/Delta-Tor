package io.deltator.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import io.deltator.AppState
import io.deltator.Config
import io.deltator.MainActivity
import io.deltator.R
import io.deltator.TorVpnService
import io.deltator.core.backend.EngineMode

class VpnNotificationController(private val context: Context) {

    companion object {
        const val CHANNEL_VPN_STATUS = "vpn_status"
        const val CHANNEL_UPDATES = "deltator_updates"
        const val NOTIFICATION_ID = 1
    }

    private val notificationManager: NotificationManager by lazy {
        context.getSystemService(NotificationManager::class.java)
    }

    private var lastRenderedText: String = ""

    init {
        createChannels()
    }

    private fun createChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val vpnChannel = NotificationChannel(
                CHANNEL_VPN_STATUS,
                "VPN Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live DeltaTor VPN connection status and traffic stats"
                setShowBadge(false)
            }
            val updateChannel = NotificationChannel(
                CHANNEL_UPDATES,
                "DeltaTor Updates",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "App update notifications"
            }
            notificationManager.createNotificationChannel(vpnChannel)
            notificationManager.createNotificationChannel(updateChannel)
        }
    }

    fun buildNotification(text: String, progress: Boolean, progressValue: Int = 0): Notification {
        return withStateActions(
            NotificationCompat.Builder(context, CHANNEL_VPN_STATUS)
                .setSmallIcon(R.drawable.ic_tor)
                .setContentTitle("DeltaTor")
                .setContentText(text)
                .setContentIntent(mainPendingIntent)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setProgress(100, progressValue, progress)
        ).build()
    }

    fun postNotification(notification: Notification) {
        lastRenderedText = ""
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    fun updateNotification(text: String, progress: Boolean, progressValue: Int = 0) {
        postNotification(buildNotification(text, progress, progressValue))
    }

    fun notifyTraffic(text: String) {
        val parts = text.split('|')
        val title = parts.getOrNull(0) ?: "DeltaTor"
        val body = parts.getOrNull(1) ?: ""
        val builder = NotificationCompat.Builder(context, CHANNEL_VPN_STATUS)
            .setSmallIcon(R.drawable.ic_tor)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
        postNotification(withStateActions(builder).build())
    }

    fun trafficText(
        upSpeed: Float,
        downSpeed: Float,
        txBytes: Long,
        rxBytes: Long
    ): String {
        val reconnecting = AppState.state.value.reconnecting
        return if (reconnecting) {
            "DeltaTor \u2014 Reconnecting|Restoring the tunnel\u2026"
        } else {
            "DeltaTor \u2014 Connected|\u2191 ${formatBytes(upSpeed)}/s  \u2193 ${formatBytes(downSpeed)}/s\n" +
                "Total: \u2191 ${formatBytes(txBytes)}  \u2193 ${formatBytes(rxBytes)}"
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var v = bytes.toFloat()
        var idx = 0
        while (v >= 1024 && idx < units.size - 1) {
            v /= 1024f
            idx++
        }
        return if (idx == 0) "${v.toInt()} ${units[idx]}" else String.format(java.util.Locale.US, "%.1f %s", v, units[idx])
    }

    fun formatBytes(bytes: Float): String = formatBytes(bytes.toLong())

    fun getLastRenderedText(): String = lastRenderedText

    fun setLastRenderedText(text: String) {
        lastRenderedText = text
    }

    fun withStateActions(builder: NotificationCompat.Builder): NotificationCompat.Builder {
        val s = AppState.state.value
        builder.addAction(R.drawable.ic_notification_disconnect, "Disconnect", disconnectPendingIntent)
        builder.addAction(R.drawable.ic_notification_locate, "Location", exitSheetPendingIntent)
        if ((s.torRunning || s.connected) &&
            s.engineMode.equals(EngineMode.TOR_RACING.id, ignoreCase = true) &&
            Config.torChainMode == Config.TOR_CHAIN_NONE
        ) {
            builder.addAction(R.drawable.ic_notification_refresh, "New identity", newIdentityPendingIntent)
        }
        when {
            AppState.chainState.value.status == AppState.ChainStatus.CONNECTING ||
                AppState.chainState.value.status == AppState.ChainStatus.CONNECTED ->
                builder.addAction(R.drawable.ic_notification_stop, "Stop VPN", chainDisconnectPendingIntent)
            s.connected -> builder.addAction(R.drawable.ic_notification_stop, "Stop VPN", stopVpnPendingIntent)
            s.torRunning && !Config.proxyOnlyMode ->
                builder.addAction(R.drawable.ic_notification_start, "Start VPN", startVpnPendingIntent)
        }
        return builder
    }

    val mainPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        PendingIntent.getActivity(
            context,
            1,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val disconnectPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, TorVpnService::class.java).apply {
            action = TorVpnService.ACTION_DISCONNECT
        }
        PendingIntent.getService(
            context,
            2,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val stopVpnPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, TorVpnService::class.java).apply {
            action = TorVpnService.ACTION_STOP_VPN
        }
        PendingIntent.getService(
            context,
            3,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val startVpnPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, TorVpnService::class.java).apply {
            action = TorVpnService.ACTION_START_VPN
        }
        PendingIntent.getService(
            context,
            4,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val chainDisconnectPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, TorVpnService::class.java).apply {
            action = TorVpnService.ACTION_CHAIN_DISCONNECT
        }
        PendingIntent.getService(
            context,
            5,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val newIdentityPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, TorVpnService::class.java).apply {
            action = TorVpnService.ACTION_NEW_IDENTITY
        }
        PendingIntent.getService(
            context,
            6,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    val exitSheetPendingIntent: PendingIntent by lazy {
        val intent = Intent(context, MainActivity::class.java).apply {
            action = TorVpnService.ACTION_OPEN_EXIT_SHEET
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        PendingIntent.getActivity(
            context,
            7,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}
