package com.musicses.vlessvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat

private const val TAG        = "VlessVpnService"
private const val CH_ID      = "vless_vpn"
private const val NOTIF_ID   = 1
private const val VPN_ADDR   = "10.233.233.1"
private const val VPN_PREFIX = 24
private const val MTU        = 1500

class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.musicses.vlessvpn.START"
        const val ACTION_STOP  = "com.musicses.vlessvpn.STOP"

        const val BROADCAST    = "com.musicses.vlessvpn.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_IN     = "bytes_in"
        const val EXTRA_OUT    = "bytes_out"
    }

    private var tun: ParcelFileDescriptor? = null
    private var packetTunnel: PacketTunnel? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP  -> { stopVpn(); stopSelf(); START_NOT_STICKY }
            ACTION_START -> {
                // startForeground 必须在主线程 onStartCommand 里调用
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> START_STICKY
        }
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
    override fun onRevoke()  { stopVpn(); super.onRevoke() }

    private fun startVpnInBackground() {
        if (running) return
        running = true

        Thread {
            try {
                val cfg = VlessConfig.load(this)

                // 建立 TUN 接口
                val tunBuilder = Builder()
                    .setSession("VlessVPN")
                    .setMtu(MTU)
                    .addAddress(VPN_ADDR, VPN_PREFIX)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(cfg.dns1)
                    .addDnsServer(cfg.dns2)
                    .addDisallowedApplication(packageName)

                val tunPfd = tunBuilder.establish() ?: run {
                    broadcast("ERROR"); return@Thread
                }
                tun = tunPfd

                // 启动 PacketTunnel：直接在 TUN fd 上读写 IP 包并转发
                val pt = PacketTunnel(tunPfd.fileDescriptor, cfg) { bytesIn, bytesOut ->
                    sendBroadcast(
                        Intent(BROADCAST)
                            .putExtra(EXTRA_STATUS, "CONNECTED")
                            .putExtra(EXTRA_IN, bytesIn)
                            .putExtra(EXTRA_OUT, bytesOut)
                    )
                    updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
                }
                packetTunnel = pt
                pt.start()

                Log.i(TAG, "VPN up, TUN=$VPN_ADDR")
                broadcast("CONNECTED")
                updateNotif("Connected")

            } catch (e: Exception) {
                Log.e(TAG, "startVpn error: ${e.message}")
                broadcast("ERROR")
                stopVpn()
                stopSelf()
            }
        }.also { it.isDaemon = true }.start()
    }

    private fun stopVpn() {
        if (!running) return
        running = false
        packetTunnel?.stop(); packetTunnel = null
        runCatching { tun?.close() }; tun = null
        broadcast("DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun buildNotif(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH_ID) == null)
            nm.createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            )
        val openPi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, VlessVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle("VLESS VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openPi)
            .addAction(0, "Disconnect", stopPi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotif(text: String) =
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIF_ID, buildNotif(text))

    private fun broadcast(status: String) =
        sendBroadcast(Intent(BROADCAST).putExtra(EXTRA_STATUS, status))

    private fun fmt(b: Long) = when {
        b < 1024L        -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else             -> "${"%.1f".format(b / 1048576.0)}M"
    }
}
