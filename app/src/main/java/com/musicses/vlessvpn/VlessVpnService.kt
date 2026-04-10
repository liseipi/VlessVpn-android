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

private const val TAG = "VlessVpnService"
private const val CH_ID = "vless_vpn"
private const val NOTIF_ID = 1
private const val VPN_ADDR = "10.233.233.1"
private const val VPN_PREFIX = 24
private const val MTU = 1500

class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.musicses.vlessvpn.START"
        const val ACTION_STOP = "com.musicses.vlessvpn.STOP"
        const val BROADCAST = "com.musicses.vlessvpn.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_IN = "bytes_in"
        const val EXTRA_OUT = "bytes_out"
    }

    private var tun: ParcelFileDescriptor? = null
    private var tun2socks: Tun2Socks? = null
    private var socksServer: LocalSocks5Server? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); stopSelf(); START_NOT_STICKY }
            ACTION_START -> {
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> START_STICKY
        }
    }

    private fun startVpnInBackground() {
        if (running) return
        running = true

        Thread {
            try {
                val cfg = ConfigStore.loadActive(this)

                // 1. 启动本地 SOCKS5（你的原有逻辑）
                socksServer = LocalSocks5Server(cfg, this) { inB, outB ->
                    sendBroadcast(Intent(BROADCAST).apply {
                        putExtra(EXTRA_STATUS, "CONNECTED")
                        putExtra(EXTRA_IN, inB)
                        putExtra(EXTRA_OUT, outB)
                        setPackage(packageName)
                    })
                    updateNotif("↓ ${fmt(inB)} ↑ ${fmt(outB)}")
                }
                val socksPort = socksServer!!.start()
                Log.i(TAG, "✓ SOCKS5 on 127.0.0.1:$socksPort")

                // 2. 建立 TUN
                val tunPfd = Builder()
                    .setSession("VlessVPN")
                    .setMtu(MTU)
                    .addAddress(VPN_ADDR, VPN_PREFIX)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(cfg.dns1)
                    .addDnsServer(cfg.dns2)
                    .addDisallowedApplication(packageName)
                    .establish() ?: throw Exception("TUN establish failed")

                tun = tunPfd

                // 3. 启动 tun2socks（原生库，最稳定）
                tun2socks = Tun2Socks(this)
                val success = tun2socks!!.startTun2Socks(
                    tunPfd,
                    MTU,
                    "127.0.0.1",
                    socksPort,
                    enableUdpRelay = true
                )

                if (!success) throw Exception("tun2socks start failed")

                Log.i(TAG, "✓ VPN Connected (tun2socks + VLESS)")
                broadcast("CONNECTED")
                updateNotif("${cfg.name} • Connected")

            } catch (e: Exception) {
                Log.e(TAG, "Start failed", e)
                broadcast("ERROR")
                stopVpn()
            }
        }.start()
    }

    private fun stopVpn() {
        running = false
        tun2socks?.stopTun2Socks()
        socksServer?.stop()
        tun?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
        broadcast("DISCONNECTED")
    }

    private fun cleanup() {
        runCatching { socksServer?.stop() }; socksServer = null
        VlessTunnel.clearSharedClients()
        runCatching { tun?.close() }; tun = null
    }

    // ── 通知 ──────────────────────────────────────────────────────────────────

    private fun broadcast(status: String) {
        Log.d(TAG, "Status → $status")
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, status); setPackage(packageName)
        })
    }

    private fun broadcastStats(bytesIn: Long, bytesOut: Long) {
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, "CONNECTED")
            putExtra(EXTRA_IN, bytesIn); putExtra(EXTRA_OUT, bytesOut)
            setPackage(packageName)
        })
    }

    private fun buildNotif(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            )
        }
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

    private fun updateNotif(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotif(text))
    }

    private fun fmt(b: Long) = when {
        b < 1024L        -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else             -> "${"%.1f".format(b / 1048576.0)}M"
    }
}