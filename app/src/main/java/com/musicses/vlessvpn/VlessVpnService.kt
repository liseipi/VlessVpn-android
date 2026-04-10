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
import java.util.Collections

private const val TAG = "VlessVpnService"
private const val CH_ID = "vless_vpn"
private const val NOTIF_ID = 1
private const val VPN_ADDR = "10.233.233.1"
private const val VPN_PREFIX = 24
private const val MTU = 1500

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
    private var socksServer: LocalSocks5Server? = null
    private var tun2socksThread: Thread? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                Log.i(TAG, "Received STOP action")
                stopVpn(); stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> {
                Log.i(TAG, "Received START action")
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> START_STICKY
        }
    }

    override fun onDestroy() { Log.i(TAG, "onDestroy"); stopVpn(); super.onDestroy() }
    override fun onRevoke()  { Log.w(TAG, "VPN revoked"); stopVpn(); super.onRevoke() }

    private fun startVpnInBackground() {
        if (running) { Log.w(TAG, "Already running"); return }
        running = true
        Thread(::doStart, "VPN-Start").start()
    }

    private fun doStart() {
        try {
            Log.i(TAG, "========== VPN Start ==========")

            // 1. 加载原生库（tun2socks 模块里的 System.loadLibrary("tun2socks")）
            Tun2Socks.initialize(this)
            Log.d(TAG, "✓ tun2socks library loaded")

            // 2. 启动本地 SOCKS5 服务器
            val cfg = ConfigStore.loadActive(this)
            Log.i(TAG, "Config: ${cfg.name}  server=${cfg.server}:${cfg.port}")
            broadcast("CONNECTING")

            val server = LocalSocks5Server(cfg, this) { bytesIn, bytesOut ->
                broadcastStats(bytesIn, bytesOut)
                updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
            }
            socksServer = server
            val socksPort = server.start()
            Log.i(TAG, "✓ SOCKS5 on 127.0.0.1:$socksPort")

            // 3. 建立 TUN 接口
            val tunPfd = Builder()
                .setSession("VlessVPN")
                .setMtu(MTU)
                .addAddress(VPN_ADDR, VPN_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(cfg.dns1)
                .addDnsServer(cfg.dns2)
                .addDisallowedApplication(packageName)
                .establish()

            if (tunPfd == null) {
                Log.e(TAG, "✗ TUN establish failed"); broadcast("ERROR"); server.stop(); return
            }
            tun = tunPfd
            Log.i(TAG, "✓ TUN fd=${tunPfd.fd}")

            // 4. 在独立线程运行 tun2socks（阻塞调用）
            // ★ Tun2Socks.startTun2Socks 是 static 方法，直接类名调用
            val t = Thread({
                val ok = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.NOTICE,   // logLevel
                    tunPfd,                       // vpnInterfaceFileDescriptor
                    MTU,                          // vpnInterfaceMtu
                    "127.0.0.1",                  // socksServerAddress
                    socksPort,                    // socksServerPort
                    "10.233.233.2",               // netIPv4Address（tun2socks 虚拟对端）
                    null,                         // netIPv6Address
                    "255.255.255.252",            // netmask
                    false,                        // forwardUdp
                    Collections.emptyList()       // extraArgs
                )
                Log.i(TAG, "tun2socks exited: ok=$ok")
            }, "tun2socks-main")
            t.isDaemon = true
            t.start()
            tun2socksThread = t

            Log.i(TAG, "✓ VPN Connected (tun2socks)")
            broadcast("CONNECTED")
            updateNotif("${cfg.name} • Connected")

        } catch (e: Exception) {
            Log.e(TAG, "VPN start error", e)
            broadcast("ERROR"); cleanup()
        }
    }

    private fun stopVpn() {
        if (!running) return
        running = false
        Log.i(TAG, "Stopping VPN...")

        // ★ Tun2Socks.stopTun2Socks() 也是 static 方法
        try { Tun2Socks.stopTun2Socks() } catch (_: Exception) {}
        tun2socksThread?.join(3000)
        tun2socksThread = null

        cleanup()
        broadcast("DISCONNECTED")
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "✓ VPN stopped")
    }

    private fun cleanup() {
        runCatching { socksServer?.stop() }; socksServer = null
        VlessTunnel.clearSharedClients()
        runCatching { tun?.close() }; tun = null
    }

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