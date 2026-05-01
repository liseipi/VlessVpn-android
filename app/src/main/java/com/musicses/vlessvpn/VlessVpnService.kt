package com.musicses.vlessvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "VlessVpnService"
private const val CH_ID = "vless_vpn"
private const val NOTIF_ID = 1

private const val TUN_ADDR     = "10.0.0.2"
private const val NET_IF_ADDR  = "10.0.0.1"
private const val TUN_ADDR6    = "fd00::2"
private const val NET_IF_ADDR6 = "fd00::1"
private const val VPN_PREFIX   = 24
private const val VPN_PREFIX6  = 120
private const val NETMASK      = "255.255.255.0"
private const val MTU          = 1500

class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START     = "com.musicses.vlessvpn.START"
        const val ACTION_STOP      = "com.musicses.vlessvpn.STOP"
        const val ACTION_RECONNECT = "com.musicses.vlessvpn.RECONNECT"
        const val BROADCAST    = "com.musicses.vlessvpn.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_IN     = "bytes_in"
        const val EXTRA_OUT    = "bytes_out"
        const val EXTRA_ERROR  = "error"
    }

    private val lock = Any()

    // Protected by lock
    private var tun: ParcelFileDescriptor? = null
    private var socksServer: LocalSocks5Server? = null
    private var tun2socksThread: Thread? = null
    private var statsThread: Thread? = null

    // Atomic flags — safe to read without lock
    private val running = AtomicBoolean(false)
    private val userStopped = AtomicBoolean(false)

    private val totalIn  = AtomicLong(0)
    private val totalOut = AtomicLong(0)

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        Log.i(TAG, "onStartCommand: $action  running=${running.get()}")

        return when (action) {
            ACTION_STOP -> {
                userStopped.set(true)
                Log.i(TAG, "User requested STOP")
                Thread({
                    fullStop()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }, "VPN-Stop").start()
                START_NOT_STICKY
            }

            ACTION_RECONNECT -> {
                userStopped.set(false)
                Log.i(TAG, "RECONNECT: stopping and restarting service")
                // ★ 修复：重连时立即刷新前台通知，防止系统因前台服务超时而杀进程
                startForeground(NOTIF_ID, buildNotif("Reconnecting…"),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                Thread({
                    fullStop()
                    Thread.sleep(200)
                    fullStart()
                }, "VPN-Reconnect").start()
                START_STICKY
            }

            ACTION_START -> {
                userStopped.set(false)
                if (running.get()) {
                    Log.w(TAG, "Already running, ignoring START")
                    return START_STICKY
                }
                startForeground(NOTIF_ID, buildNotif("Connecting…"),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                Thread({ fullStart() }, "VPN-Start").start()
                START_STICKY
            }

            else -> START_STICKY
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        if (running.get()) fullStop()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by system")
        userStopped.set(true)
        Thread({ fullStop(); stopSelf() }, "VPN-Revoke").start()
        super.onRevoke()
    }

    // ── Core start / stop ─────────────────────────────────────────────────────

    private fun fullStart() {
        if (!running.compareAndSet(false, true)) {
            Log.w(TAG, "fullStart: already running, skipping")
            return
        }
        Log.i(TAG, "===== fullStart =====")

        try {
            val cfg = ConfigStore.loadActive(this)
            Log.i(TAG, "Config: ${cfg.name}  ${cfg.server}:${cfg.port}")

            broadcast("CONNECTING")
            startForeground(NOTIF_ID, buildNotif("Connecting…"),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)

            totalIn.set(0); totalOut.set(0)

            VlessTunnel.clearSharedClients()
            val client = VlessTunnel.getOrCreateClient(cfg, this)
            Log.i(TAG, "✓ OkHttpClient ready")

            Tun2Socks.initialize(this)

            val server = LocalSocks5Server(cfg, this) { bytesIn, bytesOut ->
                totalIn.addAndGet(bytesIn)
                totalOut.addAndGet(bytesOut)
            }
            val socksPort = server.start()
            Log.i(TAG, "✓ SOCKS5 on :$socksPort")

            val tunPfd = Builder()
                .setSession("VlessVPN")
                .setMtu(MTU)
                .addAddress(TUN_ADDR, VPN_PREFIX)
                .addAddress(TUN_ADDR6, VPN_PREFIX6)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(cfg.dns1)
                .addDnsServer(cfg.dns2)
                .addDisallowedApplication(packageName)
                .establish()
                ?: throw IllegalStateException("TUN establish() returned null — VPN permission denied?")

            Log.i(TAG, "✓ TUN fd=${tunPfd.fd}")

            synchronized(lock) {
                socksServer    = server
                tun            = tunPfd
            }

            broadcast("CONNECTED")
            updateNotif("${cfg.name} • Connected")

            val st = Thread({
                var lastIn = 0L; var lastOut = 0L
                while (running.get()) {
                    try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
                    if (!running.get()) break
                    val ci = totalIn.get(); val co = totalOut.get()
                    val ri = ci - lastIn;   val ro = co - lastOut
                    lastIn = ci; lastOut = co
                    broadcastStats(ri, ro)
                    updateNotif("↓ ${fmt(ri)}/s  ↑ ${fmt(ro)}/s")
                }
            }, "stats-timer").also { it.isDaemon = true; it.start() }

            synchronized(lock) { statsThread = st }

            val t2s = Thread({
                Log.i(TAG, "tun2socks starting fd=${tunPfd.fd} socks=:$socksPort")
                val ok = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.NOTICE,
                    tunPfd, MTU,
                    "127.0.0.1", socksPort,
                    NET_IF_ADDR, NET_IF_ADDR6, NETMASK,
                    true, Collections.emptyList()
                )
                Log.i(TAG, "tun2socks exited ok=$ok")
                if (!ok && running.get() && !userStopped.get()) {
                    broadcast("ERROR", "tun2socks exited abnormally")
                }
            }, "tun2socks-main").also { it.isDaemon = true; it.start() }

            synchronized(lock) { tun2socksThread = t2s }

        } catch (e: Exception) {
            Log.e(TAG, "fullStart failed: ${e.message}", e)
            running.set(false)
            broadcast("ERROR", e.message)
            cleanup()
        }
    }

    private fun fullStop() {
        if (!running.compareAndSet(true, false)) {
            Log.w(TAG, "fullStop: not running")
            return
        }
        Log.i(TAG, "===== fullStop =====")

        synchronized(lock) { statsThread?.interrupt(); statsThread = null }

        try { Tun2Socks.stopTun2Socks() } catch (_: Exception) {}
        val t2s = synchronized(lock) { tun2socksThread.also { tun2socksThread = null } }
        t2s?.join(3000)

        cleanup()
        broadcast("DISCONNECTED")
        Log.i(TAG, "===== fullStop done =====")
    }

    private fun cleanup() {
        val (server, tunPfd) = synchronized(lock) {
            val s = socksServer; val t = tun
            socksServer = null; tun = null
            s to t
        }
        runCatching { server?.stop() }
        VlessTunnel.clearSharedClients()
        runCatching { tunPfd?.close() }
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────────

    private fun broadcast(status: String, error: String? = null) =
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, status)
            if (error != null) putExtra(EXTRA_ERROR, error)
            setPackage(packageName)
        })

    private fun broadcastStats(rateIn: Long, rateOut: Long) =
        sendBroadcast(Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, "CONNECTED")
            putExtra(EXTRA_IN,  rateIn)
            putExtra(EXTRA_OUT, rateOut)
            setPackage(packageName)
        })

    // ── Notification helpers ──────────────────────────────────────────────────

    private fun buildNotif(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH_ID) == null)
            nm.createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW))

        val openPi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, VlessVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CH_ID)
            .setContentTitle("VLESS VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openPi)
            .addAction(0, getString(R.string.disconnect), stopPi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotif(text: String) =
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIF_ID, buildNotif(text))

    private fun fmt(b: Long) = when {
        b < 1024L        -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else             -> "${"%.1f".format(b / 1048576.0)}M"
    }
}