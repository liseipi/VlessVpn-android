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
    private var packetTunnel: PacketTunnel? = null  // ← 改用 PacketTunnel
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")
        return when (intent?.action) {
            ACTION_STOP -> {
                Log.i(TAG, "Received STOP action")
                stopVpn()
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_START -> {
                Log.i(TAG, "Received START action")
                startForeground(NOTIF_ID, buildNotif("Connecting…"))
                startVpnInBackground()
                START_STICKY
            }
            else -> {
                Log.w(TAG, "Unknown action: ${intent?.action}")
                START_STICKY
            }
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy called")
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by user")
        stopVpn()
        super.onRevoke()
    }

    private fun startVpnInBackground() {
        if (running) {
            Log.w(TAG, "VPN already running, ignoring start request")
            return
        }
        running = true

        Thread {
            try {
                Log.i(TAG, "========== VPN Start Sequence ==========")

                // 步骤 1: 加载配置
                Log.d(TAG, "Step 1: Loading configuration...")
                val cfg = ConfigStore.loadActive(this)
                Log.i(TAG, "Config loaded: ${cfg.name}")
                Log.d(TAG, "  Server: ${cfg.server}:${cfg.port}")
                Log.d(TAG, "  UUID: ${cfg.uuid}")
                Log.d(TAG, "  Path: ${cfg.path}")
                Log.d(TAG, "  Security: ${cfg.security}")
                Log.d(TAG, "  SNI: ${cfg.sni}")
                broadcast("CONNECTING")

                // 步骤 2: 建立 TUN 接口
                Log.d(TAG, "Step 2: Establishing TUN interface...")
                val tunBuilder = Builder()
                    .setSession("VlessVPN")
                    .setMtu(MTU)
                    .addAddress(VPN_ADDR, VPN_PREFIX)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(cfg.dns1)
                    .addDnsServer(cfg.dns2)
                    .addDisallowedApplication(packageName)

                Log.d(TAG, "  TUN config: $VPN_ADDR/$VPN_PREFIX, MTU=$MTU")
                Log.d(TAG, "  DNS: ${cfg.dns1}, ${cfg.dns2}")
                Log.d(TAG, "  Excluded app: $packageName")

                val tunPfd = tunBuilder.establish()
                if (tunPfd == null) {
                    Log.e(TAG, "✗ Failed to establish VPN interface (returned null)")
                    Log.e(TAG, "  This usually means:")
                    Log.e(TAG, "  1. VPN permission not granted")
                    Log.e(TAG, "  2. Another VPN is already active")
                    Log.e(TAG, "  3. System VPN service is unavailable")
                    broadcast("ERROR")
                    return@Thread
                }
                tun = tunPfd
                Log.i(TAG, "✓ TUN interface established, fd=${tunPfd.fd}")

                // 步骤 3: 启动 PacketTunnel（处理 TUN 数据包）
                Log.d(TAG, "Step 3: Starting PacketTunnel...")
                val pt = PacketTunnel(
                    tunPfd.fileDescriptor,
                    cfg,
                    this  // ← 传递 VpnService 实例用于 protect
                ) { bytesIn, bytesOut ->
                    // 流量统计回调
                    val intent = Intent(BROADCAST).apply {
                        putExtra(EXTRA_STATUS, "CONNECTED")
                        putExtra(EXTRA_IN, bytesIn)
                        putExtra(EXTRA_OUT, bytesOut)
                        setPackage(packageName)  // ← 指定接收包名
                    }
                    sendBroadcast(intent)
                    updateNotif("↓ ${fmt(bytesIn)}  ↑ ${fmt(bytesOut)}")
                }
                packetTunnel = pt
                pt.start()
                Log.i(TAG, "✓ PacketTunnel started")

                // 完成
                Log.i(TAG, "========== VPN Connected ==========")
                Log.i(TAG, "Profile: ${cfg.name}")
                Log.i(TAG, "Server: ${cfg.server}:${cfg.port}")
                Log.i(TAG, "=======================================")
                broadcast("CONNECTED")
                updateNotif("${cfg.name} • Connected")

            } catch (e: SecurityException) {
                Log.e(TAG, "✗ Security exception (VPN permission?)", e)
                broadcast("ERROR")
                stopVpn()
                stopSelf()
            } catch (e: IllegalArgumentException) {
                Log.e(TAG, "✗ Invalid VPN configuration", e)
                broadcast("ERROR")
                stopVpn()
                stopSelf()
            } catch (e: IllegalStateException) {
                Log.e(TAG, "✗ VPN service in invalid state", e)
                broadcast("ERROR")
                stopVpn()
                stopSelf()
            } catch (e: Exception) {
                Log.e(TAG, "✗ Unexpected error during VPN start", e)
                broadcast("ERROR")
                stopVpn()
                stopSelf()
            }
        }.apply {
            name = "VPN-Start-Thread"
            isDaemon = false
        }.start()
    }

    private fun stopVpn() {
        if (!running) {
            Log.d(TAG, "VPN not running, nothing to stop")
            return
        }

        Log.i(TAG, "========== Stopping VPN ==========")
        running = false

        try {
            packetTunnel?.let {
                Log.d(TAG, "Stopping PacketTunnel...")
                it.stop()
                Log.d(TAG, "✓ PacketTunnel stopped")
            }
            packetTunnel = null

            tun?.let {
                Log.d(TAG, "Closing TUN interface...")
                it.close()
                Log.d(TAG, "✓ TUN interface closed")
            }
            tun = null

            broadcast("DISCONNECTED")
            stopForeground(STOP_FOREGROUND_REMOVE)
            Log.i(TAG, "✓ VPN stopped successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Error during VPN shutdown", e)
        }
    }

    private fun buildNotif(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CH_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CH_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            )
        }

        val openPi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
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

    private fun broadcast(status: String) {
        Log.d(TAG, "Broadcasting status: $status")
        val intent = Intent(BROADCAST).apply {
            putExtra(EXTRA_STATUS, status)
            setPackage(packageName)  // ← 添加包名，确保只发送给本应用
        }
        sendBroadcast(intent)
    }

    private fun fmt(b: Long) = when {
        b < 1024L -> "${b}B"
        b < 1024 * 1024L -> "${"%.1f".format(b / 1024.0)}K"
        else -> "${"%.1f".format(b / 1048576.0)}M"
    }
}