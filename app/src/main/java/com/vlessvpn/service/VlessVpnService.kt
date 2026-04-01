package com.vlessvpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.musicses.vlessvpn.Tun2Socks
import com.vlessvpn.R
import com.vlessvpn.model.VlessConfig
import com.vlessvpn.ui.MainActivity
import com.vlessvpn.util.ConfigManager
import com.vlessvpn.util.VpnStateManager
import kotlin.concurrent.thread

class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.vlessvpn.START"
        const val ACTION_STOP  = "com.vlessvpn.STOP"
        const val EXTRA_CONFIG_ID = "config_id"

        private const val TAG = "VlessVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "vpn_service"

        private const val VPN_ADDRESS   = "10.0.0.1"
        private const val VPN_ROUTE     = "10.0.0.2"
        private const val VPN_ADDRESS6  = "fc00::1"
        private const val VPN_ROUTE6    = "fc00::2"
        private const val VPN_NETMASK   = "255.255.255.252"
        private const val VPN_MTU       = 1500

        @Volatile var isRunning = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var localProxy: LocalProxyServer? = null
    private var tun2socksThread: Thread? = null
    private var currentConfig: VlessConfig? = null

    override fun onCreate() {
        super.onCreate()
        Tun2Socks.initialize(applicationContext)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val configId = intent.getLongExtra(EXTRA_CONFIG_ID, -1L)
                val config = ConfigManager.getConfigs().find { it.id == configId }
                    ?: ConfigManager.getSelectedConfig()

                if (config == null) {
                    Log.e(TAG, "No config found")
                    VpnStateManager.setState(VpnStateManager.State.ERROR, "未找到配置")
                    stopSelf()
                    return START_NOT_STICKY
                }
                startVpn(config)
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // ── 启动 VPN ──────────────────────────────────────────────────────────────

    private fun startVpn(config: VlessConfig) {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }

        VpnStateManager.setState(VpnStateManager.State.CONNECTING)
        startForeground(NOTIFICATION_ID, buildNotification("正在连接...", config.displayName()))
        currentConfig = config

        // 在后台线程执行，避免阻塞 binder/main thread
        thread(name = "vpn-start") {
            val socksPort = ConfigManager.getSocksPort()

            // 1. 启动本地 SOCKS5 代理（VLESS 隧道）
            try {
                localProxy = LocalProxyServer(config, socksPort).also { it.start() }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start local proxy: ${e.message}")
                VpnStateManager.setState(VpnStateManager.State.ERROR, "代理启动失败: ${e.message}")
                stopSelf()
                return@thread
            }

            // 等待代理 ServerSocket 就绪
            try { Thread.sleep(300) } catch (_: InterruptedException) {}

            // 2. 建立 VPN 接口
            val builder = Builder()
                .setSession("VlessVPN")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 30)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .addAddress(VPN_ADDRESS6, 126)
                .addDnsServer("2606:4700:4700::1111")
                .addRoute("::", 0)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // 排除自身，避免代理循环
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                localProxy?.stop()
                VpnStateManager.setState(VpnStateManager.State.ERROR, "VPN 接口创建失败")
                stopSelf()
                return@thread
            }

            isRunning = true

            // 3. 启动 tun2socks（阻塞直到停止）
            tun2socksThread = thread(name = "tun2socks") {
                Log.i(TAG, "Starting tun2socks, SOCKS5 at 127.0.0.1:$socksPort")
                val result = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.INFO,
                    vpnInterface!!,
                    VPN_MTU,
                    "127.0.0.1",
                    socksPort,
                    VPN_ROUTE,
                    VPN_ROUTE6,
                    VPN_NETMASK,
                    false
                )
                Log.i(TAG, "tun2socks stopped, result=$result")
                isRunning = false
            }

            VpnStateManager.setState(VpnStateManager.State.CONNECTED)
            updateNotification("已连接", config.displayName())
            Log.i(TAG, "VPN started: ${config.displayName()} -> ${config.buildWsUrl()}")
        }
    }

    // ── 停止 VPN ──────────────────────────────────────────────────────────────

    private fun stopVpn() {
        if (!isRunning && vpnInterface == null) return

        VpnStateManager.setState(VpnStateManager.State.DISCONNECTING)
        Log.i(TAG, "Stopping VPN...")

        // 停止 tun2socks
        Tun2Socks.stopTun2Socks()
        try { tun2socksThread?.join(3000) } catch (_: Exception) {}
        tun2socksThread = null

        // 关闭 VPN 接口
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        // 停止本地代理
        localProxy?.stop()
        localProxy = null

        isRunning = false
        currentConfig = null

        VpnStateManager.setState(VpnStateManager.State.DISCONNECTED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    // ── 通知 ──────────────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN 服务",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VlessVPN 运行状态"
                setShowBadge(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String, server: String): Notification {
        val stopIntent = Intent(this, VlessVpnService::class.java).apply { action = ACTION_STOP }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val mainIntent = Intent(this, MainActivity::class.java)
        val mainPending = PendingIntent.getActivity(
            this, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VlessVPN - $status")
            .setContentText(server)
            .setSmallIcon(R.drawable.ic_vpn)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .addAction(R.drawable.ic_stop, "断开", stopPending)
            .setContentIntent(mainPending)
            .build()
    }

    private fun updateNotification(status: String, server: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(status, server))
    }
}
