package com.vlessvpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
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
import java.net.Inet4Address
import java.net.InetAddress
import kotlin.concurrent.thread

class VlessVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.vlessvpn.START"
        const val ACTION_STOP  = "com.vlessvpn.STOP"
        const val EXTRA_CONFIG_ID = "config_id"

        private const val TAG = "VlessVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "vpn_service"

        private const val VPN_ADDRESS  = "10.0.0.1"
        private const val VPN_ROUTE    = "10.0.0.2"
        private const val VPN_NETMASK  = "255.255.255.252"
        private const val VPN_MTU      = 1500

        @Volatile var isRunning = false
        @Volatile var isStarting = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var localProxy: LocalProxyServer? = null
    private var tun2socksThread: Thread? = null
    private var currentConfig: VlessConfig? = null
    private var underlyingNetwork: android.net.Network? = null

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

    override fun onRevoke() { stopVpn() }
    override fun onDestroy() { stopVpn(); super.onDestroy() }

    // ── 启动 VPN ──────────────────────────────────────────────────────────────

    private fun startVpn(config: VlessConfig) {
        if (isRunning || isStarting) {
            Log.w(TAG, "VPN already running or starting")
            return
        }

        isStarting = true
        VpnStateManager.setState(VpnStateManager.State.CONNECTING)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification("正在连接...", config.displayName()),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification("正在连接...", config.displayName()))
        }

        currentConfig = config

        thread(name = "vpn-start") {
            val socksPort = ConfigManager.getSocksPort()

            // 捕获物理网络引用
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            underlyingNetwork = try {
                cm.activeNetwork.also { Log.i(TAG, "Underlying network captured: $it") }
            } catch (e: Exception) {
                Log.w(TAG, "Cannot get activeNetwork: ${e.message}")
                null
            }

            // ✅ 关键修复：在 VPN 建立之前，通过物理网络强制解析服务器的 IPv4 地址
            // VPN 建立后 DNS 会走隧道，而隧道依赖 DNS，形成死锁
            // 必须在 VPN 启动前把 IP 解析好并缓存，之后直接用 IP 连接
            val preResolvedIp: String? = resolveIpv4BeforeVpn(config.serverHost, underlyingNetwork)
            if (preResolvedIp == null) {
                Log.e(TAG, "Cannot resolve server IP before VPN start, aborting")
                isStarting = false
                VpnStateManager.setState(VpnStateManager.State.ERROR, "无法解析服务器地址: ${config.serverHost}")
                stopSelf()
                return@thread
            }
            Log.i(TAG, "Pre-resolved ${config.serverHost} -> $preResolvedIp (IPv4, before VPN)")

            // 1. 启动本地 SOCKS5 代理，传入已解析的 IPv4 地址
            try {
                localProxy = LocalProxyServer(
                    config = config,
                    listenPort = socksPort,
                    network = underlyingNetwork,
                    protectSocket = { socket -> protect(socket) },
                    preResolvedServerIp = preResolvedIp  // ✅ 直接传入 IP，跳过 DNS
                ).also { it.start() }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start local proxy: ${e.message}")
                isStarting = false
                VpnStateManager.setState(VpnStateManager.State.ERROR, "代理启动失败: ${e.message}")
                stopSelf()
                return@thread
            }

            try { Thread.sleep(300) } catch (_: InterruptedException) {}

            // 2. 建立 VPN 接口（只走 IPv4，不启用 IPv6）
            val builder = Builder()
                .setSession("VlessVPN")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 30)
                .addRoute("0.0.0.0", 0)
                // ✅ DNS 用国内不支持 DoT 的服务器，避免系统升级为853端口
                .addDnsServer("114.114.114.114")
                .addDnsServer("223.5.5.5")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                localProxy?.stop()
                localProxy = null
                isStarting = false
                VpnStateManager.setState(VpnStateManager.State.ERROR, "VPN 接口创建失败")
                stopSelf()
                return@thread
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && underlyingNetwork != null) {
                setUnderlyingNetworks(arrayOf(underlyingNetwork))
                Log.i(TAG, "setUnderlyingNetworks: $underlyingNetwork")
            }

            isRunning = true
            isStarting = false

            // 3. 启动 tun2socks（只 IPv4，关闭 UDP 转发）
            tun2socksThread = thread(name = "tun2socks") {
                Log.i(TAG, "Starting tun2socks, SOCKS5 at 127.0.0.1:$socksPort")
                val result = Tun2Socks.startTun2Socks(
                    Tun2Socks.LogLevel.INFO,
                    vpnInterface!!,
                    VPN_MTU,
                    "127.0.0.1",
                    socksPort,
                    VPN_ROUTE,
                    null,   // 不启用 IPv6 隧道
                    VPN_NETMASK,
                    false   // 不启用 UDP 转发（无 udpgw）
                )
                Log.i(TAG, "tun2socks stopped, result=$result")
                isRunning = false
            }

            VpnStateManager.setState(VpnStateManager.State.CONNECTED)
            updateNotification("已连接", config.displayName())
            Log.i(TAG, "VPN started: ${config.displayName()} -> ${config.buildWsUrl()}")
        }
    }

    /**
     * 在 VPN 建立之前，通过物理网络解析服务器域名，强制只返回 IPv4 地址。
     * VPN 建立后 DNS 走隧道，隧道又依赖 DNS，会形成死锁，所以必须提前解析。
     * 只取 IPv4（Inet4Address），避免返回 IPv6 地址导致 IPv4 socket 连接失败。
     */
    private fun resolveIpv4BeforeVpn(host: String, network: android.net.Network?): String? {
        // 如果已经是 IP 地址，直接返回（同时过滤 IPv6）
        try {
            val addr = InetAddress.getByName(host)
            if (addr is Inet4Address) {
                return addr.hostAddress
            }
            // 是 IPv6 字面量，不能直接用，继续走 DNS 查 IPv4
        } catch (_: Exception) {}

        return try {
            val addresses: Array<InetAddress> = if (network != null) {
                network.getAllByName(host)
            } else {
                InetAddress.getAllByName(host)
            }
            // 优先取 IPv4 地址
            val ipv4 = addresses.filterIsInstance<Inet4Address>().firstOrNull()
            if (ipv4 != null) {
                Log.i(TAG, "resolveIpv4: $host -> ${ipv4.hostAddress}")
                ipv4.hostAddress
            } else {
                // 没有 IPv4，取第一个 IPv6（后续连接会失败，但至少能尝试）
                val fallback = addresses.firstOrNull()
                Log.w(TAG, "resolveIpv4: no IPv4 for $host, fallback to ${fallback?.hostAddress}")
                fallback?.hostAddress
            }
        } catch (e: Exception) {
            Log.e(TAG, "resolveIpv4: failed to resolve $host: ${e.message}")
            null
        }
    }

    // ── 停止 VPN ──────────────────────────────────────────────────────────────

    private fun stopVpn() {
        if (!isRunning && !isStarting && vpnInterface == null) return

        VpnStateManager.setState(VpnStateManager.State.DISCONNECTING)
        Log.i(TAG, "Stopping VPN...")

        Tun2Socks.stopTun2Socks()
        try { tun2socksThread?.join(3000) } catch (_: Exception) {}
        tun2socksThread = null

        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        localProxy?.stop()
        localProxy = null

        underlyingNetwork = null
        isRunning = false
        isStarting = false
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
                CHANNEL_ID, "VPN 服务", NotificationManager.IMPORTANCE_LOW
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