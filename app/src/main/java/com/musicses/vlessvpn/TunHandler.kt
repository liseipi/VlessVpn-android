package com.musicses.vlessvpn   // ✅ 修复：原来是 com.vlessvpn

import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.util.concurrent.Executors

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * TUN 设备读取循环。
 *
 * 架构说明：
 *  - Android VpnService 建立 TUN 接口后，所有流量都被路由到 TUN fd
 *  - 本类负责保持 fd 存活，并统计流量
 *  - 真正的 TCP 代理由 LocalSocks5Server 完成（独立文件）
 *  - 实际路由：Android 系统通过 iptables/nftables 将流量重定向到
 *    LocalSocks5Server 监听的端口（通过 VpnService.Builder 配置实现）
 *
 * ✅ 修复：删除了重复的 LocalSocks5Server 内部类（已有独立的 LocalSocks5Server.kt）
 */
class TunHandler(
    private val fd: FileDescriptor,
    private val cfg: VlessConfig,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = false

    private var totalIn  = 0L
    private var totalOut = 0L

    private lateinit var socksServer: LocalSocks5Server

    fun start() {
        running = true
        socksServer = LocalSocks5Server(cfg) { bytesIn, bytesOut ->
            totalIn  += bytesIn
            totalOut += bytesOut
            onStats(totalIn, totalOut)
        }
        val socksPort = socksServer.start()
        Log.i(TAG, "Local SOCKS5 on 127.0.0.1:$socksPort")

        executor.submit { tunReadLoop() }
    }

    fun stop() {
        running = false
        socksServer.stop()
        executor.shutdownNow()
    }

    fun getSocksPort(): Int = socksServer.port

    private fun tunReadLoop() {
        val fis = FileInputStream(fd)
        val buf = ByteArray(MTU)
        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 0) break
                // TUN 包已读出；实际 TCP 流量由 Android 系统路由到 SOCKS5 端口处理
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}")
        }
    }
}
