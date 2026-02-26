package com.musicses.vlessvpn

import android.net.VpnService  // ← 添加这个 import
import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.util.concurrent.Executors

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * TUN 设备处理器 + SOCKS5 代理服务器
 *
 * 工作流程：
 * 1. 启动本地 SOCKS5 服务器监听 127.0.0.1
 * 2. Android VpnService 通过 protect() 保护 SOCKS5 连接不被路由回 TUN
 * 3. 系统流量自动路由到 TUN 接口，然后通过 SOCKS5 代理转发
 */
class TunHandler(
    private var fd: FileDescriptor?,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,  // ← VpnService 引用
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = false

    private var totalIn  = 0L
    private var totalOut = 0L

    private lateinit var socksServer: LocalSocks5Server

    fun start() {
        running = true

        // 启动 SOCKS5 服务器，传递 vpnService
        socksServer = LocalSocks5Server(cfg, vpnService) { bytesIn, bytesOut ->  // ← 传递 vpnService
            totalIn  += bytesIn
            totalOut += bytesOut
            onStats(totalIn, totalOut)
        }
        val socksPort = socksServer.start()
        Log.i(TAG, "SOCKS5 proxy started on 127.0.0.1:$socksPort")

        // 如果有 TUN fd，启动读取循环保持 TUN 存活
        fd?.let { tunFd ->
            executor.submit { tunReadLoop(tunFd) }
        }
    }

    fun stop() {
        running = false
        socksServer.stop()
        executor.shutdownNow()
    }

    fun getSocksPort(): Int = socksServer.port

    fun setTunFd(tunFd: FileDescriptor) {
        this.fd = tunFd
        executor.submit { tunReadLoop(tunFd) }
    }

    /**
     * TUN 读取循环 - 保持 TUN 接口存活
     * 实际流量处理由系统自动路由到 SOCKS5 端口
     */
    private fun tunReadLoop(tunFd: FileDescriptor) {
        val fis = FileInputStream(tunFd)
        val buf = ByteArray(MTU)
        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 0) break
                // 数据已被读出，系统已将流量路由到 SOCKS5
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}")
        }
    }
}