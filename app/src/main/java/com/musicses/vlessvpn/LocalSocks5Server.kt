package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

/**
 * ★ 修复版：改进早期数据收集逻辑
 *
 * 关键修改：
 * 1. 移除 Thread.sleep(50) - 不再等待固定时间
 * 2. 立即开始中继 - 让 VlessTunnel 自己处理首包
 * 3. 与 Node.js 行为完全一致
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = Executors.newCachedThreadPool()
    private lateinit var srv: ServerSocket
    private val connectionCount = AtomicInteger(0)

    @Volatile var port: Int = 0
        private set

    @Volatile private var running = false

    fun start(): Int {
        try {
            srv = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
            port = srv.localPort
            running = true
            pool.submit { acceptLoop() }
            Log.i(TAG, "========== SOCKS5 Server Started (Node.js Mode) ==========")
            Log.i(TAG, "Listening on: 127.0.0.1:$port")
            Log.i(TAG, "Target: ${cfg.server}:${cfg.port}")
            Log.i(TAG, "Mode: Just like Node.js client.js")
            Log.i(TAG, "===========================================================")
            return port
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SOCKS5 server", e)
            throw e
        }
    }

    fun stop() {
        if (!running) return
        running = false
        Log.i(TAG, "Stopping SOCKS5 server...")
        runCatching { srv.close() }
        pool.shutdownNow()
        Log.i(TAG, "✓ SOCKS5 server stopped (handled ${connectionCount.get()} connections)")
    }

    private fun acceptLoop() {
        Log.d(TAG, "Accept loop started")
        while (running) {
            try {
                val client = srv.accept()
                val connId = connectionCount.incrementAndGet()
                Log.d(TAG, "[$connId] New connection from ${client.inetAddress.hostAddress}")
                pool.submit { handleClient(client, connId) }
            } catch (e: Exception) {
                if (running) {
                    Log.e(TAG, "Accept error: ${e.message}")
                }
                break
            }
        }
        Log.d(TAG, "Accept loop ended")
    }

    /**
     * ★ 修复版：与 Node.js client.js 完全一致的处理流程
     */
    private fun handleClient(sock: Socket, connId: Int) {
        sock.tcpNoDelay = true
        sock.soTimeout = 30000  // 30s timeout
        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. SOCKS5 握手（与 Node.js 一致）──────────────────────────
            Log.d(TAG, "[$connId] Step 1: SOCKS5 greeting")
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2) {
                Log.w(TAG, "[$connId] Invalid greeting (too short)")
                sock.close()
                return
            }

            if (greeting[0] != 0x05.toByte()) {
                Log.w(TAG, "[$connId] Not SOCKS5 (version=${greeting[0]})")
                sock.close()
                return
            }

            val nMethods = greeting[1].toInt() and 0xFF
            Log.d(TAG, "[$connId] Client supports $nMethods auth methods")
            inp.readNBytes(nMethods)  // 跳过方法列表

            // Node.js: sock.write(Buffer.from([0x05, 0x00]))
            out.write(byteArrayOf(0x05, 0x00))  // 选择：无认证
            out.flush()
            Log.d(TAG, "[$connId] ✓ Greeting OK (no auth)")

            // ── 2. 连接请求（与 Node.js 一致）──────────────────────────────
            Log.d(TAG, "[$connId] Step 2: Reading connect request")
            val req = inp.readNBytes(4)
            if (req.size < 4) {
                Log.w(TAG, "[$connId] Invalid request (too short)")
                sock.close()
                return
            }

            if (req[0] != 0x05.toByte()) {
                Log.w(TAG, "[$connId] Invalid SOCKS version")
                sock.close()
                return
            }

            if (req[1] != 0x01.toByte()) {
                Log.w(TAG, "[$connId] Only CONNECT supported (got ${req[1]})")
                sock.close()
                return
            }

            // 解析目标地址（与 Node.js 一致）
            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> { // IPv4
                    val ip = inp.readNBytes(4)
                    val pt = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                0x03.toByte() -> { // 域名
                    val len = inp.read()
                    val domain = String(inp.readNBytes(len))
                    val pt = inp.readNBytes(2)
                    domain to portOf(pt)
                }
                0x04.toByte() -> { // IPv6
                    val ip = inp.readNBytes(16)
                    val pt = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                else -> {
                    Log.w(TAG, "[$connId] Unknown address type: ${req[3]}")
                    sock.close()
                    return
                }
            }

            Log.i(TAG, "[$connId] CONNECT request: $destHost:$destPort")

            // ★ 关键：立即回复 SOCKS5 成功（Node.js 原文注释："先回复 SOCKS5 成功，让本地立刻开始发数据"）
            // Node.js: sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]))
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
            Log.d(TAG, "[$connId] ✓ Sent success reply (client can start sending now)")

            // ── 3. 收集早期数据（修复版）────────────────────────────────────
            // ★ 修复：不再等待固定时间，而是检查是否有立即可用的数据
            // 这样可以避免不必要的延迟，同时还能捕获早期数据
            val earlyData: ByteArray? = if (inp.available() > 0) {
                val data = inp.readNBytes(inp.available())
                Log.d(TAG, "[$connId] ✓ Collected ${data.size} bytes of early data")
                data
            } else {
                Log.d(TAG, "[$connId] No early data immediately available")
                null
            }

            // ── 4. 建立 VLESS 隧道（与 Node.js openTunnel 一致）────────────
            Log.d(TAG, "[$connId] Step 3: Establishing VLESS tunnel via WebSocket...")
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = CountDownLatch(1)

            // Node.js: openTunnel((err, ws) => { ... })
            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
                Log.d(TAG, "[$connId] Tunnel connect callback: ok=$ok")
            }

            // 等待连接完成（Node.js 也是异步等待）
            if (!latch.await(15, TimeUnit.SECONDS)) {
                Log.e(TAG, "[$connId] ✗ Tunnel connection timeout (15s)")
                sock.close()
                return
            }

            if (!connected) {
                Log.e(TAG, "[$connId] ✗ Tunnel connection failed")
                sock.close()
                return
            }

            Log.i(TAG, "[$connId] ✓ VLESS tunnel established successfully")

            // ── 5. 双向中继（与 Node.js relay 一致）────────────────────────
            Log.d(TAG, "[$connId] Step 4: Starting relay...")

            // ★ 重要：Node.js 在 VlessTunnel.connect 回调中已经发送了 VLESS header + earlyData
            // 所以这里只需要 relay 后续数据
            tunnel.relay(inp, out)

            Log.d(TAG, "[$connId] Relay ended")

        } catch (e: Exception) {
            Log.d(TAG, "[$connId] Connection error: ${e.message}")
        } finally {
            runCatching { sock.close() }
            Log.d(TAG, "[$connId] Connection closed")
        }
    }

    private fun portOf(b: ByteArray) =
        ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
}