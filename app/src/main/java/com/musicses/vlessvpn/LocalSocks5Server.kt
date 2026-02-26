package com.musicses.vlessvpn

import android.net.VpnService  // ← 添加这个 import
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
 * 本地 SOCKS5 代理服务器（仅支持 CONNECT / TCP）
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,  // ← VpnService 引用用于 protect
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
            Log.i(TAG, "========== SOCKS5 Server Started ==========")
            Log.i(TAG, "Listening on: 127.0.0.1:$port")
            Log.i(TAG, "Target: ${cfg.server}:${cfg.port}")
            Log.i(TAG, "===========================================")
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

    private fun handleClient(sock: Socket, connId: Int) {
        sock.tcpNoDelay = true
        sock.soTimeout = 30000  // 30s timeout
        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. SOCKS5 握手 ──────────────────────────────────────────────
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
            out.write(byteArrayOf(0x05, 0x00))  // 选择：无认证
            Log.d(TAG, "[$connId] ✓ Greeting OK (no auth)")

            // ── 2. 连接请求 ──────────────────────────────────────────────────
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

            // 回复 SOCKS5 成功
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            Log.d(TAG, "[$connId] ✓ Sent success reply")

            // ── 3. 收集早期数据 ──────────────────────────────────────────────
            val earlyData: ByteArray? = if (inp.available() > 0) {
                val data = inp.readNBytes(inp.available())
                Log.d(TAG, "[$connId] Collected ${data.size} bytes of early data")
                data
            } else {
                Log.d(TAG, "[$connId] No early data")
                null
            }

            // ── 4. 建立 VLESS 隧道（传递 vpnService 用于 protect）─────────────
            Log.d(TAG, "[$connId] Step 3: Establishing VLESS tunnel...")
            val tunnel = VlessTunnel(cfg, vpnService)  // ← 传递 vpnService
            var connected = false
            val latch = CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
                Log.d(TAG, "[$connId] Tunnel connect callback: ok=$ok")
            }

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

            Log.i(TAG, "[$connId] ✓ VLESS tunnel established")

            // ── 5. 双向中继 ──────────────────────────────────────────────────
            Log.d(TAG, "[$connId] Step 4: Starting relay...")
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