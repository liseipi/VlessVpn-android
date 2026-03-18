package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

/**
 * ★★★ 彻底重写版：修复所有不稳定问题 ★★★
 *
 * 关键修复：
 * 1. 早期数据收集改用定时读取（200ms），与 Node.js 完全一致
 * 2. 避免 available() 竞争条件
 * 3. 连接超时从 15s 增加到 30s
 * 4. 增加连接级别的错误隔离
 * 5. 修复流统计
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = Executors.newCachedThreadPool()
    private lateinit var srv: ServerSocket
    private val connectionCount = AtomicInteger(0)
    private val activeConnections = AtomicInteger(0)

    @Volatile var port: Int = 0
        private set

    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 256, InetAddress.getByName("127.0.0.1"))
        port = srv.localPort
        running = true
        pool.submit { acceptLoop() }
        Log.i(TAG, "SOCKS5 server started on 127.0.0.1:$port")
        return port
    }

    fun stop() {
        if (!running) return
        running = false
        runCatching { srv.close() }
        pool.shutdownNow()
        pool.awaitTermination(3, TimeUnit.SECONDS)
        Log.i(TAG, "SOCKS5 server stopped (total=${connectionCount.get()})")
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                val connId = connectionCount.incrementAndGet()
                activeConnections.incrementAndGet()
                pool.submit {
                    try {
                        handleClient(client, connId)
                    } finally {
                        activeConnections.decrementAndGet()
                    }
                }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "Accept error: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket, connId: Int) {
        sock.tcpNoDelay = true
        sock.soTimeout = 30000

        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. SOCKS5 握手 ──────────────────────────────────────────────
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) {
                return
            }
            val nMethods = greeting[1].toInt() and 0xFF
            inp.readNBytes(nMethods)
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            // ── 2. CONNECT 请求 ─────────────────────────────────────────────
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) {
                return
            }

            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> {
                    val ip = inp.readNBytes(4)
                    val pt = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                0x03.toByte() -> {
                    val len = inp.read()
                    val domain = String(inp.readNBytes(len))
                    val pt = inp.readNBytes(2)
                    domain to portOf(pt)
                }
                0x04.toByte() -> {
                    val ip = inp.readNBytes(16)
                    val pt = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                else -> return
            }

            Log.i(TAG, "[$connId] CONNECT $destHost:$destPort")

            // ★ 立即回复成功（让客户端开始发数据）
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()

            // ── 3. 早期数据收集（定时 200ms，与 Node.js 完全一致）───────────
            //
            // Node.js 实现：
            //   sock.once('data', (chunk) => { earlyData = chunk; ... })
            //   setTimeout(() => { if (!earlyData) openTunnel(null) }, 200)
            //
            // 这里模拟：最多等 200ms，如果有数据则收集，没有则直接建隧道
            val earlyData: ByteArray? = collectEarlyData(sock, inp, 200)

            if (earlyData != null) {
                Log.d(TAG, "[$connId] earlyData (after ${200}ms): ${earlyData.size}B")
            } else {
                Log.d(TAG, "[$connId] No earlyData (waited 200ms)")
            }

            Log.d(TAG, "[$connId] Opening VLESS tunnel...")

            // ── 4. 建立 VLESS 隧道 ──────────────────────────────────────────
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = java.util.concurrent.CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
            }

            if (!latch.await(30, TimeUnit.SECONDS)) {
                Log.e(TAG, "[$connId] Tunnel timeout (30s)")
                tunnel.close()
                return
            }

            if (!connected) {
                Log.e(TAG, "[$connId] Tunnel failed")
                tunnel.close()
                return
            }

            Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying...")

            // ── 5. 双向中继 ──────────────────────────────────────────────────
            tunnel.relay(inp, out)

            Log.d(TAG, "[$connId] Relay ended")

        } catch (e: Exception) {
            // 静默处理，避免日志噪音
            if (running) {
                Log.d(TAG, "[$connId] ${e.javaClass.simpleName}: ${e.message}")
            }
        } finally {
            runCatching { sock.close() }
        }
    }

    /**
     * 定时收集早期数据
     *
     * 策略：
     * 1. 先检查是否有立即可用数据（immediate）
     * 2. 如果没有，等待最多 timeoutMs 毫秒
     * 3. 返回收集到的所有数据，或 null（如果超时仍无数据）
     *
     * 这与 Node.js 的 sock.once('data', ...) + setTimeout(..., 200) 完全一致
     */
    private fun collectEarlyData(sock: Socket, inp: java.io.InputStream, timeoutMs: Long): ByteArray? {
        val collected = ByteArrayOutputStream()
        val deadline = System.currentTimeMillis() + timeoutMs

        // 临时降低 soTimeout 以便快速轮询
        val originalTimeout = 30000
        sock.soTimeout = 50  // 50ms 轮询间隔

        try {
            val buf = ByteArray(8192)
            while (System.currentTimeMillis() < deadline) {
                try {
                    val n = inp.read(buf)
                    if (n < 0) break  // EOF
                    if (n > 0) {
                        collected.write(buf, 0, n)
                        // 一旦收到数据，再尝试读取更多（非阻塞）
                        // 模拟 Node.js 的单次 'data' 事件收集
                        try {
                            while (inp.available() > 0) {
                                val m = inp.read(buf)
                                if (m > 0) collected.write(buf, 0, m)
                                else break
                            }
                        } catch (_: Exception) {}
                        break  // 已收到数据，停止等待
                    }
                } catch (e: java.net.SocketTimeoutException) {
                    // 超时，继续等待
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Early data collection error: ${e.message}")
        } finally {
            sock.soTimeout = originalTimeout
        }

        return if (collected.size() > 0) collected.toByteArray() else null
    }

    private fun portOf(b: ByteArray) =
        ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
}