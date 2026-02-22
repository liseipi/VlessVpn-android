package com.musicses.vlessvpn

import android.util.Log
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private const val TAG = "SOCKS5"

/**
 * 本地 SOCKS5 代理服务器（仅支持 CONNECT / TCP）。
 *
 * 对应 client.js 的 handleSocks5()：
 *  1. Auth 握手（无认证）
 *  2. 解析目标 host:port
 *  3. 回复 SOCKS5 成功
 *  4. 开 VlessTunnel，将早期数据与 VLESS 头合并后一次发送
 *  5. 双向中继
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = Executors.newCachedThreadPool()
    private lateinit var srv: ServerSocket

    @Volatile var port: Int = 0
        private set

    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        port = srv.localPort
        running = true
        pool.submit { acceptLoop() }
        Log.i(TAG, "SOCKS5 started on 127.0.0.1:$port")
        return port
    }

    fun stop() {
        running = false
        runCatching { srv.close() }
        pool.shutdownNow()
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                pool.submit { handleClient(client) }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "accept: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket) {
        sock.tcpNoDelay = true
        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. 握手：客户端问候 ──────────────────────────────────────────
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) { sock.close(); return }
            val nMethods = greeting[1].toInt() and 0xFF
            inp.readNBytes(nMethods)               // 跳过方法列表
            out.write(byteArrayOf(0x05, 0x00))     // 选择：无认证

            // ── 2. 连接请求 ──────────────────────────────────────────────────
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) {
                sock.close(); return
            }

            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> { // IPv4
                    val ip   = inp.readNBytes(4)
                    val pt   = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                0x03.toByte() -> { // 域名
                    val len    = inp.read()
                    val domain = String(inp.readNBytes(len))
                    val pt     = inp.readNBytes(2)
                    domain to portOf(pt)
                }
                0x04.toByte() -> { // IPv6
                    val ip = inp.readNBytes(16)
                    val pt = inp.readNBytes(2)
                    InetAddress.getByAddress(ip).hostAddress!! to portOf(pt)
                }
                else -> { sock.close(); return }
            }

            // 回复 SOCKS5 成功（对应 client.js sock.write([0x05,0x00,0x00,0x01,0,0,0,0,0,0])）
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            // ── 3. 收集早期数据（WS 建立期间客户端已发来的数据） ───────────────
            // 对应 client.js 的 onEarlyData + pending 逻辑
            val earlyData: ByteArray? = if (inp.available() > 0) inp.readNBytes(inp.available()) else null

            // ── 4. 建立 VLESS 隧道 ───────────────────────────────────────────
            Log.d(TAG, "CONNECT $destHost:$destPort")
            val tunnel = VlessTunnel(cfg)
            var connected = false
            val latch = CountDownLatch(1)

            tunnel.connect(destHost, destPort, earlyData) { ok ->
                connected = ok
                latch.countDown()
            }

            if (!latch.await(10, TimeUnit.SECONDS) || !connected) {
                sock.close(); return
            }

            // ── 5. 双向中继 ──────────────────────────────────────────────────
            tunnel.relay(inp, out)

        } catch (e: Exception) {
            Log.d(TAG, "client error: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    private fun portOf(b: ByteArray) =
        ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
}
