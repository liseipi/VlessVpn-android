package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okhttp3.ConnectionPool
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*

private const val TAG = "VlessTunnel"

/**
 * ★★★ 彻底修复版 ★★★
 *
 * 修复 1011 根因：ws 字段竞争覆盖
 *
 * 问题：
 *   - newWebSocket() 是异步的，onOpen 回调在 OkHttp 的线程池中执行
 *   - 如果两个 VlessTunnel 实例的 onOpen 交错执行（完全可能），
 *     后一个会把 ws 字段覆盖成自己的 WebSocket
 *   - 前一个实例发数据时用的是后一个的 socket → 服务器收到错误数据 → 1011
 *
 * 修复：
 *   - ws 用 AtomicReference 保存，并通过 compareAndSet 确保只设置一次
 *   - onOpen 回调通过局部变量 wsRef 引用自己的 WebSocket，不依赖实例字段
 *   - 所有发送操作通过局部 wsRef 而非 this.ws
 */
class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    // ★ 使用 AtomicReference，并通过 compareAndSet 保证只设置一次
    private val wsRef = AtomicReference<WebSocket?>(null)
    private val inQueue = LinkedBlockingQueue<ByteArray>(2000)
    private val closed = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)

    private var destHost = ""
    private var destPort = 0

    companion object {
        private val END_MARKER = ByteArray(0)
        fun clearSharedClients() { /* no-op */ }
    }

    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        if (closed.get()) { onResult(false); return }

        this.destHost = destHost
        this.destPort = destPort

        val client = buildClient()
        val req = Request.Builder()
            .url(cfg.wsUrl)
            .header("Host", cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .build()

        Log.i(TAG, "Connecting: ${cfg.wsUrl}  target=$destHost:$destPort")

        val resultSent = AtomicBoolean(false)
        fun deliver(ok: Boolean) {
            if (resultSent.compareAndSet(false, true)) onResult(ok)
        }

        client.newWebSocket(req, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) {
                    webSocket.close(1000, null)
                    deliver(false)
                    return
                }

                // ★ 关键修复：用 compareAndSet 确保只设置一次
                // 如果已经有值（说明这是重复的 onOpen），拒绝并关闭
                if (!wsRef.compareAndSet(null, webSocket)) {
                    Log.w(TAG, "Duplicate onOpen, closing extra WebSocket")
                    webSocket.close(1000, null)
                    deliver(false)
                    return
                }

                Log.i(TAG, "✓ WS opened")

                // ★ 用局部变量引用，避免后续被覆盖
                sendFirstPacket(webSocket, earlyData)
                deliver(true)
            }

            override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                if (!closed.get() && bytes.size > 0) {
                    inQueue.offer(bytes.toByteArray())
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty()) {
                    inQueue.offer(text.toByteArray())
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.w(TAG, "WS closing: $code ${reason.take(30)}")
                inQueue.offer(END_MARKER)
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code")
                inQueue.offer(END_MARKER)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!closed.get()) {
                    Log.e(TAG, "✗ WS failure: ${t.message}")
                }
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    // ★ 接受 webSocket 参数而不用实例字段，避免读到别的隧道的 ws
    private fun sendFirstPacket(webSocket: WebSocket, earlyData: ByteArray?) {
        if (headerSent.getAndSet(true)) return
        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
        val packet = if (earlyData != null && earlyData.isNotEmpty()) {
            Log.d(TAG, "→ header(${header.size}B) + earlyData(${earlyData.size}B)")
            header + earlyData
        } else {
            Log.d(TAG, "→ header only (${header.size}B)")
            header
        }
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return

        // ★ 在 relay 开始时拿一次本隧道的 ws，后续所有操作用这个局部引用
        val myWs = wsRef.get()
        if (myWs == null) {
            Log.e(TAG, "relay called but ws is null!")
            return
        }

        var firstResponse = true
        val wsToLocalDone = AtomicBoolean(false)
        val localToWsDone = AtomicBoolean(false)

        // ── 线程1: WS → Local ────────────────────────────────────────────────
        val t1 = Thread {
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(60, TimeUnit.SECONDS)

                    if (chunk == null) {
                        Log.w(TAG, "WS→local: 30s timeout")
                        break
                    }
                    if (chunk === END_MARKER) {
                        Log.d(TAG, "WS→local: END")
                        break
                    }

                    // 剥除 VLESS 响应头（仅第一个包）
                    val payload = if (firstResponse && chunk.size >= 2) {
                        firstResponse = false
                        val addonLen = chunk[1].toInt() and 0xFF
                        val hdrLen = 2 + addonLen
                        Log.d(TAG, "VLESS resp hdrSize=$hdrLen addonLen=$addonLen")
                        if (chunk.size > hdrLen) {
                            chunk.copyOfRange(hdrLen, chunk.size).also {
                                Log.d(TAG, "✓ VLESS resp header stripped, payload=${it.size}B")
                            }
                        } else null
                    } else {
                        firstResponse = false
                        chunk
                    }

                    if (payload != null && payload.isNotEmpty()) {
                        try {
                            localOut.write(payload)
                            localOut.flush()
                        } catch (e: Exception) {
                            if (!closed.get()) Log.e(TAG, "WS→local write: ${e.message}")
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                if (!closed.get()) Log.e(TAG, "WS→local: ${e.message}")
            } finally {
                wsToLocalDone.set(true)
                runCatching { localOut.close() }
                if (!localToWsDone.get()) runCatching { myWs.cancel() }
            }
        }.apply { isDaemon = true; name = "VT-ws2l-$destPort" }

        // ── 线程2: Local → WS ────────────────────────────────────────────────
        val t2 = Thread {
            try {
                val buf = ByteArray(16384)
                while (!closed.get() && !wsToLocalDone.get()) {
                    val n = try {
                        localIn.read(buf)
                    } catch (e: Exception) {
                        if (!closed.get() && !wsToLocalDone.get()) {
                            Log.e(TAG, "local→WS: ${e.message}")
                        }
                        break
                    }
                    if (n < 0) break

                    val data = buf.copyOf(n)
                    // ★ 直接用 myWs（本隧道的引用），不用 wsRef.get()
                    val ok = myWs.send(data.toByteString())
                    if (!ok) {
                        if (!closed.get()) Log.e(TAG, "local→WS: Socket closed")
                        break
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !wsToLocalDone.get()) Log.e(TAG, "local→WS: ${e.message}")
            } finally {
                localToWsDone.set(true)
                inQueue.offer(END_MARKER)
                runCatching { myWs.close(1000, null) }
            }
        }.apply { isDaemon = true; name = "VT-l2ws-$destPort" }

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        Log.d(TAG, "relay ended")
    }

    fun close() {
        if (closed.getAndSet(true)) return
        inQueue.offer(END_MARKER)
        runCatching { wsRef.get()?.cancel() }
    }

    private fun buildClient(): OkHttpClient {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val sslCtx = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustAll), SecureRandom())
        }

        val builder = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .pingInterval(25, TimeUnit.SECONDS)
            // ★ 禁用连接池：WebSocket 用完即废，缓存只会导致复用死连接
            .connectionPool(ConnectionPool(0, 1, TimeUnit.NANOSECONDS))
            .hostnameVerifier { _, _ -> true }

        val vpn = vpnService
        if (vpn != null) {
            builder.socketFactory(object : javax.net.SocketFactory() {
                private val def = javax.net.SocketFactory.getDefault()
                private fun p(s: Socket): Socket {
                    s.tcpNoDelay = true
                    if (!vpn.protect(s)) Log.w(TAG, "Failed to protect socket")
                    else Log.d(TAG, "✓ protected")
                    return s
                }
                override fun createSocket() = p(def.createSocket())
                override fun createSocket(h: String, port: Int) =
                    p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                override fun createSocket(h: String, port: Int, la: java.net.InetAddress, lp: Int) =
                    p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
                override fun createSocket(h: java.net.InetAddress, port: Int) =
                    p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                override fun createSocket(h: java.net.InetAddress, port: Int, la: java.net.InetAddress, lp: Int) =
                    p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
            })

            val baseSsl = sslCtx.socketFactory
            builder.sslSocketFactory(object : SSLSocketFactory() {
                override fun getDefaultCipherSuites() = baseSsl.defaultCipherSuites
                override fun getSupportedCipherSuites() = baseSsl.supportedCipherSuites
                override fun createSocket(s: Socket, h: String, p: Int, ac: Boolean) =
                    baseSsl.createSocket(s, h, p, ac)
                override fun createSocket(h: String, p: Int) =
                    baseSsl.createSocket(h, p).also { vpn.protect(it) }
                override fun createSocket(h: String, p: Int, la: java.net.InetAddress, lp: Int) =
                    baseSsl.createSocket(h, p, la, lp).also { vpn.protect(it) }
                override fun createSocket(h: java.net.InetAddress, p: Int) =
                    baseSsl.createSocket(h, p).also { vpn.protect(it) }
                override fun createSocket(h: java.net.InetAddress, p: Int, la: java.net.InetAddress, lp: Int) =
                    baseSsl.createSocket(h, p, la, lp).also { vpn.protect(it) }
            }, trustAll)
        } else {
            builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
        }

        return builder.build()
    }
}