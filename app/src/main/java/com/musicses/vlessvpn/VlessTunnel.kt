package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "VlessTunnel"

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val wsRef = AtomicReference<WebSocket?>(null)
    internal val inQueue = LinkedBlockingQueue<ByteArray>(4000)
    private val closed = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)
    private var destHost = ""
    private var destPort = 0

    companion object {
        val END_MARKER = ByteArray(0)

        // ★ 共享 client 用独立锁保护
        private val clientLock = Any()
        private var sharedClient: OkHttpClient? = null
        private var sharedClientVpnHash: Int = -1

        fun getOrCreateClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val vpnHash = System.identityHashCode(vpnService)
            synchronized(clientLock) {
                val existing = sharedClient
                // ★ 只有 client 存在且 vpnService 实例一致时才复用
                if (existing != null && sharedClientVpnHash == vpnHash) return existing
                // 清理旧 client
                sharedClient?.let {
                    runCatching { it.dispatcher.cancelAll() }
                    runCatching { it.connectionPool.evictAll() }
                }
                val client = buildClient(cfg, vpnService)
                sharedClient = client
                sharedClientVpnHash = vpnHash
                Log.i(TAG, "✓ OkHttpClient created (vpn=${vpnService != null})")
                return client
            }
        }

        fun clearSharedClients() {
            synchronized(clientLock) {
                sharedClient?.let {
                    runCatching { it.dispatcher.cancelAll() }
                    runCatching { it.connectionPool.evictAll() }
                }
                sharedClient = null
                sharedClientVpnHash = -1  // ★ 必须重置，否则下次 hash 匹配到 null client
                Log.i(TAG, "Shared OkHttpClient cleared")
            }
        }

        private fun buildClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val trustAll = object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
            }
            val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustAll), java.security.SecureRandom())
            }

            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
                // ★ 每次重建都用全新连接池，不复用旧的 broken 连接
                .connectionPool(ConnectionPool(10, 5, TimeUnit.MINUTES))
                .hostnameVerifier { _, _ -> true }
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))

            if (vpnService != null) {
                val protectedFactory = object : javax.net.SocketFactory() {
                    private val def = javax.net.SocketFactory.getDefault()
                    private fun p(s: java.net.Socket): java.net.Socket {
                        s.tcpNoDelay = true
                        runCatching { s.sendBufferSize = 256 * 1024 }
                        runCatching { s.receiveBufferSize = 256 * 1024 }
                        if (!vpnService.protect(s)) Log.e(TAG, "✗ protect() FAILED - routing loop?")
                        return s
                    }
                    override fun createSocket() = p(def.createSocket())
                    override fun createSocket(h: String, port: Int) = p(def.createSocket(h, port))
                    override fun createSocket(h: String, port: Int, la: java.net.InetAddress?, lp: Int) = p(def.createSocket(h, port, la, lp))
                    override fun createSocket(h: java.net.InetAddress, port: Int) = p(def.createSocket(h, port))
                    override fun createSocket(h: java.net.InetAddress, port: Int, la: java.net.InetAddress?, lp: Int) = p(def.createSocket(h, port, la, lp))
                }
                builder.socketFactory(protectedFactory)
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
            } else {
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
                Log.w(TAG, "No protect() - simulator mode")
            }
            return builder.build()
        }
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

        val client = getOrCreateClient(cfg, vpnService)
        val url = buildWsUrl()
        val req = Request.Builder()
            .url(url)
            .header("Host", cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .build()

        Log.i(TAG, "Connecting → $url  target=$destHost:$destPort")
        val delivered = AtomicBoolean(false)
        fun deliver(ok: Boolean) { if (delivered.compareAndSet(false, true)) onResult(ok) }

        client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) { webSocket.cancel(); deliver(false); return }
                if (!wsRef.compareAndSet(null, webSocket)) { webSocket.cancel(); deliver(false); return }
                Log.i(TAG, "✓ WS opened [${response.protocol}]")
                sendFirstPacket(webSocket, earlyData)
                deliver(true)
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed.get() && bytes.size > 0) inQueue.offer(bytes.toByteArray())
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty()) inQueue.offer(text.toByteArray())
            }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closing: $code $reason")
                inQueue.offer(END_MARKER); webSocket.cancel()
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code")
                inQueue.offer(END_MARKER)
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val msg = t.message ?: ""
                val normal = msg.contains("Socket is closed", true) || msg.contains("Socket closed", true) || msg.contains("Connection reset", true)
                if (!closed.get() && !normal) Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: $msg")
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    private fun buildWsUrl(): HttpUrl {
        val scheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"
        return HttpUrl.Builder()
            .scheme(scheme).host(cfg.server).port(cfg.port)
            .encodedPath(cfg.wsPathPart.ifBlank { "/" })
            .also { b -> cfg.wsQueryPart?.let { b.encodedQuery(it) } }
            .build()
    }

    private fun sendFirstPacket(webSocket: WebSocket, earlyData: ByteArray?) {
        if (headerSent.getAndSet(true)) return
        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
        val packet = if (earlyData != null && earlyData.isNotEmpty()) header + earlyData else header
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return
        val myWs = wsRef.get() ?: run { Log.e(TAG, "relay: ws is null"); return }

        var respSkipped = false
        var respHdrSize = -1
        var respBuf = ByteArray(0)
        val downDone = AtomicBoolean(false)
        val relayDone = AtomicBoolean(false)

        val t1 = Thread({
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS)
                    if (chunk == null || chunk === END_MARKER) break
                    val payload: ByteArray? = if (respSkipped) {
                        chunk
                    } else {
                        respBuf += chunk
                        if (respBuf.size < 2) continue
                        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                        if (respBuf.size < respHdrSize) continue
                        respSkipped = true
                        val p = if (respBuf.size > respHdrSize) respBuf.copyOfRange(respHdrSize, respBuf.size) else null
                        respBuf = ByteArray(0); p
                    }
                    if (payload != null && payload.isNotEmpty()) {
                        try { localOut.write(payload); localOut.flush() }
                        catch (_: Exception) { break }
                    }
                }
            } catch (_: Exception) {
            } finally {
                downDone.set(true); relayDone.set(true)
                runCatching { localOut.close() }
            }
        }, "VT-ws2l-$destPort").also { it.isDaemon = true }

        val t2 = Thread({
            try {
                val buf = ByteArray(32768)
                while (!closed.get()) {
                    val n = try { localIn.read(buf) } catch (_: Exception) { break }
                    if (n < 0) break
                    val bs = buf.toByteString(0, n)
                    if (!myWs.send(bs)) break
                }
            } catch (_: Exception) {
            } finally {
                relayDone.set(true)
                inQueue.offer(END_MARKER)
                runCatching { myWs.cancel() }
            }
        }, "VT-l2ws-$destPort").also { it.isDaemon = true }

        t1.start(); t2.start()
        t1.join(); t2.join()
        Log.d(TAG, "relay ended [$destHost:$destPort]")
    }

    fun close() {
        if (closed.getAndSet(true)) return
        inQueue.offer(END_MARKER)
        runCatching { wsRef.get()?.cancel() }
    }
}