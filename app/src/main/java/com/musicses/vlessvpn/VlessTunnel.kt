package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

private const val TAG = "VlessTunnel"

// ── 工具函数 ──────────────────────────────────────────────────────────────────

private fun safeWrite(out: OutputStream, data: ByteArray) {
    try { out.write(data); out.flush() } catch (_: Exception) {}
}

// ── VlessRelayFull：WS ↔ Socket 双向中继（来自 VlessProxyClient） ─────────────

/**
 * 核心中继器：
 *  - WS → Socket：解析并跳过 VLESS 响应头，之后直接透传
 *  - Socket → WS：在 [startSockToWs] 中读取本地 socket 并发送到 WS
 */
class VlessRelayFull(private val sock: java.net.Socket) {

    private var ws: WebSocket? = null
    private var respBuf     = ByteArray(0)
    private var respSkipped = false
    private var respHdrSize = -1

    fun attachWs(ws: WebSocket) { this.ws = ws }

    /** 由 WS onMessage 回调 —— 处理下行数据（远端 → 本地） */
    fun onWsMessage(data: ByteArray) {
        if (sock.isClosed) return

        if (respSkipped) {
            safeWrite(sock.getOutputStream(), data)
            return
        }

        // 累积直到能读取响应头长度
        respBuf = respBuf + data
        if (respBuf.size < 2) return
        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
        if (respBuf.size < respHdrSize) return

        // 跳过响应头，转发剩余 payload
        respSkipped = true
        val payload = respBuf.copyOfRange(respHdrSize, respBuf.size)
        respBuf = ByteArray(0)
        if (payload.isNotEmpty()) safeWrite(sock.getOutputStream(), payload)
    }

    /** 启动上行线程（本地 Socket → WS） */
    fun startSockToWs() {
        thread(isDaemon = true, name = "vless-up-${sock.port}") {
            try {
                val buf = ByteArray(32 * 1024)
                val ins: InputStream = sock.getInputStream()
                while (!sock.isClosed) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    ws?.send(buf.toByteString(0, n))
                }
            } catch (_: Exception) {}
            cleanup()
        }
    }

    fun cleanup() {
        try { ws?.close(1000, null) } catch (_: Exception) {}
        try { sock.close() }         catch (_: Exception) {}
    }
}

// ── VlessTunnel：对外接口（供 LocalSocks5Server 调用） ───────────────────────

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val closed = AtomicBoolean(false)

    // 仅供 LocalSocks5Server.readTunnelResponse() 的 UDP 路径使用
    // TCP 路径不再使用 queue，改为 VlessRelayFull 直接回调
    internal val inQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(4000)

    companion object {
        val END_MARKER = ByteArray(0)

        // ── 共享 OkHttpClient ─────────────────────────────────────────────────
        @Volatile private var sharedClient: OkHttpClient? = null
        @Volatile private var sharedClientVpnRef: Int = -1

        fun getOrCreateClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val vpnHash = System.identityHashCode(vpnService)
            sharedClient?.takeIf { sharedClientVpnRef == vpnHash }?.let { return it }
            return synchronized(VlessTunnel::class.java) {
                sharedClient?.takeIf { sharedClientVpnRef == vpnHash }?.let { return it }
                buildClient(cfg, vpnService).also {
                    sharedClient       = it
                    sharedClientVpnRef = vpnHash
                    Log.i(TAG, "✓ OkHttpClient created (vpn=${vpnService != null})")
                }
            }
        }

        fun clearSharedClients() {
            synchronized(VlessTunnel::class.java) {
                sharedClient?.dispatcher?.cancelAll()
                sharedClient?.connectionPool?.evictAll()
                sharedClient       = null
                sharedClientVpnRef = -1
                Log.i(TAG, "Shared OkHttpClient cleared")
            }
        }

        private fun buildClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val trustAll = object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
            }
            val effectiveTM = if (cfg.rejectUnauthorized) null else trustAll

            val dns = ProtectedDns(cfg.server, vpnService)

            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)   // 长连接不超时（对齐 VlessProxyClient）
                .writeTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
                .connectionPool(ConnectionPool(10, 5, TimeUnit.MINUTES))
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .dns(dns)

            if (!cfg.rejectUnauthorized) {
                builder.hostnameVerifier { _, _ -> true }
            }

            if (vpnService != null) {
                val factory = object : javax.net.SocketFactory() {
                    private val def = javax.net.SocketFactory.getDefault()
                    private fun p(s: java.net.Socket): java.net.Socket {
                        s.tcpNoDelay = true
                        runCatching { s.sendBufferSize    = 256 * 1024 }
                        runCatching { s.receiveBufferSize = 256 * 1024 }
                        if (!vpnService.protect(s))
                            Log.e(TAG, "✗ protect(socket) FAILED — possible routing loop!")
                        return s
                    }
                    override fun createSocket() = p(def.createSocket())
                    override fun createSocket(h: String, p: Int) = p(def.createSocket(h, p))
                    override fun createSocket(h: String, p: Int, la: InetAddress?, lp: Int) = p(def.createSocket(h, p, la, lp))
                    override fun createSocket(h: InetAddress, p: Int) = p(def.createSocket(h, p))
                    override fun createSocket(h: InetAddress, p: Int, la: InetAddress?, lp: Int) = p(def.createSocket(h, p, la, lp))
                }
                builder.socketFactory(factory)
                if (effectiveTM != null) {
                    val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                        init(null, arrayOf(effectiveTM), java.security.SecureRandom())
                    }
                    builder.sslSocketFactory(sslCtx.socketFactory, effectiveTM)
                }
            } else {
                if (effectiveTM != null) {
                    val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                        init(null, arrayOf(effectiveTM), java.security.SecureRandom())
                    }
                    builder.sslSocketFactory(sslCtx.socketFactory, effectiveTM)
                }
                Log.w(TAG, "Building OkHttpClient WITHOUT protect (emulator mode)")
            }

            return builder.build()
        }

        // ── ProtectedDns（完整保留，Android 必需） ───────────────────────────
        private val globalIpCache = ConcurrentHashMap<String, List<InetAddress>>()

        fun clearDnsCache() {
            globalIpCache.clear()
            Log.i(TAG, "ProtectedDns global cache cleared")
        }

        private class ProtectedDns(
            private val serverHost: String,
            private val vpnService: VpnService?
        ) : Dns {

            @Volatile private var sessionCache: List<InetAddress>? = null

            override fun lookup(hostname: String): List<InetAddress> {
                if (hostname != serverHost) return Dns.SYSTEM.lookup(hostname)
                sessionCache?.let { return it }
                return synchronized(this) {
                    sessionCache?.let { return it }
                    val global   = globalIpCache[serverHost]
                    val resolved = tryResolveProtected(vpnService)
                    when {
                        resolved != null -> {
                            Log.i(TAG, "ProtectedDns: $serverHost → ${resolved.map { it.hostAddress }}")
                            globalIpCache[serverHost] = resolved
                            sessionCache = resolved
                            resolved
                        }
                        global != null -> {
                            Log.w(TAG, "ProtectedDns: resolution failed, using cached ${global.map { it.hostAddress }}")
                            sessionCache = global
                            global
                        }
                        else -> throw UnknownHostException(
                            "ProtectedDns: could not resolve $serverHost (no cache, no response)"
                        )
                    }
                }
            }

            private fun tryResolveProtected(vpnService: VpnService?): List<InetAddress>? {
                if (vpnService == null) {
                    return runCatching { Dns.SYSTEM.lookup(serverHost).takeIf { it.isNotEmpty() } }.getOrNull()
                }
                val DNS_SERVERS = listOf("8.8.8.8", "8.8.4.4")
                val TIMEOUT_MS  = 2_000L
                val result  = AtomicReference<List<InetAddress>?>(null)
                val latch   = CountDownLatch(DNS_SERVERS.size)
                val query   = buildDnsQuery(serverHost)
                val threads = DNS_SERVERS.map { dnsIp ->
                    Thread({
                        try {
                            val sock = DatagramSocket()
                            vpnService.protect(sock)
                            sock.soTimeout = TIMEOUT_MS.toInt()
                            try {
                                val dest = InetAddress.getByName(dnsIp)
                                sock.send(DatagramPacket(query, query.size, dest, 53))
                                val buf = ByteArray(512)
                                val pkt = DatagramPacket(buf, buf.size)
                                sock.receive(pkt)
                                val addrs = parseDnsARecords(buf, pkt.length)
                                if (addrs.isNotEmpty()) result.compareAndSet(null, addrs)
                            } finally { runCatching { sock.close() } }
                        } catch (e: Exception) {
                            Log.d(TAG, "ProtectedDns: DNS via $dnsIp failed: ${e.javaClass.simpleName}: ${e.message}")
                        } finally { latch.countDown() }
                    }, "pdns-$dnsIp").also { it.isDaemon = true }
                }
                threads.forEach { it.start() }
                latch.await(TIMEOUT_MS + 500, TimeUnit.MILLISECONDS)
                threads.forEach { it.interrupt() }
                return result.get()
            }

            private fun buildDnsQuery(hostname: String): ByteArray {
                val out = ByteArrayOutputStream()
                out.write(0x12); out.write(0x34)
                out.write(0x01); out.write(0x00)
                out.write(0x00); out.write(0x01)
                repeat(6) { out.write(0x00) }
                hostname.split(".").forEach { label ->
                    out.write(label.length)
                    out.write(label.toByteArray())
                }
                out.write(0x00)
                out.write(0x00); out.write(0x01)
                out.write(0x00); out.write(0x01)
                return out.toByteArray()
            }

            private fun parseDnsARecords(buf: ByteArray, len: Int): List<InetAddress> {
                val result  = mutableListOf<InetAddress>()
                if (len < 12) return result
                val anCount = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
                if (anCount == 0) return result
                var pos = 12
                while (pos < len) {
                    val b = buf[pos].toInt() and 0xFF
                    if (b and 0xC0 == 0xC0) { pos += 2; break }
                    if (b == 0)             { pos++;    break }
                    pos += b + 1
                }
                pos += 4
                repeat(anCount) {
                    if (pos >= len) return@repeat
                    if (buf[pos].toInt() and 0xC0 == 0xC0) { pos += 2 }
                    else {
                        while (pos < len) {
                            val b = buf[pos].toInt() and 0xFF
                            if (b and 0xC0 == 0xC0) { pos += 2; break }
                            if (b == 0)             { pos++;    break }
                            pos += b + 1
                        }
                    }
                    if (pos + 10 > len) return@repeat
                    val type  = ((buf[pos].toInt()   and 0xFF) shl 8) or (buf[pos+1].toInt() and 0xFF)
                    val rdLen = ((buf[pos+8].toInt() and 0xFF) shl 8) or (buf[pos+9].toInt() and 0xFF)
                    pos += 10
                    if (type == 1 && rdLen == 4 && pos + 4 <= len) {
                        result.add(InetAddress.getByAddress(buf.copyOfRange(pos, pos + 4)))
                    }
                    pos += rdLen
                }
                return result
            }
        }
    }

    // ── 公开 API ──────────────────────────────────────────────────────────────

    /**
     * TCP CONNECT 模式（主路径）
     *
     * 采用 VlessProxyClient.openTunnelWithRelay() 模式：
     *   1. 建立 WS 连接
     *   2. onOpen 立即发送 VLESS 头 + earlyData（一次 send，减少 RTT）
     *   3. WS listener 内置，直接回调 relay.onWsMessage()
     *   4. 不再使用 LinkedBlockingQueue，避免了额外的线程切换
     */
    fun connectAndRelay(
        localSock: java.net.Socket,
        destHost: String,
        destPort: Int,
        earlyData: ByteArray?,
        onConnected: (Boolean) -> Unit
    ) {
        if (closed.get()) { onConnected(false); return }

        val client  = getOrCreateClient(cfg, vpnService)
        val url     = buildWsUrl()
        val request = Request.Builder()
            .url(url)
            .header("Host",          cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .header("Pragma",        "no-cache")
            .build()

        Log.i(TAG, "Connecting → $url  target=$destHost:$destPort")

        val relay       = VlessRelayFull(localSock)
        val resultSent  = AtomicBoolean(false)
        fun deliver(ok: Boolean) { if (resultSent.compareAndSet(false, true)) onConnected(ok) }

        client.newWebSocket(request, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) { webSocket.cancel(); deliver(false); return }

                // ★ 核心改进：onOpen 时立即将 VLESS 头 + earlyData 合并为一个包发送
                //   与 VlessProxyClient.openTunnelWithRelay() 完全对齐
                val vlessHdr = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                val firstPkt = if (earlyData != null && earlyData.isNotEmpty())
                    vlessHdr + earlyData else vlessHdr
                webSocket.send(firstPkt.toByteString())

                relay.attachWs(webSocket)
                relay.startSockToWs()

                Log.i(TAG, "✓ WS opened [${response.protocol}]  sent ${firstPkt.size}B")
                deliver(true)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed.get()) relay.onWsMessage(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get()) relay.onWsMessage(text.toByteArray())
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closing: $code $reason")
                webSocket.cancel()
                relay.cleanup()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code")
                relay.cleanup()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val msg      = t.message ?: ""
                val isNormal = msg.contains("Socket is closed", ignoreCase = true)
                        || msg.contains("Socket closed",        ignoreCase = true)
                        || msg.contains("Connection reset",     ignoreCase = true)
                        || msg.contains("Canceled",             ignoreCase = true)
                if (!closed.get() && !isNormal)
                    Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: $msg")
                relay.cleanup()
                deliver(false)
            }
        })
    }

    /**
     * UDP / DNS 模式（inQueue 路径，供 LocalSocks5Server.readTunnelResponse 使用）
     *
     * 保留原有 inQueue 机制，因为 UDP 是一问一答模式，
     * readTunnelResponse() 需要主动 poll 响应包。
     */
    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        if (closed.get()) { onResult(false); return }

        val client  = getOrCreateClient(cfg, vpnService)
        val url     = buildWsUrl()
        val request = Request.Builder()
            .url(url)
            .header("Host",          cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .header("Pragma",        "no-cache")
            .build()

        val wsRef      = AtomicReference<WebSocket?>(null)
        val resultSent = AtomicBoolean(false)
        fun deliver(ok: Boolean) { if (resultSent.compareAndSet(false, true)) onResult(ok) }

        client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) { webSocket.cancel(); deliver(false); return }
                wsRef.set(webSocket)

                val vlessHdr = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                val firstPkt = if (earlyData != null && earlyData.isNotEmpty())
                    vlessHdr + earlyData else vlessHdr
                webSocket.send(firstPkt.toByteString())

                Log.d(TAG, "✓ UDP tunnel WS opened → $destHost:$destPort")
                deliver(true)
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed.get() && bytes.size > 0)
                    try { inQueue.put(bytes.toByteArray()) }
                    catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty())
                    try { inQueue.put(text.toByteArray()) }
                    catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                inQueue.offer(END_MARKER); webSocket.cancel()
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                inQueue.offer(END_MARKER)
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val msg      = t.message ?: ""
                val isNormal = msg.contains("Socket is closed", ignoreCase = true)
                        || msg.contains("Canceled",             ignoreCase = true)
                if (!closed.get() && !isNormal)
                    Log.e(TAG, "✗ UDP WS failure: ${t.javaClass.simpleName}: $msg")
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    fun close() {
        if (closed.getAndSet(true)) return
        inQueue.offer(END_MARKER)
    }

    // ── 私有工具 ──────────────────────────────────────────────────────────────

    private fun buildWsUrl(): HttpUrl {
        // 对齐 VlessProxyClient.buildWsUrl()：security=="tls" 或 port==443 → wss
        val scheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"
        return HttpUrl.Builder()
            .scheme(scheme)
            .host(cfg.server)
            .port(cfg.port)
            .encodedPath(cfg.wsPathPart.ifBlank { "/" })
            .also { b -> cfg.wsQueryPart?.let { b.encodedQuery(it) } }
            .build()
    }
}