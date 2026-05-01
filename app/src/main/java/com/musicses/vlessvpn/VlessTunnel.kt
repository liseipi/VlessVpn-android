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
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "VlessTunnel"

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val wsRef      = AtomicReference<WebSocket?>(null)
    internal val inQueue   = LinkedBlockingQueue<ByteArray>(4000)
    private val closed     = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)
    private var destHost   = ""
    private var destPort   = 0

    // ★ Fix Bug 1: store earlyData here, send together with header+first-payload in relay()
    @Volatile private var pendingEarlyData: ByteArray? = null

    companion object {
        val END_MARKER = ByteArray(0)

        // ── Shared OkHttpClient (one per VpnService instance) ─────────────────
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
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
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
                    override fun createSocket(h: String,  p: Int) = p(def.createSocket(h, p))
                    override fun createSocket(h: String,  p: Int, la: InetAddress?, lp: Int) = p(def.createSocket(h, p, la, lp))
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

        // ── ProtectedDns ──────────────────────────────────────────────────────
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

                    val global = globalIpCache[serverHost]
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
                        else -> {
                            throw UnknownHostException(
                                "ProtectedDns: could not resolve $serverHost (no cache, no response)"
                            )
                        }
                    }
                }
            }

            private fun tryResolveProtected(vpnService: VpnService?): List<InetAddress>? {
                if (vpnService == null) {
                    return runCatching { Dns.SYSTEM.lookup(serverHost).takeIf { it.isNotEmpty() } }
                        .getOrNull()
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
                                if (addrs.isNotEmpty()) {
                                    result.compareAndSet(null, addrs)
                                }
                            } finally {
                                runCatching { sock.close() }
                            }
                        } catch (e: Exception) {
                            Log.d(TAG, "ProtectedDns: DNS via $dnsIp failed: ${e.javaClass.simpleName}: ${e.message}")
                        } finally {
                            latch.countDown()
                        }
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
                    if (buf[pos].toInt() and 0xC0 == 0xC0) {
                        pos += 2
                    } else {
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

    // ── Public API ────────────────────────────────────────────────────────────

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
        val url    = buildWsUrl()
        val req    = Request.Builder()
            .url(url)
            .header("Host",          cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .build()

        Log.i(TAG, "Connecting → $url  target=$destHost:$destPort")

        val resultSent = AtomicBoolean(false)
        fun deliver(ok: Boolean) { if (resultSent.compareAndSet(false, true)) onResult(ok) }

        // ★ Fix Bug 1: save earlyData for relay() to send together with header+first-payload.
        //   Do NOT call sendFirstPacket() in onOpen — that sends an empty-payload header frame
        //   which many VLESS servers (Xray/V2Ray) reject, closing the connection immediately.
        if (earlyData != null && earlyData.isNotEmpty()) {
            pendingEarlyData = earlyData
        }

        client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed.get()) { webSocket.cancel(); deliver(false); return }
                if (!wsRef.compareAndSet(null, webSocket)) { webSocket.cancel(); deliver(false); return }
                Log.i(TAG, "✓ WS opened [${response.protocol}]")
                // ★ Fix Bug 1: no sendFirstPacket here — relay() handles first frame
                deliver(true)
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed.get() && bytes.size > 0) {
                    try { inQueue.put(bytes.toByteArray()) }
                    catch (_: InterruptedException) { Thread.currentThread().interrupt() }
                }
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty()) {
                    try { inQueue.put(text.toByteArray()) }
                    catch (_: InterruptedException) { Thread.currentThread().interrupt() }
                }
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
                val msg      = t.message ?: ""
                val isNormal = msg.contains("Socket is closed", ignoreCase = true)
                        || msg.contains("Socket closed",        ignoreCase = true)
                        || msg.contains("Connection reset",     ignoreCase = true)
                        || msg.contains("Canceled",             ignoreCase = true)
                if (!closed.get() && !isNormal)
                    Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: $msg")
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return
        val myWs = wsRef.get() ?: run { Log.e(TAG, "relay: ws is null"); return }

        var respSkipped = false
        var respHdrSize = -1
        val respBuf     = ByteArrayOutputStream(256)
        val relayDone   = AtomicBoolean(false)
        val wsDownDone  = AtomicBoolean(false)

        // WS → local (downstream)
        val t1 = Thread({
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS) ?: break
                    if (chunk === END_MARKER) break

                    val payload: ByteArray? = if (respSkipped) {
                        chunk
                    } else {
                        respBuf.write(chunk)
                        val buf = respBuf.toByteArray()
                        if (buf.size < 2) continue
                        if (respHdrSize == -1) respHdrSize = 2 + (buf[1].toInt() and 0xFF)
                        if (buf.size < respHdrSize) continue
                        respSkipped = true
                        respBuf.reset()
                        if (buf.size > respHdrSize) buf.copyOfRange(respHdrSize, buf.size) else null
                    }
                    if (payload != null && payload.isNotEmpty()) {
                        try { localOut.write(payload); localOut.flush() }
                        catch (e: Exception) {
                            if (!closed.get() && !relayDone.get())
                                Log.d(TAG, "WS→local write: ${e.message}")
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !relayDone.get()) Log.d(TAG, "WS→local: ${e.message}")
            } finally {
                wsDownDone.set(true); relayDone.set(true)
                runCatching { localOut.close() }
                runCatching { localIn.close() }
            }
        }, "VT-ws2l-$destPort").also { it.isDaemon = true }

        // local → WS (upstream)
        // ★ Fix Bug 1: first write = VLESS header + pendingEarlyData (if any) + first read chunk.
        //   This guarantees header and payload are in the same WebSocket frame, which is required
        //   by Xray/V2Ray VLESS implementations.
        val t2 = Thread({
            try {
                val buf = ByteArray(32768)
                while (!closed.get()) {
                    val n = try { localIn.read(buf) }
                    catch (e: Exception) {
                        if (!closed.get() && !wsDownDone.get() && !relayDone.get())
                            Log.d(TAG, "local→WS read: ${e.message}")
                        break
                    }
                    if (n < 0) break

                    val bs: ByteString = if (!headerSent.getAndSet(true)) {
                        // First frame: header + optional earlyData + current read chunk
                        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                        val early  = pendingEarlyData
                        pendingEarlyData = null
                        when {
                            early != null && early.isNotEmpty() ->
                                (header + early + buf.copyOf(n)).toByteString()
                            else ->
                                (header + buf.copyOf(n)).toByteString()
                        }
                    } else {
                        buf.toByteString(0, n)
                    }

                    if (!myWs.send(bs)) {
                        if (!wsDownDone.get()) Log.d(TAG, "local→WS: send=false")
                        break
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !wsDownDone.get()) Log.d(TAG, "local→WS: ${e.message}")
            } finally {
                relayDone.set(true)
                inQueue.offer(END_MARKER)
                runCatching { myWs.cancel() }
            }
        }, "VT-l2ws-$destPort").also { it.isDaemon = true }

        t1.start(); t2.start()
        t1.join();  t2.join()
        Log.d(TAG, "relay ended [$destHost:$destPort]")
    }

    fun close() {
        if (closed.getAndSet(true)) return
        inQueue.offer(END_MARKER)
        runCatching { wsRef.getAndSet(null)?.cancel() }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private fun buildWsUrl(): HttpUrl {
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