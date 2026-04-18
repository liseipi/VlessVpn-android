package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "VlessTunnel"

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val wsRef     = AtomicReference<WebSocket?>(null)
    internal val inQueue  = LinkedBlockingQueue<ByteArray>(4000)
    private val closed    = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)
    private var destHost  = ""
    private var destPort  = 0

    companion object {
        val END_MARKER = ByteArray(0)

        @Volatile private var sharedClient: OkHttpClient? = null
        @Volatile private var sharedClientVpnRef: Int = -1

        fun getOrCreateClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val vpnHash = System.identityHashCode(vpnService)
            val existing = sharedClient
            if (existing != null && sharedClientVpnRef == vpnHash) return existing
            synchronized(VlessTunnel::class.java) {
                val double = sharedClient
                if (double != null && sharedClientVpnRef == vpnHash) return double
                val client = buildClient(cfg, vpnService)
                sharedClient = client
                sharedClientVpnRef = vpnHash
                Log.i(TAG, "✓ OkHttpClient created (vpn=${vpnService != null})")
                return client
            }
        }

        fun clearSharedClients() {
            synchronized(VlessTunnel::class.java) {
                sharedClient?.dispatcher?.cancelAll()
                sharedClient?.connectionPool?.evictAll()
                sharedClient = null
                sharedClientVpnRef = -1
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

            // ── Custom DNS that bypasses VPN routing ─────────────────────────
            // InetAddress.getByName() uses the system network stack, which means
            // after the TUN interface is up, DNS lookups for the VLESS server
            // hostname go INTO the VPN tunnel → routing loop → UnknownHostException.
            // We fix this by resolving the server hostname via a UDP socket that
            // has been protected from the VPN, then caching the result.
            val protectedDns = ProtectedDns(cfg.server, vpnService)

            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
                .connectionPool(ConnectionPool(10, 5, TimeUnit.MINUTES))
                .hostnameVerifier { _, _ -> true }
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .dns(protectedDns)   // ← the key fix

            if (vpnService != null) {
                val protectedSocketFactory = object : javax.net.SocketFactory() {
                    private val default = javax.net.SocketFactory.getDefault()

                    private fun protect(sock: java.net.Socket): java.net.Socket {
                        sock.tcpNoDelay = true
                        try { sock.sendBufferSize    = 256 * 1024 } catch (_: Exception) {}
                        try { sock.receiveBufferSize = 256 * 1024 } catch (_: Exception) {}
                        val ok = vpnService.protect(sock)
                        if (!ok) Log.e(TAG, "✗ protect(socket) FAILED — routing loop risk!")
                        return sock
                    }

                    override fun createSocket() = protect(default.createSocket())
                    override fun createSocket(h: String, p: Int) = protect(default.createSocket(h, p))
                    override fun createSocket(h: String, p: Int, la: InetAddress?, lp: Int) =
                        protect(default.createSocket(h, p, la, lp))
                    override fun createSocket(h: InetAddress, p: Int) = protect(default.createSocket(h, p))
                    override fun createSocket(h: InetAddress, p: Int, la: InetAddress?, lp: Int) =
                        protect(default.createSocket(h, p, la, lp))
                }
                builder.socketFactory(protectedSocketFactory)
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
            } else {
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
                Log.w(TAG, "Building OkHttpClient WITHOUT protect (emulator mode)")
            }

            return builder.build()
        }

        // ── Protected DNS resolver ─────────────────────────────────────────────
        /**
         * Resolves [serverHost] via a VpnService-protected UDP socket so the DNS
         * query bypasses the TUN interface entirely.  Result is cached permanently
         * (for the lifetime of this OkHttpClient instance).
         *
         * All other hostnames fall through to OkHttp's default system resolver,
         * which means proxied-target lookups still go through the VPN as intended.
         */
        private class ProtectedDns(
            private val serverHost: String,
            private val vpnService: VpnService?
        ) : Dns {

            @Volatile private var cached: List<InetAddress>? = null

            override fun lookup(hostname: String): List<InetAddress> {
                if (hostname != serverHost) return Dns.SYSTEM.lookup(hostname)
                cached?.let { return it }
                return synchronized(this) {
                    cached?.let { return it }
                    val resolved = resolve()
                    cached = resolved
                    resolved
                }
            }

            private fun resolve(): List<InetAddress> {
                if (vpnService == null) {
                    // Emulator / no VPN — plain system DNS is fine.
                    return Dns.SYSTEM.lookup(serverHost)
                }
                return try {
                    val addrs = resolveViaProtectedUdp(serverHost, vpnService)
                    if (addrs.isNotEmpty()) {
                        Log.i(TAG, "ProtectedDns: $serverHost → ${addrs.map { it.hostAddress }}")
                        addrs
                    } else {
                        Log.w(TAG, "ProtectedDns: empty result, falling back")
                        Dns.SYSTEM.lookup(serverHost)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "ProtectedDns: resolve failed (${e.message}), falling back")
                    Dns.SYSTEM.lookup(serverHost)
                }
            }

            /** Send a minimal DNS A-query over a protected UDP socket. */
            private fun resolveViaProtectedUdp(
                hostname: String,
                vpnService: VpnService
            ): List<InetAddress> {
                val dnsAddr = InetAddress.getByName("8.8.8.8")
                val sock    = DatagramSocket()
                vpnService.protect(sock)   // ← bypasses VPN routing for this socket
                return try {
                    sock.soTimeout = 5_000
                    val query  = buildDnsQuery(hostname)
                    sock.send(DatagramPacket(query, query.size, dnsAddr, 53))
                    val buf    = ByteArray(512)
                    val pkt    = DatagramPacket(buf, buf.size)
                    sock.receive(pkt)
                    parseDnsARecords(buf, pkt.length)
                } finally {
                    runCatching { sock.close() }
                }
            }

            private fun buildDnsQuery(hostname: String): ByteArray {
                val out = java.io.ByteArrayOutputStream()
                out.write(0x12); out.write(0x34)  // txid
                out.write(0x01); out.write(0x00)  // flags: recursion desired
                out.write(0x00); out.write(0x01)  // qdcount = 1
                repeat(6) { out.write(0x00) }     // ancount/nscount/arcount = 0
                for (label in hostname.split(".")) {
                    out.write(label.length)
                    out.write(label.toByteArray())
                }
                out.write(0x00)                   // root label
                out.write(0x00); out.write(0x01)  // qtype = A
                out.write(0x00); out.write(0x01)  // qclass = IN
                return out.toByteArray()
            }

            private fun parseDnsARecords(buf: ByteArray, len: Int): List<InetAddress> {
                val result   = mutableListOf<InetAddress>()
                if (len < 12) return result
                val anCount  = ((buf[6].toInt() and 0xFF) shl 8) or (buf[7].toInt() and 0xFF)
                if (anCount == 0) return result

                // Skip header (12 bytes) + question section
                var pos = 12
                while (pos < len) {
                    val b = buf[pos].toInt() and 0xFF
                    if (b and 0xC0 == 0xC0) { pos += 2; break }   // DNS pointer
                    if (b == 0) { pos++; break }                    // root label
                    pos += b + 1
                }
                pos += 4  // skip QTYPE + QCLASS

                repeat(anCount) {
                    if (pos >= len) return@repeat
                    // Skip NAME
                    if (buf[pos].toInt() and 0xC0 == 0xC0) {
                        pos += 2
                    } else {
                        while (pos < len) {
                            val b = buf[pos].toInt() and 0xFF
                            if (b and 0xC0 == 0xC0) { pos += 2; return@repeat }
                            if (b == 0) { pos++; break }
                            pos += b + 1
                        }
                    }
                    if (pos + 10 > len) return@repeat
                    val type  = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos+1].toInt() and 0xFF)
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

    // ── connect / relay / close — unchanged from your working version ──────────

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
                val msg      = t.message ?: ""
                val isNormal = msg.contains("Socket is closed", true)
                        || msg.contains("Socket closed", true)
                        || msg.contains("Connection reset", true)
                if (!closed.get() && !isNormal)
                    Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: $msg")
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

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

    private fun sendFirstPacket(webSocket: WebSocket, earlyData: ByteArray?) {
        if (headerSent.getAndSet(true)) return
        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
        val packet = if (earlyData != null && earlyData.isNotEmpty()) header + earlyData else header
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return
        val myWs = wsRef.get() ?: run { Log.e(TAG, "relay: ws is null"); return }

        var respSkipped  = false
        var respHdrSize  = -1
        var respBuf      = ByteArray(0)
        val wsToLocalDone  = AtomicBoolean(false)
        val relayDone      = AtomicBoolean(false)

        val t1 = Thread({
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS) ?: break
                    if (chunk === END_MARKER) break
                    val payload: ByteArray? = if (respSkipped) {
                        chunk
                    } else {
                        respBuf = respBuf + chunk
                        if (respBuf.size < 2) continue
                        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                        if (respBuf.size < respHdrSize) continue
                        respSkipped = true
                        val p = if (respBuf.size > respHdrSize)
                            respBuf.copyOfRange(respHdrSize, respBuf.size) else null
                        respBuf = ByteArray(0)
                        p
                    }
                    if (payload != null && payload.isNotEmpty()) {
                        try { localOut.write(payload); localOut.flush() }
                        catch (e: Exception) {
                            if (!closed.get() && !relayDone.get()) Log.d(TAG, "WS→local write: ${e.message}")
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !relayDone.get()) Log.d(TAG, "WS→local: ${e.message}")
            } finally {
                wsToLocalDone.set(true); relayDone.set(true)
                runCatching { localOut.close() }
            }
        }, "VT-ws2l-$destPort").also { it.isDaemon = true }

        val t2 = Thread({
            try {
                val buf = ByteArray(32768)
                while (!closed.get()) {
                    val n = try { localIn.read(buf) }
                    catch (e: Exception) {
                        if (!closed.get() && !wsToLocalDone.get() && !relayDone.get())
                            Log.d(TAG, "local→WS read: ${e.message}")
                        break
                    }
                    if (n < 0) break
                    val bs: ByteString = if (!headerSent.get()) {
                        val hdr = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                        headerSent.set(true)
                        (hdr + buf.copyOf(n)).toByteString()
                    } else {
                        buf.toByteString(0, n)
                    }
                    if (!myWs.send(bs)) {
                        if (!wsToLocalDone.get()) Log.d(TAG, "local→WS: send=false")
                        break
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !wsToLocalDone.get()) Log.d(TAG, "local→WS: ${e.message}")
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
        runCatching { wsRef.getAndSet(null)?.cancel() }  // getAndSet to avoid double-cancel
    }
}