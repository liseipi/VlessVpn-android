package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okhttp3.ConnectionPool
import okio.ByteString
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

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private val wsRef = AtomicReference<WebSocket?>(null)
    private val inQueue = LinkedBlockingQueue<ByteArray>(4000)
    private val closed = AtomicBoolean(false)
    private val headerSent = AtomicBoolean(false)
    private var destHost = ""
    private var destPort = 0

    companion object {
        val END_MARKER = ByteArray(0)
        @Volatile private var sharedClient: OkHttpClient? = null
        @Volatile private var sharedClientVpn: VpnService? = null

        fun getOrCreateClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val existing = sharedClient
            if (existing != null && sharedClientVpn === vpnService) return existing
            synchronized(this) {
                val double = sharedClient
                if (double != null && sharedClientVpn === vpnService) return double
                val client = buildClient(cfg, vpnService)
                sharedClient = client; sharedClientVpn = vpnService
                Log.i(TAG, "✓ Created shared OkHttpClient"); return client
            }
        }

        fun clearSharedClients() {
            synchronized(this) {
                sharedClient?.dispatcher?.cancelAll()
                sharedClient?.connectionPool?.evictAll()
                sharedClient = null; sharedClientVpn = null
                Log.i(TAG, "Shared OkHttpClient cleared")
            }
        }

        private fun buildClient(cfg: VlessConfig, vpnService: VpnService?): OkHttpClient {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val sslCtx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .writeTimeout(0, TimeUnit.SECONDS)
                .connectionPool(ConnectionPool(10, 5, TimeUnit.MINUTES))
                .pingInterval(25, TimeUnit.SECONDS)
                .hostnameVerifier { _, _ -> true }
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))

            if (vpnService != null) {
                builder.socketFactory(object : javax.net.SocketFactory() {
                    private val def = javax.net.SocketFactory.getDefault()
                    private fun p(s: Socket): Socket {
                        s.tcpNoDelay = true
                        try { s.sendBufferSize = 256 * 1024 } catch (_: Exception) {}
                        try { s.receiveBufferSize = 256 * 1024 } catch (_: Exception) {}
                        if (!vpnService.protect(s)) Log.w(TAG, "protect failed")
                        return s
                    }
                    override fun createSocket() = p(def.createSocket())
                    override fun createSocket(h: String, port: Int) = p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: String, port: Int, la: java.net.InetAddress, lp: Int) = p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: java.net.InetAddress, port: Int) = p(def.createSocket()).also { it.connect(InetSocketAddress(h, port), 15000) }
                    override fun createSocket(h: java.net.InetAddress, port: Int, la: java.net.InetAddress, lp: Int) = p(def.createSocket()).also { it.bind(InetSocketAddress(la, lp)); it.connect(InetSocketAddress(h, port), 15000) }
                })
                val baseSsl = sslCtx.socketFactory
                builder.sslSocketFactory(object : SSLSocketFactory() {
                    override fun getDefaultCipherSuites() = baseSsl.defaultCipherSuites
                    override fun getSupportedCipherSuites() = baseSsl.supportedCipherSuites
                    override fun createSocket(s: Socket, h: String, p: Int, ac: Boolean) = baseSsl.createSocket(s, h, p, ac).also { vpnService.protect(it) }
                    override fun createSocket(h: String, p: Int) = baseSsl.createSocket(h, p).also { vpnService.protect(it) }
                    override fun createSocket(h: String, p: Int, la: java.net.InetAddress, lp: Int) = baseSsl.createSocket(h, p, la, lp).also { vpnService.protect(it) }
                    override fun createSocket(h: java.net.InetAddress, p: Int) = baseSsl.createSocket(h, p).also { vpnService.protect(it) }
                    override fun createSocket(h: java.net.InetAddress, p: Int, la: java.net.InetAddress, lp: Int) = baseSsl.createSocket(h, p, la, lp).also { vpnService.protect(it) }
                }, trustAll)
            } else {
                builder.sslSocketFactory(sslCtx.socketFactory, trustAll)
            }
            return builder.build()
        }
    }

    fun connect(destHost: String, destPort: Int, earlyData: ByteArray? = null, onResult: (Boolean) -> Unit) {
        if (closed.get()) { onResult(false); return }
        this.destHost = destHost; this.destPort = destPort
        val client = getOrCreateClient(cfg, vpnService)
        val url = buildWsUrl()
        val req = Request.Builder().url(url)
            .header("Host", cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .build()
        Log.i(TAG, "Connecting: $url  target=$destHost:$destPort")
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
            override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
                if (!closed.get() && bytes.size > 0) inQueue.offer(bytes.toByteArray())
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed.get() && text.isNotEmpty()) inQueue.offer(text.toByteArray())
            }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closing: $code"); inQueue.offer(END_MARKER); webSocket.cancel()
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WS closed: $code"); inQueue.offer(END_MARKER)
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val msg = t.message ?: ""
                val normal = msg.contains("Socket is closed", true) || msg.contains("Socket closed", true) || msg.contains("Connection reset", true)
                if (!closed.get() && !normal) Log.e(TAG, "✗ WS: ${t.javaClass.simpleName}: $msg")
                inQueue.offer(END_MARKER); deliver(false)
            }
        })
    }

    private fun buildWsUrl(): HttpUrl {
        val scheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"
        val builder = HttpUrl.Builder().scheme(scheme).host(cfg.server).port(cfg.port)
            .encodedPath(cfg.wsPathPart.ifBlank { "/" })
        cfg.wsQueryPart?.let { builder.encodedQuery(it) }
        return builder.build()
    }

    private fun sendFirstPacket(webSocket: WebSocket, earlyData: ByteArray?) {
        if (headerSent.getAndSet(true)) return
        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
        val packet = if (earlyData != null && earlyData.isNotEmpty()) {
            Log.d(TAG, "→ header(${header.size}B) + earlyData(${earlyData.size}B)")
            header + earlyData
        } else { Log.d(TAG, "→ header only (${header.size}B)"); header }
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return
        val myWs = wsRef.get() ?: run { Log.e(TAG, "relay: ws is null"); return }

        var respSkipped = false; var respHdrSize = -1; var respBuf = ByteArray(0)
        val wsToLocalDone = AtomicBoolean(false)
        val localToWsDone = AtomicBoolean(false)
        val relayDone = AtomicBoolean(false)

        val t1 = Thread {
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS)
                    if (chunk == null) { Log.d(TAG, "WS→local: 120s idle"); break }
                    if (chunk === END_MARKER) { Log.d(TAG, "WS→local: END"); break }
                    val payload: ByteArray? = if (respSkipped) chunk else {
                        respBuf = respBuf + chunk
                        if (respBuf.size < 2) continue
                        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                        if (respBuf.size < respHdrSize) continue
                        respSkipped = true
                        val p = if (respBuf.size > respHdrSize) respBuf.copyOfRange(respHdrSize, respBuf.size) else null
                        respBuf = ByteArray(0); p
                    }
                    if (payload != null && payload.isNotEmpty()) {
                        try { localOut.write(payload); localOut.flush() }
                        catch (e: Exception) { if (!closed.get() && !relayDone.get()) Log.d(TAG, "WS→local write: ${e.message}"); break }
                    }
                }
            } catch (e: Exception) { if (!closed.get() && !relayDone.get()) Log.d(TAG, "WS→local: ${e.message}") }
            finally {
                wsToLocalDone.set(true); relayDone.set(true)
                runCatching { localOut.close() }
            }
        }.apply { isDaemon = true; name = "VT-ws2l-$destPort" }

        val t2 = Thread {
            try {
                val buf = ByteArray(32768)

                while (!closed.get()) {
                    val n = try {
                        localIn.read(buf)
                    } catch (e: Exception) {
                        if (!closed.get() && !wsToLocalDone.get() && !relayDone.get()) {
                            Log.d(TAG, "local→WS: ${e.message}")
                        }
                        break
                    }

                    if (n < 0) break

                    val bs: ByteString = if (!headerSent.get()) {
                        val hdr = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                        headerSent.set(true)
                        (hdr + buf.copyOf(n)).toByteString()
                    } else {
                        buf.toByteString(0, n)          // ← 关键修改点
                    }

                    val ok = myWs.send(bs)
                    if (!ok) {
                        if (!wsToLocalDone.get()) Log.d(TAG, "local→WS: send=false")
                        break
                    }
                }
            } catch (e: Exception) {
                if (!closed.get() && !wsToLocalDone.get()) Log.d(TAG, "local→WS: ${e.message}")
            } finally {
                localToWsDone.set(true); relayDone.set(true)
                inQueue.offer(END_MARKER)
                runCatching { myWs.cancel() }
            }
        }.apply { isDaemon = true; name = "VT-l2ws-$destPort" }

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