package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
import okhttp3.ConnectionPool
import okio.ByteString
import okio.ByteString.Companion.toByteString  // buf.toByteString(offset, count) 扩展函数
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

import java.net.InetAddress
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

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

        // ★ 关键修复：sharedClient 必须和 vpnService 绑定
        // 真机上：vpnService != null 时必须用带 protect 的 client
        // 模拟器侥幸能工作是因为虚拟网络不会产生路由环路
        @Volatile private var sharedClient: OkHttpClient? = null
        @Volatile private var sharedClientVpnRef: Int = -1  // 用 System.identityHashCode 避免错误的 null===null 命中

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

            val sslContext = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustAll), java.security.SecureRandom())
            }

            val builder = OkHttpClient.Builder()
                .connectTimeout(15, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(60, java.util.concurrent.TimeUnit.SECONDS)
                .writeTimeout(60, java.util.concurrent.TimeUnit.SECONDS)
                .pingInterval(25, java.util.concurrent.TimeUnit.SECONDS)
                .connectionPool(okhttp3.ConnectionPool(10, 5, java.util.concurrent.TimeUnit.MINUTES))
                .hostnameVerifier { _, _ -> true }
                .protocols(listOf(okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1))

            if (vpnService != null) {
                Log.i(TAG, "Building OkHttpClient WITH protect() for real device")

                val protectedSocketFactory = object : javax.net.SocketFactory() {
                    private val defaultFactory = javax.net.SocketFactory.getDefault()

                    private fun protect(socket: java.net.Socket): java.net.Socket {
                        socket.tcpNoDelay = true
                        try { socket.sendBufferSize = 256 * 1024 } catch (_: Exception) {}
                        try { socket.receiveBufferSize = 256 * 1024 } catch (_: Exception) {}

                        val success = vpnService.protect(socket)
                        if (!success) {
                            Log.e(TAG, "✗ protect(socket) FAILED! Possible routing loop!")
                        }
                        return socket
                    }

                    override fun createSocket() = protect(defaultFactory.createSocket())
                    override fun createSocket(host: String, port: Int) = protect(defaultFactory.createSocket(host, port))
                    override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress?, localPort: Int) =
                        protect(defaultFactory.createSocket(host, port, localHost, localPort))
                    override fun createSocket(host: java.net.InetAddress, port: Int) = protect(defaultFactory.createSocket(host, port))
                    override fun createSocket(host: java.net.InetAddress, port: Int, localHost: java.net.InetAddress?, localPort: Int) =
                        protect(defaultFactory.createSocket(host, port, localHost, localPort))
                }

                builder.socketFactory(protectedSocketFactory)
                builder.sslSocketFactory(sslContext.socketFactory, trustAll)
            } else {
                builder.sslSocketFactory(sslContext.socketFactory, trustAll)
                Log.w(TAG, "Building OkHttpClient WITHOUT protect (simulator mode)")
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

        // ★ 确保始终传入 vpnService，否则拿到无 protect 的 client
        val client = getOrCreateClient(cfg, vpnService)
        val url = buildWsUrl()
        val req = Request.Builder()
            .url(url)
            .header("Host", cfg.wsHost.ifBlank { cfg.server })
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
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

            override fun onMessage(webSocket: WebSocket, bytes: okio.ByteString) {
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
                val isNormal = msg.contains("Socket is closed", true)
                        || msg.contains("Socket closed", true)
                        || msg.contains("Connection reset", true)
                if (!closed.get() && !isNormal) {
                    Log.e(TAG, "✗ WS failure: ${t.javaClass.simpleName}: $msg")
                    // ★ 路由环路时通常报 SocketTimeoutException 或 ConnectException
                    // 如果是真机上看到这个错误，大概率就是 protect 未生效
                    if (msg.contains("timeout", true) || msg.contains("refused", true)) {
                        Log.e(TAG, "  → Possible routing loop! Check vpnService.protect()")
                    }
                }
                inQueue.offer(END_MARKER)
                deliver(false)
            }
        })
    }

    private fun buildWsUrl(): HttpUrl {
        val scheme = if (cfg.security == "tls" || cfg.port == 443) "https" else "http"
        val builder = HttpUrl.Builder()
            .scheme(scheme)
            .host(cfg.server)
            .port(cfg.port)
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
        } else {
            Log.d(TAG, "→ header only (${header.size}B)")
            header
        }
        webSocket.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed.get()) return
        val myWs = wsRef.get() ?: run { Log.e(TAG, "relay: ws is null"); return }

        var respSkipped = false
        var respHdrSize = -1
        var respBuf = ByteArray(0)
        val wsToLocalDone = AtomicBoolean(false)
        val localToWsDone = AtomicBoolean(false)
        val relayDone = AtomicBoolean(false)

        // ── WS → Local（下行）────────────────────────────────────────────────
        val t1 = Thread({
            try {
                while (!closed.get()) {
                    val chunk = inQueue.poll(120, TimeUnit.SECONDS)
                    if (chunk == null) { Log.d(TAG, "WS→local: 120s idle"); break }
                    if (chunk === END_MARKER) { Log.d(TAG, "WS→local: END"); break }

                    val payload: ByteArray? = if (respSkipped) {
                        chunk
                    } else {
                        respBuf = respBuf + chunk
                        if (respBuf.size < 2) continue
                        if (respHdrSize == -1) respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                        if (respBuf.size < respHdrSize) continue
                        respSkipped = true
                        val p = if (respBuf.size > respHdrSize) respBuf.copyOfRange(respHdrSize, respBuf.size) else null
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

        // ── Local → WS（上行）────────────────────────────────────────────────
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

                    // buf.toByteString(0, n) 避免先 copyOf 再转换的双重拷贝
                    val bs: ByteString = if (!headerSent.get()) {
                        val hdr = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                        headerSent.set(true)
                        (hdr + buf.copyOf(n)).toByteString()
                    } else {
                        buf.toByteString(0, n)
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