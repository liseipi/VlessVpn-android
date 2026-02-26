package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import okhttp3.*
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
import javax.net.ssl.*

private const val TAG = "VlessTunnel"

/**
 * VLESS over WebSocket 隧道
 *
 * ★ 关键修复：不在 WebSocket open 时立即发送 VLESS 头
 * 而是等到有实际数据时，把 VLESS头 + 第一批数据 合并发送
 * 这样避免服务器因为只收到协议头而关闭连接
 */
class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private var ws: WebSocket? = null
    private val inQueue = LinkedBlockingQueue<ByteArray>(1000)
    private var firstMsg = true
    @Volatile private var closed = false
    @Volatile private var headerSent = false  // ← 标记是否已发送协议头

    private val END_MARKER = ByteArray(0)

    // 保存连接参数，用于延迟发送协议头
    private var destHost: String = ""
    private var destPort: Int = 0

    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        if (closed) {
            Log.w(TAG, "Tunnel already closed")
            onResult(false)
            return
        }

        // 保存目标信息
        this.destHost = destHost
        this.destPort = destPort

        val client = buildClient()

        val req = Request.Builder()
            .url(cfg.wsUrl)
            .header("Host",          cfg.wsHost)
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .header("Pragma",        "no-cache")
            .build()

        var resultSent = false

        client.newWebSocket(req, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (closed) {
                    webSocket.close(1000, "Tunnel closed")
                    return
                }

                ws = webSocket
                Log.i(TAG, "✓ WebSocket opened to ${cfg.server}:${cfg.port}")
                Log.d(TAG, "Target: $destHost:$destPort")

                // ★★★ 关键修复：如果有 early data，立即发送协议头 + 数据
                // 否则等到 relay 开始时再发送
                if (earlyData != null && earlyData.isNotEmpty()) {
                    Log.d(TAG, "Sending VLESS header + early data (${earlyData.size} bytes)")
                    sendVlessHeader(earlyData)
                } else {
                    Log.d(TAG, "No early data, will send header with first packet")
                }

                if (!resultSent) {
                    resultSent = true
                    onResult(true)
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (!closed && bytes.size > 0) {
                    Log.d(TAG, "← Received ${bytes.size} bytes")

                    if (firstMsg) {
                        Log.d(TAG, "First message from server")
                        firstMsg = false
                    }

                    if (!inQueue.offer(bytes.toByteArray(), 100, TimeUnit.MILLISECONDS)) {
                        Log.w(TAG, "Queue full, dropping message")
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed) {
                    val bytes = text.toByteArray(Charsets.UTF_8)
                    if (bytes.isNotEmpty()) {
                        if (!inQueue.offer(bytes, 100, TimeUnit.MILLISECONDS)) {
                            Log.w(TAG, "Queue full, dropping text")
                        }
                    }
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closing: $code $reason")
                inQueue.offer(END_MARKER)
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closed: $code $reason")
                inQueue.offer(END_MARKER)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "✗ WebSocket failure: ${t.message}", t)
                Log.e(TAG, "  Response: ${response?.code} ${response?.message}")
                inQueue.offer(END_MARKER)

                if (!resultSent) {
                    resultSent = true
                    onResult(false)
                }
            }
        })
    }

    /**
     * 发送 VLESS 协议头 + 数据
     * data 可以为空，但建议总是包含一些数据
     */
    private fun sendVlessHeader(data: ByteArray? = null) {
        if (headerSent) {
            Log.w(TAG, "Header already sent")
            return
        }

        headerSent = true

        val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)

        val packet = if (data != null && data.isNotEmpty()) {
            Log.d(TAG, "Sending header (${header.size}B) + data (${data.size}B)")
            header + data
        } else {
            Log.d(TAG, "Sending header only (${header.size}B) - may cause server to close!")
            header
        }

        ws?.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed) {
            Log.w(TAG, "Tunnel closed")
            return
        }

        // ★ 从服务器接收数据 → 写入本地
        val t1 = Thread {
            try {
                while (!closed) {
                    val chunk = inQueue.poll(30, TimeUnit.SECONDS)
                    if (chunk == null || chunk === END_MARKER) {
                        Log.d(TAG, "WS→local: ${if (chunk == null) "timeout" else "closed"}")
                        break
                    }

                    // 第一条消息需要跳过 VLESS 响应头（2字节）
                    val payload = if (firstMsg && chunk.size > 2) {
                        firstMsg = false
                        Log.d(TAG, "Stripping VLESS response header (2 bytes)")
                        chunk.copyOfRange(2, chunk.size)
                    } else {
                        chunk
                    }

                    if (payload.isNotEmpty()) {
                        localOut.write(payload)
                        localOut.flush()
                    }
                }
            } catch (e: Exception) {
                if (!closed) {
                    Log.d(TAG, "WS→local error: ${e.message}")
                }
            } finally {
                runCatching { localOut.close() }
                ws?.cancel()
            }
        }

        // ★ 从本地读取数据 → 发送到服务器
        val t2 = Thread {
            try {
                val buf = ByteArray(8192)
                while (!closed) {
                    val n = localIn.read(buf)
                    if (n < 0) break

                    val data = buf.copyOf(n)

                    // ★★★ 如果协议头还没发送，现在发送（header + 第一批数据）
                    if (!headerSent) {
                        Log.d(TAG, "First data from local (${data.size}B), sending with header")
                        sendVlessHeader(data)
                    } else {
                        // 后续数据直接发送
                        ws?.send(data.toByteString())
                    }
                }
            } catch (e: Exception) {
                if (!closed) {
                    Log.d(TAG, "local→WS error: ${e.message}")
                }
            } finally {
                // 如果到这里协议头还没发送（本地没有发数据），必须发一次
                if (!headerSent) {
                    Log.w(TAG, "No data sent, sending header only")
                    sendVlessHeader()
                }

                inQueue.offer(END_MARKER)
                ws?.close(1000, null)
            }
        }

        t1.isDaemon = true
        t2.isDaemon = true
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    }

    fun close() {
        if (closed) return
        closed = true
        Log.d(TAG, "Closing tunnel")
        ws?.cancel()
        inQueue.clear()
        inQueue.offer(END_MARKER)
    }

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .pingInterval(30, TimeUnit.SECONDS)

        // Socket protect
        if (vpnService != null) {
            builder.socketFactory(object : javax.net.SocketFactory() {
                private val defaultFactory = javax.net.SocketFactory.getDefault()

                override fun createSocket(): Socket {
                    val socket = defaultFactory.createSocket()
                    socket.tcpNoDelay = true
                    socket.keepAlive = true

                    if (!vpnService.protect(socket)) {
                        Log.w(TAG, "Failed to protect socket")
                    } else {
                        Log.d(TAG, "✓ Socket protected")
                    }
                    return socket
                }

                override fun createSocket(host: String, port: Int): Socket {
                    val socket = createSocket()
                    socket.connect(InetSocketAddress(host, port), 10000)
                    return socket
                }

                override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
                    val socket = createSocket()
                    socket.bind(InetSocketAddress(localHost, localPort))
                    socket.connect(InetSocketAddress(host, port), 10000)
                    return socket
                }

                override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
                    val socket = createSocket()
                    socket.connect(InetSocketAddress(host, port), 10000)
                    return socket
                }

                override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
                    val socket = createSocket()
                    socket.bind(InetSocketAddress(localAddress, localPort))
                    socket.connect(InetSocketAddress(address, port), 10000)
                    return socket
                }
            })
        }

        // TLS 配置
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sc = SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(trustAll), SecureRandom())
        }

        val sslSocketFactory = sc.socketFactory

        if (vpnService != null) {
            builder.sslSocketFactory(object : SSLSocketFactory() {
                override fun getDefaultCipherSuites() = sslSocketFactory.defaultCipherSuites
                override fun getSupportedCipherSuites() = sslSocketFactory.supportedCipherSuites

                override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
                    return sslSocketFactory.createSocket(s, host, port, autoClose)
                }

                override fun createSocket(host: String, port: Int): Socket {
                    val socket = sslSocketFactory.createSocket(host, port)
                    vpnService.protect(socket)
                    return socket
                }

                override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
                    val socket = sslSocketFactory.createSocket(host, port, localHost, localPort)
                    vpnService.protect(socket)
                    return socket
                }

                override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
                    val socket = sslSocketFactory.createSocket(host, port)
                    vpnService.protect(socket)
                    return socket
                }

                override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
                    val socket = sslSocketFactory.createSocket(address, port, localAddress, localPort)
                    vpnService.protect(socket)
                    return socket
                }
            }, trustAll)
        } else {
            builder.sslSocketFactory(sslSocketFactory, trustAll)
        }

        builder.hostnameVerifier { _, _ -> true }

        return builder.build()
    }
}