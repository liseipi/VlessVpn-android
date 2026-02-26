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
 * ★ 关键修复：
 * 1. 使用独立的状态标记避免竞态条件
 * 2. 在 relay() 中处理响应头（不在 onMessage 中）
 * 3. 增加详细的写入日志
 */
class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null
) {
    private var ws: WebSocket? = null
    private val inQueue = LinkedBlockingQueue<ByteArray>(1000)
    @Volatile private var closed = false
    @Volatile private var headerSent = false

    private val END_MARKER = ByteArray(0)

    // 保存连接参数
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
                    val data = bytes.toByteArray()

                    // ★ 只记录日志，不修改 firstResponseProcessed
                    // 响应头处理在 relay() 方法中进行
                    Log.d(TAG, "← Received ${data.size} bytes from server")

                    if (!inQueue.offer(data, 100, TimeUnit.MILLISECONDS)) {
                        Log.w(TAG, "Queue full, dropping ${data.size} bytes")
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (!closed) {
                    val bytes = text.toByteArray(Charsets.UTF_8)
                    if (bytes.isNotEmpty()) {
                        Log.d(TAG, "← Received text message (${bytes.size} bytes)")
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
                Log.e(TAG, "✗ WebSocket failure: ${t.javaClass.simpleName}: ${t.message}")
                if (response != null) {
                    Log.e(TAG, "  Response: ${response.code} ${response.message}")
                }
                inQueue.offer(END_MARKER)

                if (!resultSent) {
                    resultSent = true
                    onResult(false)
                }
            }
        })
    }

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
            Log.d(TAG, "Sending header only (${header.size}B)")
            header
        }

        ws?.send(packet.toByteString())
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        if (closed) {
            Log.w(TAG, "Tunnel closed")
            return
        }

        // ★ 在 relay 中处理响应头，避免竞态条件
        var firstResponseProcessed = false

        // ★ 从服务器接收数据 → 写入本地
        val t1 = Thread {
            try {
                while (!closed) {
                    val chunk = inQueue.poll(30, TimeUnit.SECONDS)
                    if (chunk == null) {
                        Log.w(TAG, "WS→local: timeout (30s), closing")
                        break
                    }
                    if (chunk === END_MARKER) {
                        Log.d(TAG, "WS→local: received END_MARKER")
                        break
                    }

                    // ★ 关键修复：在这里处理响应头
                    val payload = if (!firstResponseProcessed && chunk.size >= 2) {
                        firstResponseProcessed = true

                        val version = chunk[0].toInt() and 0xFF
                        val addonLen = chunk[1].toInt() and 0xFF
                        val headerLen = 2 + addonLen

                        Log.d(TAG, "✓ Processing VLESS response header:")
                        Log.d(TAG, "   Version: 0x${"%02x".format(version)}")
                        Log.d(TAG, "   Addon length: $addonLen")
                        Log.d(TAG, "   Header length: $headerLen bytes")
                        Log.d(TAG, "   Total chunk: ${chunk.size} bytes")

                        if (version != 0) {
                            Log.w(TAG, "   ⚠ Unexpected version: $version")
                        }

                        if (chunk.size > headerLen) {
                            val payloadSize = chunk.size - headerLen
                            Log.d(TAG, "   → Extracting payload: $payloadSize bytes")
                            chunk.copyOfRange(headerLen, chunk.size)
                        } else {
                            Log.w(TAG, "   ⚠ No payload after header")
                            ByteArray(0)
                        }
                    } else {
                        // 后续数据包直接使用
                        chunk
                    }

                    if (payload.isNotEmpty()) {
                        try {
                            Log.d(TAG, "→ Writing ${payload.size} bytes to local")
                            localOut.write(payload)
                            localOut.flush()
                            Log.d(TAG, "✓ Successfully wrote ${payload.size} bytes")
                        } catch (e: Exception) {
                            Log.e(TAG, "✗ Write to local failed: ${e.javaClass.simpleName}: ${e.message}")
                            throw e
                        }
                    } else {
                        Log.d(TAG, "⊘ Skipping empty payload")
                    }
                }
            } catch (e: Exception) {
                if (!closed) {
                    Log.e(TAG, "WS→local error: ${e.javaClass.simpleName}: ${e.message}")
                }
            } finally {
                Log.d(TAG, "WS→local thread ending")
                runCatching { localOut.close() }
                ws?.cancel()
            }
        }

        // ★ 从本地读取数据 → 发送到服务器
        val t2 = Thread {
            try {
                val buf = ByteArray(8192)
                var totalSent = 0

                while (!closed) {
                    val n = localIn.read(buf)
                    if (n < 0) {
                        Log.d(TAG, "local→WS: EOF reached")
                        break
                    }

                    val data = buf.copyOf(n)

                    if (!headerSent) {
                        Log.d(TAG, "First data from local (${data.size}B), sending with header")
                        sendVlessHeader(data)
                    } else {
                        ws?.send(data.toByteString())
                    }

                    totalSent += n
                    if (totalSent % 10240 == 0) {
                        Log.d(TAG, "local→WS: sent ${totalSent / 1024}KB")
                    }
                }

                Log.d(TAG, "local→WS: finished (total: ${totalSent / 1024}KB)")
            } catch (e: Exception) {
                if (!closed) {
                    Log.e(TAG, "local→WS error: ${e.javaClass.simpleName}: ${e.message}")
                }
            } finally {
                if (!headerSent) {
                    Log.w(TAG, "No data sent, sending header only")
                    sendVlessHeader()
                }

                Log.d(TAG, "local→WS thread ending")
                inQueue.offer(END_MARKER)
                ws?.close(1000, null)
            }
        }

        t1.isDaemon = true
        t2.isDaemon = true
        t1.start()
        t2.start()

        Log.d(TAG, "Relay threads started")

        t1.join()
        t2.join()

        Log.d(TAG, "Relay threads completed")
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
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .pingInterval(20, TimeUnit.SECONDS)

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