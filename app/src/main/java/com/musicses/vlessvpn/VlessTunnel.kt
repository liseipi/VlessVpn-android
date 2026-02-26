package com.musicses.vlessvpn

import android.net.VpnService  // ← 添加这个 import
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

class VlessTunnel(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null  // ← VpnService 引用用于 protect
) {
    private var ws: WebSocket? = null
    private val inQueue = LinkedBlockingQueue<ByteArray?>()
    private var firstMsg = true

    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
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
                ws = webSocket
                Log.i(TAG, "✓ WebSocket opened to ${cfg.server}:${cfg.port}")

                val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                val firstPkt = if (earlyData != null && earlyData.isNotEmpty())
                    header + earlyData else header
                webSocket.send(firstPkt.toByteString())
                if (!resultSent) { resultSent = true; onResult(true) }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                inQueue.put(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                inQueue.put(text.toByteArray(Charsets.UTF_8))
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                inQueue.put(null)
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closed: $code $reason")
                inQueue.put(null)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "✗ WebSocket failure: ${t.message}")
                inQueue.put(null)
                if (!resultSent) { resultSent = true; onResult(false) }
            }
        })
    }

    fun relay(localIn: InputStream, localOut: OutputStream) {
        val t1 = Thread {
            try {
                while (true) {
                    val chunk = inQueue.poll(30, TimeUnit.SECONDS) ?: break
                    val payload = if (firstMsg) {
                        firstMsg = false
                        VlessProtocol.stripResponseHeader(chunk)
                    } else chunk
                    if (payload.isNotEmpty()) localOut.write(payload)
                }
            } catch (e: Exception) {
                Log.d(TAG, "WS→local: ${e.message}")
            } finally {
                runCatching { localOut.close() }
                ws?.cancel()
            }
        }

        val t2 = Thread {
            try {
                val buf = ByteArray(8192)
                while (true) {
                    val n = localIn.read(buf)
                    if (n < 0) break
                    ws?.send(buf.copyOf(n).toByteString())
                }
            } catch (e: Exception) {
                Log.d(TAG, "local→WS: ${e.message}")
            } finally {
                inQueue.put(null)
                ws?.close(1000, null)
            }
        }

        t1.isDaemon = true; t2.isDaemon = true
        t1.start();         t2.start()
        t1.join();          t2.join()
    }

    fun close() {
        ws?.cancel()
        inQueue.put(null)
    }

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0,  TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)

        // ★★★ 关键：添加自定义 SocketFactory 来 protect 所有 socket ★★★
        if (vpnService != null) {
            builder.socketFactory(object : javax.net.SocketFactory() {
                private val defaultFactory = javax.net.SocketFactory.getDefault()

                override fun createSocket(): Socket {
                    val socket = defaultFactory.createSocket()
                    if (vpnService.protect(socket)) {
                        Log.d(TAG, "✓ Socket protected from VPN routing")
                    } else {
                        Log.w(TAG, "⚠ Failed to protect socket")
                    }
                    return socket
                }

                override fun createSocket(host: String, port: Int): Socket {
                    val socket = createSocket()
                    socket.connect(InetSocketAddress(host, port))
                    return socket
                }

                override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket {
                    val socket = createSocket()
                    socket.bind(InetSocketAddress(localHost, localPort))
                    socket.connect(InetSocketAddress(host, port))
                    return socket
                }

                override fun createSocket(host: java.net.InetAddress, port: Int): Socket {
                    val socket = createSocket()
                    socket.connect(InetSocketAddress(host, port))
                    return socket
                }

                override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket {
                    val socket = createSocket()
                    socket.bind(InetSocketAddress(localAddress, localPort))
                    socket.connect(InetSocketAddress(address, port))
                    return socket
                }
            })
        }

        if (!cfg.rejectUnauthorized) {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val sc = SSLContext.getInstance("TLS").also {
                it.init(null, arrayOf(trustAll), SecureRandom())
            }

            val sslSocketFactory = sc.socketFactory

            // ★ 如果有 vpnService，包装 SSLSocketFactory 来 protect SSL sockets
            if (vpnService != null) {
                builder.sslSocketFactory(object : SSLSocketFactory() {
                    override fun getDefaultCipherSuites() = sslSocketFactory.defaultCipherSuites
                    override fun getSupportedCipherSuites() = sslSocketFactory.supportedCipherSuites

                    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
                        if (vpnService.protect(s)) {
                            Log.d(TAG, "✓ SSL socket protected")
                        }
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
        }

        return builder.build()
    }
}