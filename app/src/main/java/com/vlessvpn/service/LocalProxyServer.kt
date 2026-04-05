package com.vlessvpn.service

import android.util.Log
import com.vlessvpn.model.VlessConfig
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * 本地 SOCKS5 代理服务器
 * 将 tun2socks 发来的 SOCKS5 请求通过 VLESS+WebSocket 隧道转发
 *
 * 完整还原 client.js 的连接逻辑：
 * - buildVlessHeader()
 * - openTunnel() via WebSocket (HTTP Upgrade)
 * - relay() with VLESS response header parsing
 * - handleSocks5() with early data collection（与 client.js 修复4对齐）
 *
 * protectSocket: 由 VpnService.protect() 提供，保护连接服务器的 socket 不走 VPN，避免路由循环
 */
class LocalProxyServer(
    private val config: VlessConfig,
    private val listenPort: Int,
    private val protectSocket: ((Socket) -> Unit)? = null
) {
    companion object {
        private const val TAG = "LocalProxy"
        private const val BUFFER_SIZE = 8192
    }

    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    @Volatile private var running = false

    // 创建忽略证书的 SSLContext（与 client.js rejectUnauthorized:false 一致）
    private val sslContext: SSLContext by lazy {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        SSLContext.getInstance("TLS").also { it.init(null, trustAll, java.security.SecureRandom()) }
    }

    fun start() {
        running = true
        thread(name = "proxy-accept") {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress("127.0.0.1", listenPort))
                }
                Log.i(TAG, "SOCKS5 proxy listening on 127.0.0.1:$listenPort")
                Log.i(TAG, "Tunnel target: ${config.buildWsUrl()}")

                while (running) {
                    try {
                        val client = serverSocket!!.accept()
                        executor.submit { handleSocks5(client) }
                    } catch (e: IOException) {
                        if (running) Log.e(TAG, "Accept error: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server error: ${e.message}")
            }
        }
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) {}
        executor.shutdownNow()
        Log.i(TAG, "Proxy stopped")
    }

    // ── SOCKS5 握手 ───────────────────────────────────────────────────────────

    private fun handleSocks5(client: Socket) {
        client.use {
            try {
                val inp = client.getInputStream()
                val out = client.getOutputStream()

                // 1. 读取握手
                val greeting = readBytes(inp, 2) ?: return
                if (greeting[0] != 0x05.toByte()) return
                val nmethods = greeting[1].toInt() and 0xFF
                readBytes(inp, nmethods) ?: return

                // 2. 回复：无认证
                out.write(byteArrayOf(0x05, 0x00))
                out.flush()

                // 3. 读取请求
                val req = readAtLeast(inp, 4) ?: return
                if (req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) return

                val atyp = req[3].toInt() and 0xFF
                val host: String
                val port: Int

                when (atyp) {
                    0x01 -> { // IPv4
                        val addr = readBytes(inp, 4) ?: return
                        host = "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}.${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
                        val portBytes = readBytes(inp, 2) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    0x03 -> { // Domain
                        val lenByte = readBytes(inp, 1) ?: return
                        val len = lenByte[0].toInt() and 0xFF
                        val domainBytes = readBytes(inp, len) ?: return
                        host = String(domainBytes)
                        val portBytes = readBytes(inp, 2) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    0x04 -> { // IPv6
                        val addr = readBytes(inp, 16) ?: return
                        val sb = StringBuilder()
                        for (i in 0 until 8) {
                            if (i > 0) sb.append(":")
                            sb.append(Integer.toHexString(((addr[i*2].toInt() and 0xFF) shl 8) or (addr[i*2+1].toInt() and 0xFF)))
                        }
                        host = sb.toString()
                        val portBytes = readBytes(inp, 2) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    else -> return
                }

                // 4. 回复 SOCKS5 成功
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()

                Log.d(TAG, "SOCKS5 -> $host:$port")

                // 5. 对齐 client.js 修复4：
                //    回复 SOCKS5 成功后立即开始在独立线程收集 early data，
                //    等隧道建立后把 vlessHeader + earlyData 合并成第一个包发送，
                //    避免客户端抢先发送的数据丢失导致连接卡住。
                val earlyData = java.io.ByteArrayOutputStream()
                val earlyLock = Object()
                val earlyDone = AtomicBoolean(false)

                val earlyThread = thread(name = "early-data") {
                    try {
                        val buf = ByteArray(BUFFER_SIZE)
                        client.soTimeout = 100  // 短超时，感知 earlyDone
                        while (!earlyDone.get()) {
                            try {
                                val n = inp.read(buf)
                                if (n == -1) break
                                synchronized(earlyLock) {
                                    if (!earlyDone.get()) earlyData.write(buf, 0, n)
                                }
                            } catch (_: java.net.SocketTimeoutException) {
                                // 正常超时，继续检查 earlyDone
                            }
                        }
                    } catch (_: Exception) {}
                }

                // 6. 建立 WebSocket 隧道
                try {
                    openTunnel { _, tunnelOut, tunnelIn ->
                        // 隧道就绪，停止 early data 收集
                        earlyDone.set(true)
                        earlyThread.join(500)
                        client.soTimeout = 0  // 恢复无超时

                        // 构造第一个包：vlessHeader + earlyData（对齐 client.js firstPkt）
                        val vlessHdr = buildVlessHeader(config.uuid, host, port)
                        val collected = synchronized(earlyLock) { earlyData.toByteArray() }
                        val firstPkt = if (collected.isNotEmpty()) {
                            vlessHdr + collected
                        } else {
                            vlessHdr
                        }
                        tunnelOut.write(firstPkt)
                        tunnelOut.flush()

                        // 双向中继
                        relay(client, inp, out, tunnelIn, tunnelOut)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "SOCKS5 handler error: ${e.message}")
                    earlyDone.set(true)
                    earlyThread.join(500)
                }

            } catch (e: Exception) {
                Log.e(TAG, "SOCKS5 handler error: ${e.message}")
            }
        }
    }

    // ── 建立 WebSocket 隧道 (手动 HTTP Upgrade，与 client.js 完全一致) ─────────

    private fun openTunnel(block: (socket: Socket, out: OutputStream, inp: InputStream) -> Unit) {
        val useTls = config.isTls()
        val rawSocket = Socket()

        // 关键：在 connect 之前调用 protect，让这个 socket 绕过 VPN 路由，避免循环
        protectSocket?.invoke(rawSocket)

        rawSocket.connect(InetSocketAddress(config.serverHost, config.serverPort), 15000)
        rawSocket.soTimeout = 0  // no timeout for relay

        val socket: Socket = if (useTls) {
            val ssl = sslContext.socketFactory.createSocket(
                rawSocket, config.serverHost, config.serverPort, true
            ) as SSLSocket
            ssl.enabledProtocols = ssl.supportedProtocols
            ssl.startHandshake()
            ssl
        } else {
            rawSocket
        }

        val out = socket.getOutputStream()
        val inp = socket.getInputStream()

        // HTTP Upgrade to WebSocket
        val key = android.util.Base64.encodeToString(
            java.security.SecureRandom().generateSeed(16), android.util.Base64.NO_WRAP
        )
        val wsUrl = config.buildWsUrl()
        val afterScheme = wsUrl.substringAfter("://")
        val slashIdx = afterScheme.indexOf('/')
        val pathWithQuery = if (slashIdx >= 0) afterScheme.substring(slashIdx) else "/"

        val request = buildString {
            append("GET $pathWithQuery HTTP/1.1\r\n")
            append("Host: ${config.wsHost}\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: $key\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
            append("Cache-Control: no-cache\r\n")
            append("Pragma: no-cache\r\n")
            append("\r\n")
        }

        out.write(request.toByteArray())
        out.flush()

        // 读取 HTTP 响应头
        val respLine = readHttpResponseLine(inp)
        if (!respLine.contains("101")) {
            socket.close()
            throw IOException("WebSocket upgrade failed: $respLine")
        }
        // 跳过剩余响应头
        while (true) {
            val line = readHttpResponseLine(inp)
            if (line.isEmpty()) break
        }

        Log.d(TAG, "WebSocket tunnel established")
        try {
            block(socket, WebSocketOutputStream(out), WebSocketInputStream(inp))
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    // ── WebSocket 帧封装/解封 ─────────────────────────────────────────────────

    inner class WebSocketOutputStream(private val raw: OutputStream) : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()))
        override fun write(b: ByteArray) = write(b, 0, b.size)
        override fun write(data: ByteArray, off: Int, len: Int) {
            val frame = encodeWsFrame(data, off, len)
            synchronized(raw) {
                raw.write(frame)
                raw.flush()
            }
        }

        private fun encodeWsFrame(data: ByteArray, off: Int, len: Int): ByteArray {
            val mask = ByteArray(4).also { java.security.SecureRandom().nextBytes(it) }
            val header = when {
                len <= 125 -> byteArrayOf(0x82.toByte(), (0x80 or len).toByte()) + mask
                len <= 65535 -> byteArrayOf(
                    0x82.toByte(), (0x80 or 126).toByte(),
                    ((len shr 8) and 0xFF).toByte(), (len and 0xFF).toByte()
                ) + mask
                else -> {
                    val b = ByteBuffer.allocate(10)
                    b.put(0x82.toByte())
                    b.put((0x80 or 127).toByte())
                    b.putLong(len.toLong())
                    b.array() + mask
                }
            }
            val masked = ByteArray(len)
            for (i in 0 until len) {
                masked[i] = (data[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            }
            return header + masked
        }
    }

    inner class WebSocketInputStream(private val raw: InputStream) : InputStream() {
        private var currentFrame: ByteArray? = null
        private var pos = 0

        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n == -1) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (currentFrame == null || pos >= currentFrame!!.size) {
                currentFrame = nextFrame() ?: return -1
                pos = 0
            }
            val n = Math.min(len, currentFrame!!.size - pos)
            System.arraycopy(currentFrame!!, pos, b, off, n)
            pos += n
            return n
        }

        private fun nextFrame(): ByteArray? {
            while (true) {
                val h1 = raw.read()
                if (h1 == -1) return null
                val h2 = raw.read()
                if (h2 == -1) return null

                val opcode = h1 and 0x0F
                val masked = (h2 and 0x80) != 0
                var payloadLen = (h2 and 0x7F).toLong()

                if (payloadLen == 126L) {
                    payloadLen = ((raw.read() shl 8) or raw.read()).toLong()
                } else if (payloadLen == 127L) {
                    payloadLen = 0
                    for (i in 0 until 8) payloadLen = (payloadLen shl 8) or raw.read().toLong()
                }

                val mask = if (masked) {
                    val m = ByteArray(4)
                    raw.read(m)
                    m
                } else null

                val data = ByteArray(payloadLen.toInt())
                var read = 0
                while (read < payloadLen) {
                    val n = raw.read(data, read, payloadLen.toInt() - read)
                    if (n == -1) break
                    read += n
                }

                if (mask != null) {
                    for (i in data.indices) data[i] = (data[i].toInt() xor mask[i % 4].toInt()).toByte()
                }

                if (opcode == 0x02 || opcode == 0x01 || opcode == 0x00) {
                    return data
                } else if (opcode == 0x08) {
                    return null // Close
                }
                // Ignore other opcodes (ping/pong)
            }
        }
    }

    // ── VLESS 协议 & 中继 ──────────────────────────────────────────────────────

    private fun buildVlessHeader(uuid: String, host: String, port: Int): ByteArray {
        val uuidBytes = uuid.replace("-", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val hostBytes = host.toByteArray()
        val header = ByteBuffer.allocate(1 + 16 + 1 + 1 + 1 + hostBytes.size + 2)
        header.put(0x00.toByte()) // Version 0
        header.put(uuidBytes)    // UUID
        header.put(0x00.toByte()) // Addons length 0
        header.put(0x01.toByte()) // Command Connect
        header.put(0x03.toByte()) // Domain type (using domain for simplicity)
        header.put(hostBytes.size.toByte())
        header.put(hostBytes)
        header.putShort(port.toShort())
        return header.array()
    }

    private fun relay(client: Socket, clientIn: InputStream, clientOut: OutputStream, tunnelIn: InputStream, tunnelOut: OutputStream) {
        val t1 = thread(name = "relay-up") {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (true) {
                    val n = clientIn.read(buf)
                    if (n == -1) break
                    tunnelOut.write(buf, 0, n)
                }
            } catch (_: Exception) {}
            finally { try { client.close() } catch (_: Exception) {} }
        }

        val t2 = thread(name = "relay-down") {
            try {
                // VLESS 响应头：1字节版本 + 1字节addons长度(忽略addons)
                val ver = tunnelIn.read()
                if (ver != -1) {
                    val addonLen = tunnelIn.read()
                    if (addonLen > 0) readBytes(tunnelIn, addonLen) // skip addons
                    
                    val buf = ByteArray(BUFFER_SIZE)
                    while (true) {
                        val n = tunnelIn.read(buf)
                        if (n == -1) break
                        clientOut.write(buf, 0, n)
                    }
                }
            } catch (_: Exception) {}
            finally { try { client.close() } catch (_: Exception) {} }
        }

        t1.join()
        t2.join()
    }

    // ── Utils ────────────────────────────────────────────────────────────────

    private fun readBytes(inp: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = inp.read(buf, read, n - read)
            if (r == -1) return null
            read += r
        }
        return buf
    }

    private fun readAtLeast(inp: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(BUFFER_SIZE)
        val r = inp.read(buf, 0, BUFFER_SIZE)
        if (r < n) return null
        return buf.copyOf(r)
    }

    private fun readHttpResponseLine(inp: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b == -1 || b == '\n'.toInt()) break
            if (b == '\r'.toInt()) continue
            sb.append(b.toChar())
        }
        return sb.toString()
    }
}
