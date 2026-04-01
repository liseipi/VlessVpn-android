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
import kotlin.concurrent.thread

/**
 * 本地 SOCKS5 代理服务器
 * 将 tun2socks 发来的 SOCKS5 请求通过 VLESS+WebSocket 隧道转发
 *
 * 完整还原 client.js 的连接逻辑：
 * - buildVlessHeader()
 * - openTunnel() via WebSocket (HTTP Upgrade)
 * - relay() with VLESS response header parsing
 * - handleSocks5()
 */
class LocalProxyServer(
    private val config: VlessConfig,
    private val listenPort: Int
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

                // 4. 回复成功
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()

                Log.d(TAG, "SOCKS5 -> $host:$port")

                // 5. 建立 VLESS 隧道
                openTunnel { _, tunnelOut, tunnelIn ->
                    val vlessHdr = buildVlessHeader(config.uuid, host, port)
                    tunnelOut.write(vlessHdr)
                    tunnelOut.flush()

                    // 双向中继
                    relay(inp, out, tunnelIn, tunnelOut)
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
        // 正确提取 path+query：从 host:port 之后取第一个 / 及其后面全部内容
        val wsUrl = config.buildWsUrl()
        val afterScheme = wsUrl.substringAfter("://")           // host:port/path?query
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

    /**
     * 将数据封装为 WebSocket 二进制帧（客户端需要 mask）
     */
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
                else -> byteArrayOf(
                    0x82.toByte(), (0x80 or 127).toByte(),
                    0, 0, 0, 0,
                    ((len shr 24) and 0xFF).toByte(), ((len shr 16) and 0xFF).toByte(),
                    ((len shr 8) and 0xFF).toByte(), (len and 0xFF).toByte()
                ) + mask
            }
            val payload = ByteArray(len) { i -> (data[off + i].toInt() xor mask[i % 4].toInt()).toByte() }
            return header + payload
        }
    }

    /**
     * 从 WebSocket 帧中读取数据
     */
    inner class WebSocketInputStream(private val raw: InputStream) : InputStream() {
        private var frameBuffer = ByteArray(0)
        private var framePos = 0

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) == -1) -1 else (b[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (framePos >= frameBuffer.size) {
                frameBuffer = readNextFrame() ?: return -1
                framePos = 0
            }
            val available = frameBuffer.size - framePos
            val toRead = minOf(len, available)
            System.arraycopy(frameBuffer, framePos, b, off, toRead)
            framePos += toRead
            return toRead
        }

        private fun readNextFrame(): ByteArray? {
            while (true) {
                val b0 = raw.read()
                if (b0 == -1) return null
                val b1 = raw.read()
                if (b1 == -1) return null

                val opcode = b0 and 0x0F
                val masked = (b1 and 0x80) != 0
                var payloadLen = (b1 and 0x7F).toLong()

                payloadLen = when (payloadLen.toInt()) {
                    126 -> {
                        val ext = ByteArray(2)
                        readFully(raw, ext)
                        ((ext[0].toLong() and 0xFF) shl 8) or (ext[1].toLong() and 0xFF)
                    }
                    127 -> {
                        val ext = ByteArray(8)
                        readFully(raw, ext)
                        var v = 0L
                        for (i in 0..7) v = (v shl 8) or (ext[i].toLong() and 0xFF)
                        v
                    }
                    else -> payloadLen
                }

                val maskKey = if (masked) ByteArray(4).also { readFully(raw, it) } else null
                val payload = ByteArray(payloadLen.toInt())
                readFully(raw, payload)

                if (maskKey != null) {
                    for (i in payload.indices) payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                }

                // opcode 8 = close, 9 = ping, 10 = pong
                if (opcode == 8) return null
                if (opcode == 9) {  // ping -> send pong
                    // ignore for now
                    continue
                }
                if (payload.isEmpty()) continue
                return payload
            }
        }

        private fun readFully(inp: InputStream, buf: ByteArray) {
            var off = 0
            while (off < buf.size) {
                val n = inp.read(buf, off, buf.size - off)
                if (n == -1) throw IOException("Stream closed")
                off += n
            }
        }
    }

    // ── VLESS 请求头构造 (完全还原 client.js buildVlessHeader) ────────────────

    private fun buildVlessHeader(uuid: String, host: String, port: Int): ByteArray {
        val uid = hexToBytes(uuid.replace("-", ""))

        // 判断地址类型
        val (atype, abuf) = when {
            isIPv4(host) -> {
                val parts = host.split(".").map { it.toInt().toByte() }
                Pair(1.toByte(), parts.toByteArray())
            }
            isIPv6(host) -> {
                Pair(3.toByte(), ipv6ToBytes(host))
            }
            else -> {
                val db = host.toByteArray(Charsets.UTF_8)
                Pair(2.toByte(), byteArrayOf(db.size.toByte()) + db)
            }
        }

        // fixed header: version(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atype(1) = 22
        val fixed = ByteBuffer.allocate(22).apply {
            put(0x00)           // version
            put(uid)            // uuid (16 bytes)
            put(0x00)           // addon length
            put(0x01)           // cmd = TCP
            putShort(port.toShort())  // port
            put(atype)          // address type
        }.array()

        return fixed + abuf
    }

    private fun hexToBytes(hex: String): ByteArray {
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun isIPv4(host: String): Boolean {
        return host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))
    }

    private fun isIPv6(host: String): Boolean {
        return host.contains(":")
    }

    private fun ipv6ToBytes(addr: String): ByteArray {
        val buf = ByteArray(16)
        val groups: List<String>
        if (addr.contains("::")) {
            val parts = addr.split("::")
            val left = if (parts[0].isEmpty()) emptyList() else parts[0].split(":")
            val right = if (parts.size < 2 || parts[1].isEmpty()) emptyList() else parts[1].split(":")
            val mid = List(8 - left.size - right.size) { "0" }
            groups = left + mid + right
        } else {
            groups = addr.split(":")
        }
        groups.forEachIndexed { i, g ->
            val v = g.ifEmpty { "0" }.toInt(16)
            buf[i * 2] = ((v shr 8) and 0xFF).toByte()
            buf[i * 2 + 1] = (v and 0xFF).toByte()
        }
        return buf
    }

    // ── 双向中继 (还原 client.js relay，含 VLESS 响应头跳过) ─────────────────

    private fun relay(
        clientIn: InputStream,
        clientOut: OutputStream,
        tunnelIn: InputStream,
        tunnelOut: OutputStream
    ) {
        // 从隧道到客户端（需先跳过 VLESS 响应头）
        val t2c = thread(name = "relay-t2c") {
            try {
                val accumulator = java.io.ByteArrayOutputStream()
                var respSkipped = false
                var respHdrSize = -1
                val buf = ByteArray(BUFFER_SIZE)

                while (true) {
                    val n = tunnelIn.read(buf)
                    if (n == -1) break

                    if (respSkipped) {
                        clientOut.write(buf, 0, n)
                        clientOut.flush()
                        continue
                    }

                    accumulator.write(buf, 0, n)
                    val respBuf = accumulator.toByteArray()
                    if (respBuf.size < 2) continue

                    if (respHdrSize == -1) {
                        // byte[0]=version, byte[1]=addon_len => 总头长 = 2 + addon_len
                        respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                    }
                    if (respBuf.size < respHdrSize) continue

                    respSkipped = true
                    accumulator.reset()
                    val payload = respBuf.copyOfRange(respHdrSize, respBuf.size)
                    if (payload.isNotEmpty()) {
                        clientOut.write(payload)
                        clientOut.flush()
                    }
                }
            } catch (_: Exception) {}
            // t2c 结束时，关闭 clientOut 通知另一侧
            try { clientOut.close() } catch (_: Exception) {}
        }

        // 从客户端到隧道
        val c2t = thread(name = "relay-c2t") {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (true) {
                    val n = clientIn.read(buf)
                    if (n == -1) break
                    tunnelOut.write(buf, 0, n)
                }
            } catch (_: Exception) {}
            // c2t 结束时，关闭 tunnelOut 通知隧道侧
            try { tunnelOut.close() } catch (_: Exception) {}
        }

        // 等待任意一侧结束，然后关闭两侧让另一侧也退出
        t2c.join()
        c2t.join()
    }

    // ── 工具方法 ──────────────────────────────────────────────────────────────

    private fun readBytes(inp: InputStream, count: Int): ByteArray? {
        val buf = ByteArray(count)
        var off = 0
        while (off < count) {
            val n = inp.read(buf, off, count - off)
            if (n == -1) return null
            off += n
        }
        return buf
    }

    private fun readAtLeast(inp: InputStream, min: Int): ByteArray? {
        val buf = ByteArray(min)
        var off = 0
        while (off < min) {
            val n = inp.read(buf, off, min - off)
            if (n == -1) return null
            off += n
        }
        return buf
    }

    private fun readHttpResponseLine(inp: InputStream): String {
        val sb = StringBuilder()
        var prev = 0
        while (true) {
            val c = inp.read()
            if (c == -1) break
            if (c == '\n'.code && prev == '\r'.code) {
                return sb.dropLast(1).toString()
            }
            sb.append(c.toChar())
            prev = c
        }
        return sb.toString()
    }
}
