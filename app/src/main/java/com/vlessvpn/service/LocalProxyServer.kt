package com.vlessvpn.service

import android.util.Log
import com.vlessvpn.model.VlessConfig
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
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
 * network: 物理网络引用（VPN 建立前从 ConnectivityManager.activeNetwork 获取），
 *          用于创建 socket 并解析 DNS，确保流量不走 VPN，避免路由循环。
 * protectSocket: 由 VpnService.protect() 提供，双重保障。
 */
class LocalProxyServer(
    private val config: VlessConfig,
    private val listenPort: Int,
    private val network: android.net.Network? = null,
    private val protectSocket: ((Socket) -> Unit)? = null
) {
    companion object {
        private const val TAG = "LocalProxy"
        private const val BUFFER_SIZE = 8192
    }

    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    @Volatile private var running = false

    // 忽略证书验证（与 client.js rejectUnauthorized:false 一致）
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

                // 1. 握手：VER + NMETHODS + METHODS
                val ver = inp.read()
                if (ver != 5) return
                val nmethods = inp.read()
                if (nmethods < 0) return
                val methods = ByteArray(nmethods)
                readFully(inp, methods) ?: return

                // 2. 回复：无认证
                out.write(byteArrayOf(0x05, 0x00))
                out.flush()

                // 3. 请求头固定 4 字节：VER CMD RSV ATYP
                val header = ByteArray(4)
                readFully(inp, header) ?: return
                if (header[0] != 0x05.toByte() || header[1] != 0x01.toByte()) {
                    Log.w(TAG, "Unsupported SOCKS5 cmd: ${header[1]}")
                    return
                }

                val atyp = header[3].toInt() and 0xFF

                // 4. 根据 atyp 读取目标地址和端口
                val host: String
                val port: Int

                when (atyp) {
                    0x01 -> { // IPv4
                        val addr = ByteArray(4)
                        readFully(inp, addr) ?: return
                        host = InetAddress.getByAddress(addr).hostAddress ?: return
                        val portBytes = ByteArray(2)
                        readFully(inp, portBytes) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    0x03 -> { // Domain
                        val lenByte = inp.read()
                        if (lenByte < 0) return
                        val domainBytes = ByteArray(lenByte)
                        readFully(inp, domainBytes) ?: return
                        host = String(domainBytes)
                        val portBytes = ByteArray(2)
                        readFully(inp, portBytes) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    0x04 -> { // IPv6
                        val addr = ByteArray(16)
                        readFully(inp, addr) ?: return
                        host = InetAddress.getByAddress(addr).hostAddress ?: return
                        val portBytes = ByteArray(2)
                        readFully(inp, portBytes) ?: return
                        port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    }
                    else -> {
                        Log.w(TAG, "Unsupported ATYP: $atyp")
                        return
                    }
                }

                // 5. 回复 SOCKS5 成功
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()

                Log.d(TAG, "SOCKS5 connect -> $host:$port (atyp=$atyp)")

                // 6. 建立 WebSocket 隧道并中继
                try {
                    openTunnel { _, tunnelOut, tunnelIn ->
                        val vlessHdr = buildVlessHeader(host, port)
                        tunnelOut.write(vlessHdr)
                        tunnelOut.flush()
                        relay(client, inp, out, tunnelIn, tunnelOut)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Tunnel error for $host:$port : ${e.message}")
                }

            } catch (e: Exception) {
                Log.e(TAG, "SOCKS5 handler error: ${e.message}")
            }
        }
    }

    // ── 建立 WebSocket 隧道 ───────────────────────────────────────────────────

    private fun openTunnel(block: (socket: Socket, out: OutputStream, inp: InputStream) -> Unit) {
        // ✅ 关键修复：用物理网络的 socketFactory 创建 socket
        // network.socketFactory 创建的 socket 的 DNS 解析也走物理网络，不走 VPN
        // 这样 InetSocketAddress(hostname, port) 的 DNS 解析不会产生路由循环
        val rawSocket: Socket = if (network != null) {
            network.socketFactory.createSocket()
        } else {
            Socket()
        }

        // protect 作为双重保障，防止 network 为 null 时的回退路径
        protectSocket?.invoke(rawSocket)

        // 现在可以安全地用 hostname 连接，DNS 走物理网络
        rawSocket.connect(InetSocketAddress(config.serverHost, config.serverPort), 15000)
        rawSocket.soTimeout = 0

        val socket: Socket = if (config.isTls()) {
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

        val respLine = readHttpResponseLine(inp)
        Log.d(TAG, "WS handshake response: $respLine")
        if (!respLine.contains("101")) {
            socket.close()
            throw IOException("WebSocket upgrade failed: $respLine")
        }
        // 跳过剩余响应头
        while (true) {
            val line = readHttpResponseLine(inp)
            if (line.isEmpty()) break
        }

        Log.d(TAG, "WebSocket tunnel established to ${config.serverHost}:${config.serverPort}")
        try {
            block(socket, WebSocketOutputStream(out), WebSocketInputStream(inp))
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    // ── WebSocket 帧封装 ──────────────────────────────────────────────────────

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

    // ── WebSocket 帧解封 ──────────────────────────────────────────────────────

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
            val n = minOf(len, currentFrame!!.size - pos)
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

                val maskBytes = if (masked) {
                    val m = ByteArray(4)
                    readFully(raw, m)
                    m
                } else null

                val data = ByteArray(payloadLen.toInt())
                readFully(raw, data) ?: return null

                if (maskBytes != null) {
                    for (i in data.indices) data[i] = (data[i].toInt() xor maskBytes[i % 4].toInt()).toByte()
                }

                return when (opcode) {
                    0x00, 0x01, 0x02 -> data  // continuation, text, binary
                    0x08 -> null               // close
                    else -> continue           // ping/pong，忽略继续读
                }
            }
        }
    }

    // ── VLESS 协议头（对齐 client.js buildVlessHeader）────────────────────────

    private fun buildVlessHeader(host: String, port: Int): ByteArray {
        val uuidBytes = config.uuid.replace("-", "")
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // 判断地址类型，与 client.js 逻辑完全一致：
        // IPv4 → atype=1, IPv6 → atype=3(16字节), domain → atype=2
        return try {
            val addr = InetAddress.getByName(host)
            val addrBytes = addr.address
            val atype: Byte = if (addrBytes.size == 4) 0x01 else 0x03
            // fixed: version(1) + uuid(16) + addonLen(1) + cmd(1) + port(2) + atype(1) = 22
            val buf = ByteBuffer.allocate(22 + addrBytes.size)
            buf.put(0x00)        // version
            buf.put(uuidBytes)   // uuid
            buf.put(0x00)        // addon length
            buf.put(0x01)        // command: connect
            buf.putShort(port.toShort())
            buf.put(atype)
            buf.put(addrBytes)
            buf.array()
        } catch (e: Exception) {
            // domain
            val hostBytes = host.toByteArray(Charsets.UTF_8)
            val buf = ByteBuffer.allocate(22 + 1 + hostBytes.size)
            buf.put(0x00)        // version
            buf.put(uuidBytes)   // uuid
            buf.put(0x00)        // addon length
            buf.put(0x01)        // command: connect
            buf.putShort(port.toShort())
            buf.put(0x02)        // atype: domain
            buf.put(hostBytes.size.toByte())
            buf.put(hostBytes)
            buf.array()
        }
    }

    // ── 双向中继（对齐 client.js relay()）───────────────────────────────────

    private fun relay(
        client: Socket,
        clientIn: InputStream, clientOut: OutputStream,
        tunnelIn: InputStream, tunnelOut: OutputStream
    ) {
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
                // VLESS 响应头解析（对齐 client.js relay() onMsg 逻辑）：
                // byte[0]=version, byte[1]=addon_len, 总头长 = 2 + addon_len
                var respBuf = ByteArray(0)
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

                    respBuf = respBuf + buf.copyOf(n)
                    if (respBuf.size < 2) continue

                    if (respHdrSize == -1) {
                        respHdrSize = 2 + (respBuf[1].toInt() and 0xFF)
                    }
                    if (respBuf.size < respHdrSize) continue

                    respSkipped = true
                    val payload = respBuf.drop(respHdrSize).toByteArray()
                    if (payload.isNotEmpty()) {
                        clientOut.write(payload)
                        clientOut.flush()
                    }
                }
            } catch (_: Exception) {}
            finally { try { client.close() } catch (_: Exception) {} }
        }

        t1.join()
        t2.join()
    }

    // ── Utils ────────────────────────────────────────────────────────────────

    private fun readFully(inp: InputStream, buf: ByteArray): ByteArray? {
        var read = 0
        while (read < buf.size) {
            val r = inp.read(buf, read, buf.size - read)
            if (r == -1) return null
            read += r
        }
        return buf
    }

    private fun readHttpResponseLine(inp: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b == -1 || b == '\n'.code) break
            if (b == '\r'.code) continue
            sb.append(b.toChar())
        }
        return sb.toString()
    }
}