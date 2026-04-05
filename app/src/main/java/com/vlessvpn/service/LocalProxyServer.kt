package com.vlessvpn.service

import android.util.Log
import com.vlessvpn.model.VlessConfig
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
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
 *
 * preResolvedServerIp: VPN 启动前由 VlessVpnService 解析好的服务器 IPv4 地址字符串。
 *   传入后直接用 IP 连接，完全跳过 DNS，避免 VPN 建立后 DNS 死锁。
 */
class LocalProxyServer(
    private val config: VlessConfig,
    private val listenPort: Int,
    private val network: android.net.Network? = null,
    private val protectSocket: ((Socket) -> Unit)? = null,
    preResolvedServerIp: String? = null   // ✅ 新增：外部预解析的 IPv4 地址
) {
    companion object {
        private const val TAG = "LocalProxy"
        private const val BUFFER_SIZE = 8192
    }

    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    @Volatile private var running = false

    // ✅ 直接用外部传入的 IP 初始化缓存，后续所有连接都走这个 IP，不再触发任何 DNS
    @Volatile private var cachedServerAddress: InetAddress? =
        preResolvedServerIp?.let {
            try { InetAddress.getByName(it) } catch (_: Exception) { null }
        }

    private val sslContext: SSLContext by lazy {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        SSLContext.getInstance("TLS").also { it.init(null, trustAll, java.security.SecureRandom()) }
    }

    /**
     * 获取服务器地址，优先使用缓存（外部预解析的 IPv4）。
     * 如果缓存为空（兜底情况），通过物理网络解析并强制取 IPv4。
     */
    private fun getServerAddress(): InetAddress {
        cachedServerAddress?.let { return it }

        // 兜底：通过物理网络解析，强制只取 IPv4
        val addresses: Array<InetAddress> = try {
            if (network != null) {
                network.getAllByName(config.serverHost)
            } else {
                InetAddress.getAllByName(config.serverHost)
            }
        } catch (e: Exception) {
            throw IOException("Cannot resolve ${config.serverHost}: ${e.message}", e)
        }

        // ✅ 强制优先取 IPv4，避免拿到 IPv6 地址导致 IPv4 socket 连接失败
        val addr = addresses.filterIsInstance<Inet4Address>().firstOrNull()
            ?: addresses.firstOrNull()
            ?: throw IOException("No address resolved for ${config.serverHost}")

        Log.i(TAG, "Fallback resolved ${config.serverHost} -> ${addr.hostAddress}")
        cachedServerAddress = addr
        return addr
    }

    fun start() {
        running = true

        if (cachedServerAddress != null) {
            Log.i(TAG, "Using pre-resolved server IP: ${cachedServerAddress!!.hostAddress}")
        } else {
            // 没有预解析结果，后台异步尝试（此时 VPN 可能还没建立）
            thread(name = "proxy-pre-resolve") {
                Thread.sleep(100)
                try { getServerAddress() } catch (e: Exception) {
                    Log.w(TAG, "Pre-resolution failed: ${e.message}")
                }
            }
        }

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
        cachedServerAddress = null
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

                val ver = inp.read()
                if (ver != 5) return
                val nmethods = inp.read()
                if (nmethods < 0) return
                val methods = ByteArray(nmethods)
                readFully(inp, methods) ?: return

                out.write(byteArrayOf(0x05, 0x00))
                out.flush()

                val header = ByteArray(4)
                readFully(inp, header) ?: return
                if (header[0] != 0x05.toByte() || header[1] != 0x01.toByte()) {
                    Log.w(TAG, "Unsupported SOCKS5 cmd: ${header[1]}")
                    return
                }

                val atyp = header[3].toInt() and 0xFF
                val host: String
                val port: Int

                when (atyp) {
                    0x01 -> {
                        val addr = ByteArray(4)
                        readFully(inp, addr) ?: return
                        host = InetAddress.getByAddress(addr).hostAddress ?: return
                        val pb = ByteArray(2); readFully(inp, pb) ?: return
                        port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)
                    }
                    0x03 -> {
                        val len = inp.read(); if (len < 0) return
                        val db = ByteArray(len); readFully(inp, db) ?: return
                        host = String(db)
                        val pb = ByteArray(2); readFully(inp, pb) ?: return
                        port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)
                    }
                    0x04 -> {
                        val addr = ByteArray(16)
                        readFully(inp, addr) ?: return
                        host = InetAddress.getByAddress(addr).hostAddress ?: return
                        val pb = ByteArray(2); readFully(inp, pb) ?: return
                        port = ((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF)
                    }
                    else -> { Log.w(TAG, "Unsupported ATYP: $atyp"); return }
                }

                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()

                Log.d(TAG, "SOCKS5 connect -> $host:$port (atyp=$atyp)")

                try {
                    openTunnel { _, tunnelOut, tunnelIn ->
                        val vlessHdr = buildVlessHeader(host, port)
                        tunnelOut.write(vlessHdr)
                        tunnelOut.flush()
                        Log.d(TAG, "Starting relay for $host:$port")
                        relay(client, inp, out, tunnelIn, tunnelOut)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Tunnel error for $host:$port : ${e.javaClass.simpleName}: ${e.message}")
                }

            } catch (e: Exception) {
                Log.e(TAG, "SOCKS5 handler error: ${e.message}")
            }
        }
    }

    // ── 建立 WebSocket 隧道 ───────────────────────────────────────────────────

    private fun openTunnel(block: (socket: Socket, out: OutputStream, inp: InputStream) -> Unit) {
        // ✅ 用物理网络的 socketFactory 创建 socket，确保不走 VPN
        val rawSocket: Socket = if (network != null) {
            network.socketFactory.createSocket()
        } else {
            Socket()
        }

        protectSocket?.invoke(rawSocket)

        // ✅ 用缓存的 IP 直接连接（外部预解析的 IPv4），完全不触发 DNS
        val serverAddr = getServerAddress()
        Log.d(TAG, "Connecting to $serverAddr:${config.serverPort}")
        rawSocket.connect(InetSocketAddress(serverAddr, config.serverPort), 15000)
        rawSocket.soTimeout = 0

        val socket: Socket = if (config.isTls()) {
            val ssl = sslContext.socketFactory.createSocket(
                rawSocket, config.serverHost, config.serverPort, true
            ) as SSLSocket
            ssl.enabledProtocols = ssl.supportedProtocols
            val sniHost = config.sni.takeIf { it.isNotBlank() } ?: config.serverHost
            val sslParams = ssl.sslParameters
            sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(sniHost))
            ssl.sslParameters = sslParams
            ssl.startHandshake()
            ssl
        } else {
            rawSocket
        }

        val out = socket.getOutputStream()
        val inp = socket.getInputStream()

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
            synchronized(raw) { raw.write(frame); raw.flush() }
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
                    b.put(0x82.toByte()); b.put((0x80 or 127).toByte()); b.putLong(len.toLong())
                    b.array() + mask
                }
            }
            val masked = ByteArray(len)
            for (i in 0 until len) masked[i] = (data[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            return header + masked
        }
    }

    // ── WebSocket 帧解封 ──────────────────────────────────────────────────────

    inner class WebSocketInputStream(private val raw: InputStream) : InputStream() {
        private var currentFrame: ByteArray? = null
        private var pos = 0

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) == -1) -1 else b[0].toInt() and 0xFF
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
                val h1 = raw.read(); if (h1 == -1) return null
                val h2 = raw.read(); if (h2 == -1) return null
                val opcode = h1 and 0x0F
                val masked = (h2 and 0x80) != 0
                var payloadLen = (h2 and 0x7F).toLong()
                if (payloadLen == 126L) {
                    payloadLen = ((raw.read() shl 8) or raw.read()).toLong()
                } else if (payloadLen == 127L) {
                    payloadLen = 0
                    for (i in 0 until 8) payloadLen = (payloadLen shl 8) or raw.read().toLong()
                }
                val maskBytes = if (masked) { val m = ByteArray(4); readFully(raw, m); m } else null
                val data = ByteArray(payloadLen.toInt())
                readFully(raw, data) ?: return null
                if (maskBytes != null) {
                    for (i in data.indices) data[i] = (data[i].toInt() xor maskBytes[i % 4].toInt()).toByte()
                }
                return when (opcode) {
                    0x00, 0x01, 0x02 -> data
                    0x08 -> null
                    else -> continue
                }
            }
        }
    }

    // ── VLESS 协议头 ─────────────────────────────────────────────────────────

    private fun buildVlessHeader(host: String, port: Int): ByteArray {
        val uuidBytes = config.uuid.replace("-", "")
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        return try {
            val addr = InetAddress.getByName(host)
            val addrBytes = addr.address
            val atype: Byte = when (addrBytes.size) {
                4  -> 0x01  // IPv4
                16 -> 0x04  // IPv6
                else -> throw IllegalArgumentException("Unknown address type")
            }
            val buf = ByteBuffer.allocate(22 + addrBytes.size)
            buf.put(0x00); buf.put(uuidBytes); buf.put(0x00)
            buf.put(0x01); buf.putShort(port.toShort())
            buf.put(atype); buf.put(addrBytes)
            buf.array()
        } catch (e: Exception) {
            val hostBytes = host.toByteArray(Charsets.UTF_8)
            val buf = ByteBuffer.allocate(22 + 1 + hostBytes.size)
            buf.put(0x00); buf.put(uuidBytes); buf.put(0x00)
            buf.put(0x01); buf.putShort(port.toShort())
            buf.put(0x02); buf.put(hostBytes.size.toByte()); buf.put(hostBytes)
            buf.array()
        }
    }

    // ── 双向中继 ─────────────────────────────────────────────────────────────

    private fun relay(
        client: Socket,
        clientIn: InputStream, clientOut: OutputStream,
        tunnelIn: InputStream, tunnelOut: OutputStream
    ) {
        val t1 = thread(name = "relay-up") {
            try {
                val buf = ByteArray(BUFFER_SIZE)
                while (true) {
                    val n = clientIn.read(buf); if (n == -1) break
                    tunnelOut.write(buf, 0, n)
                }
            } catch (_: Exception) {}
            finally { try { client.close() } catch (_: Exception) {} }
        }

        val t2 = thread(name = "relay-down") {
            try {
                var respSkipped = false
                var respHdrSize = -1
                val headerAccumulator = ByteArrayOutputStream(64)
                val buf = ByteArray(BUFFER_SIZE)

                while (true) {
                    val n = tunnelIn.read(buf); if (n == -1) break

                    if (respSkipped) {
                        clientOut.write(buf, 0, n); clientOut.flush(); continue
                    }

                    headerAccumulator.write(buf, 0, n)
                    val acc = headerAccumulator.toByteArray()
                    if (acc.size < 2) continue

                    if (respHdrSize == -1) {
                        respHdrSize = 2 + (acc[1].toInt() and 0xFF)
                        Log.d(TAG, "VLESS resp: version=${acc[0]}, addon=${acc[1].toInt() and 0xFF}, skip=$respHdrSize")
                    }
                    if (acc.size < respHdrSize) continue

                    respSkipped = true
                    val payload = acc.copyOfRange(respHdrSize, acc.size)
                    if (payload.isNotEmpty()) { clientOut.write(payload); clientOut.flush() }
                }
            } catch (_: Exception) {}
            finally { try { client.close() } catch (_: Exception) {} }
        }

        t1.join(); t2.join()
    }

    // ── Utils ─────────────────────────────────────────────────────────────────

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
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }
}