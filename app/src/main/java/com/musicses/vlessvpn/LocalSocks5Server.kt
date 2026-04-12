package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

private const val TAG = "SOCKS5"

class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit = { _, _ -> }
) {
    private val pool = ThreadPoolExecutor(
        4, 256, 60L, TimeUnit.SECONDS, SynchronousQueue()
    ).also { it.prestartCoreThread() }

    private lateinit var srv: ServerSocket

    // ★ 用于接收 tun2socks 的 UDP 包（主要是 DNS）
    private var udpRelay: UdpDnsRelay? = null

    private val connectionCount = AtomicInteger(0)

    @Volatile var port: Int = 0; private set
    @Volatile private var running = false

    fun start(): Int {
        srv = ServerSocket(0, 512, InetAddress.getByName("127.0.0.1"))
        port = srv.localPort
        running = true
        pool.submit { acceptLoop() }
        Log.i(TAG, "SOCKS5 server started on 127.0.0.1:$port")
        return port
    }

    fun stop() {
        if (!running) return
        running = false
        runCatching { srv.close() }
        runCatching { udpRelay?.stop() }
        pool.shutdownNow()
        pool.awaitTermination(3, TimeUnit.SECONDS)
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                val id = connectionCount.incrementAndGet()
                pool.submit { handleClient(client, id) }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "Accept error: ${e.message}")
                break
            }
        }
    }

    private fun handleClient(sock: Socket, connId: Int) {
        sock.tcpNoDelay = true
        try { sock.sendBufferSize = 128 * 1024 } catch (_: Exception) {}
        try { sock.receiveBufferSize = 128 * 1024 } catch (_: Exception) {}
        sock.soTimeout = 30_000

        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // SOCKS5 握手
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) {
                Log.w(TAG, "[$connId] Invalid SOCKS5 greeting"); return
            }
            val nMethods = greeting[1].toInt() and 0xFF
            if (nMethods > 0) inp.readNBytes(nMethods)
            out.write(byteArrayOf(0x05, 0x00)); out.flush()

            // 读取命令
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte()) return
            val cmd = req[1].toInt() and 0xFF

            // 解析目标地址
            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> InetAddress.getByAddress(inp.readNBytes(4)).hostAddress!! to readPort(inp)
                0x03.toByte() -> { val l = inp.read() and 0xFF; String(inp.readNBytes(l)) to readPort(inp) }
                0x04.toByte() -> InetAddress.getByAddress(inp.readNBytes(16)).hostAddress!! to readPort(inp)
                else -> return
            }

            when (cmd) {
                0x01 -> handleConnect(sock, inp, out, connId, destHost, destPort)
                0x03 -> handleUdpAssociate(sock, out, connId)
                else -> {
                    Log.w(TAG, "[$connId] Unsupported SOCKS5 command: $cmd")
                    out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                }
            }
        } catch (e: Exception) {
            if (running) Log.d(TAG, "[$connId] ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }

    // ── CONNECT ───────────────────────────────────────────────────────────────

    private fun handleConnect(
        sock: Socket, inp: InputStream, out: java.io.OutputStream,
        connId: Int, destHost: String, destPort: Int
    ) {
        Log.i(TAG, "[$connId] CONNECT $destHost:$destPort")
        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()

        sock.soTimeout = 0
        val earlyData = collectEarlyDataNonBlocking(inp)
        if (earlyData != null) Log.d(TAG, "[$connId] earlyData: ${earlyData.size}B")

        val tunnel = VlessTunnel(cfg, vpnService)
        var connected = false
        val latch = CountDownLatch(1)
        tunnel.connect(destHost, destPort, earlyData) { ok -> connected = ok; latch.countDown() }

        if (!latch.await(30, TimeUnit.SECONDS)) {
            Log.e(TAG, "[$connId] Tunnel timeout"); tunnel.close(); return
        }
        if (!connected) { Log.e(TAG, "[$connId] Tunnel failed"); tunnel.close(); return }

        Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying $destHost:$destPort")
        tunnel.relay(inp, out)
    }

    // ── UDP ASSOCIATE ─────────────────────────────────────────────────────────
    //
    // tun2socks 发出 UDP ASSOCIATE 是为了转发 DNS UDP 查询。
    // 我们在本地开一个 UDP socket 接收这些包，
    // 然后把每个 DNS 查询通过 VLESS TCP 隧道转发到真实 DNS 服务器（8.8.8.8:53）。
    // DNS 标准支持 TCP 传输，所以这完全有效。

    private fun handleUdpAssociate(
        controlSock: Socket,
        out: java.io.OutputStream,
        connId: Int
    ) {
        Log.i(TAG, "[$connId] UDP ASSOCIATE request")

        // 创建本地 UDP socket
        val udpSock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val udpPort = udpSock.localPort
        Log.i(TAG, "[$connId] UDP relay listening on 127.0.0.1:$udpPort")

        // 回复 UDP ASSOCIATE 成功，告知客户端发包到我们的 UDP socket
        val p = (udpPort shr 8).toByte()
        val q = (udpPort and 0xFF).toByte()
        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, p, q))
        out.flush()

        // 后台线程接收并转发 UDP 包
        val udpThread = Thread({
            val buf = ByteArray(4096)
            udpSock.soTimeout = 1000
            while (running && !controlSock.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    udpSock.receive(pkt)
                    pool.submit { relayUdpPacket(connId, pkt, buf.copyOfRange(pkt.offset, pkt.offset + pkt.length), udpSock) }
                } catch (_: java.net.SocketTimeoutException) {
                    // 继续检查 controlSock
                } catch (e: Exception) {
                    if (running && !controlSock.isClosed) Log.d(TAG, "[$connId] UDP recv: ${e.message}")
                    break
                }
            }
            udpSock.close()
            Log.i(TAG, "[$connId] UDP ASSOCIATE closed")
        }, "udp-assoc-$connId")
        udpThread.isDaemon = true
        udpThread.start()

        // 阻塞等待控制连接关闭（RFC 1928：控制连接关闭时 UDP 关联也应关闭）
        try {
            controlSock.soTimeout = 0
            val ctrlInp = controlSock.getInputStream()
            while (!controlSock.isClosed && running) {
                if (ctrlInp.read() == -1) break
            }
        } catch (_: Exception) {}

        udpSock.close()
    }

    /**
     * 解析 SOCKS5 UDP 封装，把载荷通过 VLESS TCP 隧道转发出去，再把响应回包。
     *
     * SOCKS5 UDP 格式：
     *   +----+------+------+----------+----------+----------+
     *   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     *   +----+------+------+----------+----------+----------+
     *   | 2  |  1   |  1   | Variable |    2     | Variable |
     */
    private fun relayUdpPacket(
        connId: Int,
        pkt: DatagramPacket,
        rawData: ByteArray,
        udpSock: DatagramSocket
    ) {
        if (rawData.size < 10) return

        val frag = rawData[2].toInt() and 0xFF
        if (frag != 0) return  // 不支持分片

        val atyp = rawData[3].toInt() and 0xFF
        val (dstHost, dstPort, dataOffset) = try {
            when (atyp) {
                0x01 -> { // IPv4
                    val ip = InetAddress.getByAddress(rawData.copyOfRange(4, 8)).hostAddress!!
                    val port = ((rawData[8].toInt() and 0xFF) shl 8) or (rawData[9].toInt() and 0xFF)
                    Triple(ip, port, 10)
                }
                0x03 -> { // 域名
                    val len = rawData[4].toInt() and 0xFF
                    val host = String(rawData, 5, len)
                    val port = ((rawData[5 + len].toInt() and 0xFF) shl 8) or (rawData[6 + len].toInt() and 0xFF)
                    Triple(host, port, 7 + len)
                }
                else -> return
            }
        } catch (e: Exception) { return }

        val payload = rawData.copyOfRange(dataOffset, rawData.size)
        Log.d(TAG, "[$connId] UDP pkt → $dstHost:$dstPort (${payload.size}B)")

        // ★ 对于 DNS（port 53）：在 payload 前加 2 字节长度前缀，然后通过 TCP 隧道发送
        //   DNS over TCP 格式 = 2字节消息长度 + DNS报文
        val isDns = dstPort == 53
        val tcpPayload = if (isDns) {
            val len = payload.size
            byteArrayOf((len shr 8).toByte(), (len and 0xFF).toByte()) + payload
        } else {
            payload
        }

        try {
            val tunnel = VlessTunnel(cfg, vpnService)
            var connected = false
            val latch = CountDownLatch(1)
            tunnel.connect(dstHost, dstPort, tcpPayload) { ok -> connected = ok; latch.countDown() }

            if (!latch.await(10, TimeUnit.SECONDS) || !connected) {
                tunnel.close(); return
            }

            // 读取响应
            val responseBytes = readTunnelResponse(tunnel, isDns)
            tunnel.close()

            if (responseBytes == null || responseBytes.isEmpty()) return
            Log.d(TAG, "[$connId] UDP pkt ← $dstHost:$dstPort (${responseBytes.size}B)")

            // 封装 SOCKS5 UDP 回包
            val addrBytes = try {
                InetAddress.getByName(dstHost).address
            } catch (_: Exception) {
                byteArrayOf(8, 8, 8, 8)  // fallback
            }
            val replyAtpy: Byte = if (addrBytes.size == 4) 0x01 else 0x04
            val header = byteArrayOf(
                0x00, 0x00,  // RSV
                0x00,        // FRAG
                replyAtpy
            ) + addrBytes + byteArrayOf(
                (dstPort shr 8).toByte(),
                (dstPort and 0xFF).toByte()
            )
            val udpReply = header + responseBytes
            val replyPkt = DatagramPacket(udpReply, udpReply.size, pkt.address, pkt.port)
            try { udpSock.send(replyPkt) } catch (_: Exception) {}

        } catch (e: Exception) {
            Log.d(TAG, "[$connId] UDP relay error: ${e.message}")
        }
    }

    /**
     * 从 VLESS 隧道读取一次响应数据
     */
    private fun readTunnelResponse(tunnel: VlessTunnel, isDns: Boolean): ByteArray? {
        val pipeIn  = java.io.PipedInputStream(65536)
        val pipeOut = java.io.PipedOutputStream(pipeIn)

        val relayThread = Thread({
            try { tunnel.relay(java.io.ByteArrayInputStream(ByteArray(0)), pipeOut) }
            catch (_: Exception) {}
            finally { runCatching { pipeOut.close() } }
        })
        relayThread.isDaemon = true
        relayThread.start()

        return try {
            val baos = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            val deadline = System.currentTimeMillis() + 5000

            // 对于 DNS over TCP：先读 2 字节长度，再读消息体
            if (isDns) {
                // 等数据到达
                while (pipeIn.available() < 2 && System.currentTimeMillis() < deadline) {
                    Thread.sleep(5)
                }
                if (pipeIn.available() < 2) return null
                val lenBytes = ByteArray(2)
                pipeIn.read(lenBytes)
                val msgLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
                var remaining = msgLen
                while (remaining > 0 && System.currentTimeMillis() < deadline) {
                    val avail = pipeIn.available()
                    if (avail > 0) {
                        val n = pipeIn.read(buf, 0, minOf(avail, remaining, buf.size))
                        if (n > 0) { baos.write(buf, 0, n); remaining -= n }
                    } else Thread.sleep(5)
                }
            } else {
                // 非 DNS：读取所有可用数据
                while (System.currentTimeMillis() < deadline) {
                    val avail = pipeIn.available()
                    if (avail > 0) {
                        val n = pipeIn.read(buf, 0, minOf(avail, buf.size))
                        if (n > 0) baos.write(buf, 0, n)
                    } else {
                        Thread.sleep(20)
                        if (pipeIn.available() == 0 && baos.size() > 0) break
                    }
                }
            }
            baos.toByteArray().takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            Log.d(TAG, "readTunnelResponse: ${e.message}")
            null
        } finally {
            relayThread.interrupt()
        }
    }

    private fun collectEarlyDataNonBlocking(inp: InputStream): ByteArray? {
        val avail = try { inp.available() } catch (_: Exception) { return null }
        if (avail <= 0) return null
        val buf = ByteArray(65536)
        val baos = java.io.ByteArrayOutputStream()
        try {
            var remaining = avail
            while (remaining > 0) {
                val n = inp.read(buf, 0, minOf(remaining, buf.size))
                if (n <= 0) break
                baos.write(buf, 0, n); remaining -= n
                val more = try { inp.available() } catch (_: Exception) { 0 }
                if (more <= 0) break; remaining = more
            }
        } catch (_: Exception) {}
        return if (baos.size() > 0) baos.toByteArray() else null
    }

    private fun readPort(inp: InputStream): Int {
        val b = inp.readNBytes(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }
}