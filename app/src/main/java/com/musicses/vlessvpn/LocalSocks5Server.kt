package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
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
        4, 256, 60L, TimeUnit.SECONDS, LinkedBlockingQueue(128)
    ).also { it.prestartCoreThread() }

    private lateinit var srv: ServerSocket

    private val connectionCount = AtomicInteger(0)
    private val activeTunnels = ConcurrentHashMap.newKeySet<VlessTunnel>()

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
        activeTunnels.forEach { it.close() }
        activeTunnels.clear()
        pool.shutdownNow()
        pool.awaitTermination(3, TimeUnit.SECONDS)
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = srv.accept()
                val id = connectionCount.incrementAndGet()
                try {
                    pool.submit { handleClient(client, id) }
                } catch (e: RejectedExecutionException) {
                    Log.w(TAG, "[$id] Pool full, dropping connection: ${e.message}")
                    runCatching { client.close() }
                }
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
        activeTunnels.add(tunnel)
        try {
            var connected = false
            val latch = CountDownLatch(1)
            tunnel.connect(destHost, destPort, earlyData) { ok -> connected = ok; latch.countDown() }

            if (!latch.await(30, TimeUnit.SECONDS)) {
                Log.e(TAG, "[$connId] Tunnel timeout"); tunnel.close(); return
            }
            if (!connected) { Log.e(TAG, "[$connId] Tunnel failed"); tunnel.close(); return }

            Log.i(TAG, "[$connId] ✓ Tunnel ready, relaying $destHost:$destPort")

            // ── 流量统计包装流（增量模式）────────────────────────────────────────
            val countingIn = object : InputStream() {
                override fun read() = inp.read().also { if (it >= 0) onTransfer(0L, 1L) }
                override fun read(b: ByteArray, off: Int, len: Int) =
                    inp.read(b, off, len).also { n -> if (n > 0) onTransfer(0L, n.toLong()) }
                override fun available() = inp.available()
                override fun close() = inp.close()
            }

            val countingOut = object : java.io.OutputStream() {
                override fun write(b: Int) { out.write(b); onTransfer(1L, 0L) }
                override fun write(b: ByteArray, off: Int, len: Int) {
                    out.write(b, off, len); onTransfer(len.toLong(), 0L)
                }
                override fun flush() = out.flush()
                override fun close() = out.close()
            }

            tunnel.relay(countingIn, countingOut)
        } finally {
            activeTunnels.remove(tunnel)
        }
    }

    // ── UDP ASSOCIATE ─────────────────────────────────────────────────────────

    private fun handleUdpAssociate(
        controlSock: Socket,
        out: java.io.OutputStream,
        connId: Int
    ) {
        Log.i(TAG, "[$connId] UDP ASSOCIATE request")

        val udpSock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val udpPort = udpSock.localPort
        Log.i(TAG, "[$connId] UDP relay listening on 127.0.0.1:$udpPort")

        val p = (udpPort shr 8).toByte()
        val q = (udpPort and 0xFF).toByte()
        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, p, q))
        out.flush()

        val udpThread = Thread({
            val buf = ByteArray(4096)
            udpSock.soTimeout = 1000
            while (running && !controlSock.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    udpSock.receive(pkt)
                    val data = buf.copyOfRange(pkt.offset, pkt.offset + pkt.length)
                    try {
                        pool.submit { relayUdpPacket(connId, pkt, data, udpSock) }
                    } catch (e: RejectedExecutionException) {
                        Log.w(TAG, "[$connId] Pool full, dropping UDP packet")
                    }
                } catch (_: java.net.SocketTimeoutException) {
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

        try {
            controlSock.soTimeout = 0
            val ctrlInp = controlSock.getInputStream()
            while (!controlSock.isClosed && running) {
                if (ctrlInp.read() == -1) break
            }
        } catch (_: Exception) {}

        udpSock.close()
    }

    private fun relayUdpPacket(
        connId: Int,
        pkt: DatagramPacket,
        rawData: ByteArray,
        udpSock: DatagramSocket
    ) {
        if (rawData.size < 10) return

        val frag = rawData[2].toInt() and 0xFF
        if (frag != 0) return

        val atyp = rawData[3].toInt() and 0xFF
        val (dstHost, dstPort, dataOffset) = try {
            when (atyp) {
                0x01 -> {
                    val ip = InetAddress.getByAddress(rawData.copyOfRange(4, 8)).hostAddress!!
                    val port = ((rawData[8].toInt() and 0xFF) shl 8) or (rawData[9].toInt() and 0xFF)
                    Triple(ip, port, 10)
                }
                0x03 -> {
                    val len = rawData[4].toInt() and 0xFF
                    val host = String(rawData, 5, len)
                    val port = ((rawData[5 + len].toInt() and 0xFF) shl 8) or (rawData[6 + len].toInt() and 0xFF)
                    Triple(host, port, 7 + len)
                }
                0x04 -> {
                    val ip = InetAddress.getByAddress(rawData.copyOfRange(4, 20)).hostAddress!!
                    val port = ((rawData[20].toInt() and 0xFF) shl 8) or (rawData[21].toInt() and 0xFF)
                    Triple(ip, port, 22)
                }
                else -> return
            }
        } catch (e: Exception) { return }

        val payload = rawData.copyOfRange(dataOffset, rawData.size)
        Log.d(TAG, "[$connId] UDP pkt → $dstHost:$dstPort (${payload.size}B)")

        val isDns = dstPort == 53
        val tcpPayload = if (isDns) {
            val len = payload.size
            byteArrayOf((len shr 8).toByte(), (len and 0xFF).toByte()) + payload
        } else {
            payload
        }

        try {
            val tunnel = VlessTunnel(cfg, vpnService)
            activeTunnels.add(tunnel)
            try {
                var connected = false
                val latch = CountDownLatch(1)
                tunnel.connect(dstHost, dstPort, tcpPayload) { ok -> connected = ok; latch.countDown() }

                if (!latch.await(10, TimeUnit.SECONDS) || !connected) {
                    tunnel.close(); return
                }

                val responseBytes = readTunnelResponse(tunnel, isDns)
                // readTunnelResponse closes the tunnel in its finally block.

                if (responseBytes == null || responseBytes.isEmpty()) return
                Log.d(TAG, "[$connId] UDP pkt ← $dstHost:$dstPort (${responseBytes.size}B)")

            val addrBytes = try {
                InetAddress.getByName(dstHost).address
            } catch (_: Exception) {
                byteArrayOf(8, 8, 8, 8)
            }
            val replyAtyp: Byte = if (addrBytes.size == 4) 0x01 else 0x04
            val header = byteArrayOf(
                0x00, 0x00,
                0x00,
                replyAtyp
            ) + addrBytes + byteArrayOf(
                (dstPort shr 8).toByte(),
                (dstPort and 0xFF).toByte()
            )
            val udpReply = header + responseBytes
            val replyPkt = DatagramPacket(udpReply, udpReply.size, pkt.address, pkt.port)
            try { udpSock.send(replyPkt) } catch (_: Exception) {}
            } finally {
                activeTunnels.remove(tunnel)
            }
        } catch (e: Exception) {
            Log.d(TAG, "[$connId] UDP relay error: ${e.message}")
        }
    }

    private fun readTunnelResponse(tunnel: VlessTunnel, isDns: Boolean): ByteArray? {
        val deadline = System.currentTimeMillis() + 5000
        val baos = java.io.ByteArrayOutputStream()

        return try {
            if (isDns) {
                val chunk = tunnel.inQueue.poll(5, TimeUnit.SECONDS) ?: return null
                if (chunk === VlessTunnel.END_MARKER || chunk.size < 2) return null

                val vlessHeaderLen = 2 + (chunk[1].toInt() and 0xFF)
                val data = if (chunk.size > vlessHeaderLen)
                    chunk.copyOfRange(vlessHeaderLen, chunk.size) else return null

                if (data.size < 2) return null
                val msgLen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
                if (data.size >= 2 + msgLen) {
                    data.copyOfRange(2, 2 + msgLen)
                } else {
                    baos.write(data, 2, data.size - 2)
                    var remaining = msgLen - (data.size - 2)
                    while (remaining > 0 && System.currentTimeMillis() < deadline) {
                        val next = tunnel.inQueue.poll(1, TimeUnit.SECONDS) ?: break
                        if (next === VlessTunnel.END_MARKER) break
                        val take = minOf(next.size, remaining)
                        baos.write(next, 0, take)
                        remaining -= take
                    }
                    baos.toByteArray().takeIf { it.isNotEmpty() }
                }
            } else {
                val chunk = tunnel.inQueue.poll(5, TimeUnit.SECONDS) ?: return null
                if (chunk === VlessTunnel.END_MARKER || chunk.size < 2) return null
                val vlessHeaderLen = 2 + (chunk[1].toInt() and 0xFF)
                if (chunk.size <= vlessHeaderLen) return null
                chunk.copyOfRange(vlessHeaderLen, chunk.size)
            }
        } catch (e: Exception) {
            Log.d(TAG, "readTunnelResponse: ${e.message}")
            null
        } finally {
            tunnel.close()
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