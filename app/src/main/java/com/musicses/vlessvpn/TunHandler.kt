package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.*
import java.net.InetAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * ★ 修复版 TunHandler：TUN → SOCKS5 透明代理
 *
 * 工作原理：
 * 1. 从 TUN 读取 IP 数据包
 * 2. 解析 TCP 连接（SYN）
 * 3. 为每个 TCP 流创建到 SOCKS5 的连接
 * 4. 透明转发数据
 * 5. 构造假的 TCP 响应包写回 TUN
 */
class TunHandler(
    private var fd: FileDescriptor?,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = false

    private var totalIn  = 0L
    private var totalOut = 0L

    private lateinit var socksServer: LocalSocks5Server
    private var socksPort: Int = 0

    // TCP 流管理
    private val tcpFlows = ConcurrentHashMap<String, TcpProxy>()

    fun start() {
        running = true

        // 启动 SOCKS5 服务器
        socksServer = LocalSocks5Server(cfg, vpnService) { bytesIn, bytesOut ->
            totalIn  += bytesIn
            totalOut += bytesOut
            onStats(totalIn, totalOut)
        }
        socksPort = socksServer.start()
        Log.i(TAG, "✓ SOCKS5 proxy started on 127.0.0.1:$socksPort")
    }

    fun stop() {
        running = false
        socksServer.stop()

        // 关闭所有 TCP 流
        tcpFlows.values.forEach { it.close() }
        tcpFlows.clear()

        executor.shutdownNow()
        Log.i(TAG, "TunHandler stopped")
    }

    fun getSocksPort(): Int = socksPort

    fun setTunFd(tunFd: FileDescriptor) {
        this.fd = tunFd
        executor.submit { tunReadLoop(tunFd) }
        Log.i(TAG, "TUN fd set, starting packet processing...")
    }

    /**
     * ★ 关键修改：解析 TUN 数据包并转发到 SOCKS5
     */
    private fun tunReadLoop(tunFd: FileDescriptor) {
        val fis = FileInputStream(tunFd)
        val fos = FileOutputStream(tunFd)
        val buf = ByteArray(MTU)

        Log.i(TAG, "========== TUN Read Loop Started ==========")
        Log.i(TAG, "Will forward TCP traffic to SOCKS5: 127.0.0.1:$socksPort")
        Log.i(TAG, "============================================")

        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 20) continue  // 至少需要 IP 头

                val packet = buf.copyOf(n)
                handleIpPacket(packet, fos)
            }
        } catch (e: Exception) {
            if (running) {
                Log.e(TAG, "TUN read error: ${e.message}")
                e.printStackTrace()
            }
        }

        Log.i(TAG, "TUN read loop ended")
    }

    private fun handleIpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        try {
            val bb = ByteBuffer.wrap(packet)

            // 检查 IP 版本
            val version = (bb.get(0).toInt() and 0xFF) ushr 4
            if (version != 4) return  // 只处理 IPv4

            // 检查协议
            val protocol = bb.get(9).toInt() and 0xFF
            if (protocol != 6) return  // 只处理 TCP

            handleTcpPacket(packet, bb, tunOut)

        } catch (e: Exception) {
            // 静默忽略解析错误
        }
    }

    private fun handleTcpPacket(packet: ByteArray, bb: ByteBuffer, tunOut: FileOutputStream) {
        val ihl = (bb.get(0).toInt() and 0x0F) * 4
        if (packet.size < ihl + 20) return

        val srcIp  = formatIp(packet, 12)
        val dstIp  = formatIp(packet, 16)

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)

        val flags = packet[ihl + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0

        val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        // 解析数据
        val dataOffset = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payloadStart = ihl + dataOffset
        val payload = if (packet.size > payloadStart) {
            packet.copyOfRange(payloadStart, packet.size)
        } else {
            ByteArray(0)
        }

        when {
            isSyn && (flags and 0x10) == 0 -> {  // SYN without ACK
                Log.d(TAG, "[$flowKey] New TCP connection (SYN)")
                handleNewConnection(srcIp, srcPort, dstIp, dstPort, packet, ihl, tunOut, flowKey)
            }

            isFin || isRst -> {
                Log.d(TAG, "[$flowKey] Connection closing (${if (isFin) "FIN" else "RST"})")
                tcpFlows.remove(flowKey)?.close()
            }

            payload.isNotEmpty() -> {
                tcpFlows[flowKey]?.sendData(payload)
            }
        }
    }

    /**
     * 处理新的 TCP 连接：连接到本地 SOCKS5
     */
    private fun handleNewConnection(
        srcIp: String, srcPort: Int,
        dstIp: String, dstPort: Int,
        packet: ByteArray, ihl: Int,
        tunOut: FileOutputStream,
        flowKey: String
    ) {
        val clientSeq = seqFromPkt(packet, ihl)

        // 创建 TCP 代理
        val proxy = TcpProxy(
            srcIp, srcPort, dstIp, dstPort,
            clientSeq, socksPort, tunOut
        )

        tcpFlows[flowKey] = proxy
        proxy.start()
    }

    private fun formatIp(pkt: ByteArray, offset: Int) =
        "${pkt[offset].toInt() and 0xFF}.${pkt[offset+1].toInt() and 0xFF}" +
                ".${pkt[offset+2].toInt() and 0xFF}.${pkt[offset+3].toInt() and 0xFF}"

    private fun seqFromPkt(pkt: ByteArray, ihl: Int): Long {
        return ((pkt[ihl+4].toLong() and 0xFF) shl 24) or
                ((pkt[ihl+5].toLong() and 0xFF) shl 16) or
                ((pkt[ihl+6].toLong() and 0xFF) shl 8)  or
                (pkt[ihl+7].toLong()  and 0xFF)
    }
}

/**
 * TCP 透明代理：TUN ↔ SOCKS5
 */
private class TcpProxy(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val clientSeq: Long,
    private val socksPort: Int,
    private val tunOut: FileOutputStream
) {
    private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
    private var clientAck = clientSeq + 1
    private var socksSocket: Socket? = null

    @Volatile private var closed = false

    fun start() {
        Thread {
            try {
                // 1. 发送 SYN-ACK
                writeSynAck()

                // 2. 连接到本地 SOCKS5
                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Connecting to SOCKS5 127.0.0.1:$socksPort")

                val sock = Socket("127.0.0.1", socksPort)
                sock.tcpNoDelay = true
                sock.soTimeout = 30000
                socksSocket = sock

                val socksIn = sock.getInputStream()
                val socksOut = sock.getOutputStream()

                // 3. SOCKS5 握手
                performSocks5Handshake(socksOut, socksIn)

                // 4. 从 SOCKS5 读取响应并写回 TUN
                val readThread = Thread {
                    try {
                        val buf = ByteArray(8192)
                        while (!closed && !sock.isClosed) {
                            val n = socksIn.read(buf)
                            if (n < 0) break

                            val data = buf.copyOf(n)
                            writeDataToTun(data)
                        }
                    } catch (e: Exception) {
                        if (!closed) {
                            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] SOCKS5→TUN error: ${e.message}")
                        }
                    }
                }
                readThread.isDaemon = true
                readThread.start()

                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ Proxy established")

            } catch (e: Exception) {
                Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Proxy error: ${e.message}")
                close()
            }
        }.apply {
            isDaemon = true
            name = "TcpProxy-$srcPort→$dstPort"
        }.start()
    }

    /**
     * 执行 SOCKS5 握手
     */
    private fun performSocks5Handshake(out: OutputStream, inp: InputStream) {
        // 1. 发送认证方法
        out.write(byteArrayOf(0x05, 0x01, 0x00))

        // 2. 读取服务器响应
        val resp1 = ByteArray(2)
        inp.read(resp1)
        if (resp1[0] != 0x05.toByte() || resp1[1] != 0x00.toByte()) {
            throw IOException("SOCKS5 auth failed")
        }

        // 3. 发送 CONNECT 请求
        val request = buildSocks5ConnectRequest(dstIp, dstPort)
        out.write(request)

        // 4. 读取连接响应
        val resp2 = ByteArray(10)
        inp.read(resp2)
        if (resp2[0] != 0x05.toByte() || resp2[1] != 0x00.toByte()) {
            throw IOException("SOCKS5 connect failed: ${resp2[1]}")
        }

        Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ SOCKS5 handshake complete")
    }

    private fun buildSocks5ConnectRequest(host: String, port: Int): ByteArray {
        val isIpv4 = host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))

        return if (isIpv4) {
            // IPv4 地址
            val parts = host.split(".")
            byteArrayOf(
                0x05, 0x01, 0x00, 0x01,  // VER CMD RSV ATYP
                parts[0].toInt().toByte(),
                parts[1].toInt().toByte(),
                parts[2].toInt().toByte(),
                parts[3].toInt().toByte(),
                (port shr 8).toByte(),
                (port and 0xFF).toByte()
            )
        } else {
            // 域名
            val hostBytes = host.toByteArray()
            ByteArray(7 + hostBytes.size).apply {
                this[0] = 0x05  // VER
                this[1] = 0x01  // CMD (CONNECT)
                this[2] = 0x00  // RSV
                this[3] = 0x03  // ATYP (DOMAIN)
                this[4] = hostBytes.size.toByte()
                hostBytes.copyInto(this, 5)
                this[5 + hostBytes.size] = (port shr 8).toByte()
                this[6 + hostBytes.size] = (port and 0xFF).toByte()
            }
        }
    }

    fun sendData(data: ByteArray) {
        if (closed) return
        try {
            socksSocket?.getOutputStream()?.write(data)
        } catch (e: Exception) {
            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Send error: ${e.message}")
            close()
        }
    }

    private fun writeDataToTun(data: ByteArray) {
        if (closed) return

        val packet = buildTcpPacket(
            srcIp   = dstIp,
            srcPort = dstPort,
            dstIp   = srcIp,
            dstPort = srcPort,
            seq     = serverSeq,
            ack     = clientAck,
            flags   = 0x18,  // PSH + ACK
            payload = data
        )

        serverSeq += data.size

        synchronized(tunOut) {
            try {
                tunOut.write(packet)
            } catch (e: Exception) {
                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] TUN write error: ${e.message}")
            }
        }
    }

    private fun writeSynAck() {
        val packet = buildTcpPacket(
            srcIp   = dstIp,
            srcPort = dstPort,
            dstIp   = srcIp,
            dstPort = srcPort,
            seq     = serverSeq,
            ack     = clientSeq + 1,
            flags   = 0x12,  // SYN + ACK
            payload = ByteArray(0)
        )
        serverSeq++

        synchronized(tunOut) {
            runCatching { tunOut.write(packet) }
        }
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { socksSocket?.close() }
    }
}

// ── 构造 TCP 数据包 ───────────────────────────────────────────────────────────

private fun buildTcpPacket(
    srcIp: String, srcPort: Int,
    dstIp: String, dstPort: Int,
    seq: Long, ack: Long,
    flags: Int,
    payload: ByteArray
): ByteArray {
    val ipHdrLen  = 20
    val tcpHdrLen = 20
    val totalLen  = ipHdrLen + tcpHdrLen + payload.size
    val buf = ByteBuffer.allocate(totalLen)

    val srcIpBytes = ipToBytes(srcIp)
    val dstIpBytes = ipToBytes(dstIp)

    // ── IPv4 头 ───────────────────────────────────────────────────────────────
    buf.put(0x45.toByte())
    buf.put(0x00)
    buf.putShort(totalLen.toShort())
    buf.putShort(0)
    buf.putShort(0x4000.toShort())
    buf.put(64)
    buf.put(6)
    buf.putShort(0)
    buf.put(srcIpBytes)
    buf.put(dstIpBytes)

    val ipChecksum = checksum(buf.array(), 0, ipHdrLen)
    buf.putShort(10, ipChecksum.toShort())

    // ── TCP 头 ────────────────────────────────────────────────────────────────
    buf.putShort(srcPort.toShort())
    buf.putShort(dstPort.toShort())
    buf.putInt((seq and 0xFFFFFFFFL).toInt())
    buf.putInt((ack and 0xFFFFFFFFL).toInt())
    buf.put((5 shl 4).toByte())
    buf.put(flags.toByte())
    buf.putShort(65535.toShort())
    buf.putShort(0)
    buf.putShort(0)

    if (payload.isNotEmpty()) buf.put(payload)

    val tcpChecksum = tcpChecksum(srcIpBytes, dstIpBytes, buf.array(), ipHdrLen, tcpHdrLen + payload.size)
    buf.putShort(ipHdrLen + 16, tcpChecksum.toShort())

    return buf.array()
}

private fun ipToBytes(ip: String): ByteArray =
    ip.split(".").map { it.toInt().toByte() }.toByteArray()

private fun checksum(buf: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var i = offset
    while (i < offset + length - 1) {
        sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
        i += 2
    }
    if ((offset + length) % 2 != 0) sum += (buf[offset + length - 1].toInt() and 0xFF) shl 8
    while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
    return sum.inv() and 0xFFFF
}

private fun tcpChecksum(srcIp: ByteArray, dstIp: ByteArray, buf: ByteArray, tcpOffset: Int, tcpLength: Int): Int {
    val pseudo = ByteArray(12 + tcpLength)
    srcIp.copyInto(pseudo, 0)
    dstIp.copyInto(pseudo, 4)
    pseudo[8] = 0
    pseudo[9] = 6
    pseudo[10] = (tcpLength shr 8).toByte()
    pseudo[11] = (tcpLength and 0xFF).toByte()
    buf.copyInto(pseudo, 12, tcpOffset, tcpOffset + tcpLength)
    return checksum(pseudo, 0, pseudo.size)
}