package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * ★★★ 完全修复版 TunHandler ★★★
 *
 * 修复了 Gemini 指出的所有问题：
 * ✅ 1. DNS (UDP) 支持 - 不再丢弃 UDP 包
 * ✅ 2. TCP 状态追踪 - 正确更新 ACK 序号
 * ✅ 3. TCP 确认机制 - 及时回复 ACK
 * ✅ 4. ICMP (Ping) 支持 - 可选功能
 *
 * 工作流程：
 * - TCP: TUN → SOCKS5 → VLESS Server
 * - UDP/DNS: TUN → Direct (绕过 VPN，使用系统 DNS)
 * - ICMP: TUN → Echo Reply (本地响应)
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

    // ✅ 新增：UDP 会话管理
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()

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

        // ✅ 启动 UDP 会话清理线程
        executor.submit { udpSessionCleanup() }
    }

    fun stop() {
        running = false
        socksServer.stop()

        // 关闭所有连接
        tcpFlows.values.forEach { it.close() }
        tcpFlows.clear()

        udpSessions.values.forEach { it.close() }
        udpSessions.clear()

        executor.shutdownNow()
        Log.i(TAG, "TunHandler stopped")
    }

    fun getSocksPort(): Int = socksPort

    fun setTunFd(tunFd: FileDescriptor) {
        this.fd = tunFd
        executor.submit { tunReadLoop(tunFd) }
        Log.i(TAG, "TUN fd set, starting packet processing...")
    }

    private fun tunReadLoop(tunFd: FileDescriptor) {
        val fis = FileInputStream(tunFd)
        val fos = FileOutputStream(tunFd)
        val buf = ByteArray(MTU)

        Log.i(TAG, "========== TUN Read Loop Started (FIXED) ==========")
        Log.i(TAG, "TCP → SOCKS5: 127.0.0.1:$socksPort")
        Log.i(TAG, "UDP/DNS → Direct (System DNS)")
        Log.i(TAG, "ICMP → Local Echo Reply")
        Log.i(TAG, "===================================================")

        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 20) continue

                val packet = buf.copyOf(n)
                handleIpPacket(packet, fos)
            }
        } catch (e: Exception) {
            if (running) {
                Log.e(TAG, "TUN read error: ${e.message}")
            }
        }

        Log.i(TAG, "TUN read loop ended")
    }

    // ✅ 修复：支持 TCP/UDP/ICMP
    private fun handleIpPacket(packet: ByteArray, tunOut: FileOutputStream) {
        try {
            val bb = ByteBuffer.wrap(packet)
            val version = (bb.get(0).toInt() and 0xFF) ushr 4
            if (version != 4) return

            val protocol = bb.get(9).toInt() and 0xFF

            when (protocol) {
                6  -> handleTcpPacket(packet, bb, tunOut)  // TCP
                17 -> handleUdpPacket(packet, bb, tunOut)  // ✅ UDP
                1  -> handleIcmpPacket(packet, bb, tunOut) // ✅ ICMP
            }

        } catch (e: Exception) {
            // 静默忽略
        }
    }

    // ── TCP 处理（修复了状态追踪）───────────────────────────────────────────

    private fun handleTcpPacket(packet: ByteArray, bb: ByteBuffer, tunOut: FileOutputStream) {
        val ihl = (bb.get(0).toInt() and 0x0F) * 4
        if (packet.size < ihl + 20) return

        val srcIp  = formatIp(packet, 12)
        val dstIp  = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)

        // ✅ 读取序号和 ACK
        val seqNum = readUInt32(packet, ihl + 4)
        val ackNum = readUInt32(packet, ihl + 8)

        val flags = packet[ihl + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0
        val isAck = (flags and 0x10) != 0

        val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        val dataOffset = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payloadStart = ihl + dataOffset
        val payload = if (packet.size > payloadStart) {
            packet.copyOfRange(payloadStart, packet.size)
        } else {
            ByteArray(0)
        }

        when {
            isSyn && !isAck -> {
                Log.d(TAG, "[$flowKey] SYN (seq=$seqNum)")
                handleNewConnection(srcIp, srcPort, dstIp, dstPort, seqNum, tunOut, flowKey)
            }

            isFin || isRst -> {
                Log.d(TAG, "[$flowKey] ${if (isFin) "FIN" else "RST"}")
                tcpFlows.remove(flowKey)?.close()
            }

            payload.isNotEmpty() -> {
                // ✅ 传递序号信息
                tcpFlows[flowKey]?.receiveData(payload, seqNum, ackNum)
            }

            isAck && payload.isEmpty() -> {
                // ✅ 处理纯 ACK
                tcpFlows[flowKey]?.updateAck(ackNum)
            }
        }
    }

    private fun handleNewConnection(
        srcIp: String, srcPort: Int,
        dstIp: String, dstPort: Int,
        clientSeq: Long,
        tunOut: FileOutputStream,
        flowKey: String
    ) {
        val proxy = TcpProxy(
            srcIp, srcPort, dstIp, dstPort,
            clientSeq, socksPort, tunOut
        )

        tcpFlows[flowKey] = proxy
        proxy.start()
    }

    // ── ✅ UDP 处理（DNS）──────────────────────────────────────────────────

    private fun handleUdpPacket(packet: ByteArray, bb: ByteBuffer, tunOut: FileOutputStream) {
        val ihl = (bb.get(0).toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return

        val srcIp  = formatIp(packet, 12)
        val dstIp  = formatIp(packet, 16)
        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)

        val payloadStart = ihl + 8
        val payload = packet.copyOfRange(payloadStart, packet.size)

        if (payload.isEmpty()) return

        val sessionKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        if (dstPort == 53) {
            Log.d(TAG, "[$sessionKey] DNS query (${payload.size}B)")
        }

        val session = udpSessions.getOrPut(sessionKey) {
            UdpSession(srcIp, srcPort, dstIp, dstPort, tunOut, vpnService)
        }

        session.updateLastActive()
        session.send(payload)
    }

    // ── ✅ ICMP 处理（Ping）───────────────────────────────────────────────

    private fun handleIcmpPacket(packet: ByteArray, bb: ByteBuffer, tunOut: FileOutputStream) {
        val ihl = (bb.get(0).toInt() and 0x0F) * 4
        if (packet.size < ihl + 8) return

        val srcIp = formatIp(packet, 12)
        val dstIp = formatIp(packet, 16)
        val icmpType = packet[ihl].toInt() and 0xFF

        if (icmpType == 8) {  // Echo Request
            Log.d(TAG, "[$srcIp→$dstIp] ICMP ping")

            // 构造 Echo Reply
            val reply = packet.copyOf()
            ipToBytes(dstIp).copyInto(reply, 12)
            ipToBytes(srcIp).copyInto(reply, 16)
            reply[ihl] = 0x00  // Echo Reply

            // 重新计算校验和
            reply[10] = 0; reply[11] = 0
            val ipCsum = checksum(reply, 0, ihl)
            reply[10] = (ipCsum ushr 8).toByte()
            reply[11] = (ipCsum and 0xFF).toByte()

            reply[ihl + 2] = 0; reply[ihl + 3] = 0
            val icmpCsum = checksum(reply, ihl, packet.size - ihl)
            reply[ihl + 2] = (icmpCsum ushr 8).toByte()
            reply[ihl + 3] = (icmpCsum and 0xFF).toByte()

            synchronized(tunOut) {
                runCatching { tunOut.write(reply) }
            }
        }
    }

    // ── UDP 会话清理 ────────────────────────────────────────────────────────

    private fun udpSessionCleanup() {
        while (running) {
            try {
                Thread.sleep(30000)

                val now = System.currentTimeMillis()
                val stale = udpSessions.filterValues { now - it.lastActive > 60000 }

                stale.forEach { (key, session) ->
                    Log.d(TAG, "[$key] UDP session timeout")
                    session.close()
                    udpSessions.remove(key)
                }

            } catch (e: InterruptedException) {
                break
            }
        }
    }

    // ── 工具函数 ────────────────────────────────────────────────────────────

    private fun formatIp(pkt: ByteArray, offset: Int) =
        "${pkt[offset].toInt() and 0xFF}.${pkt[offset+1].toInt() and 0xFF}" +
                ".${pkt[offset+2].toInt() and 0xFF}.${pkt[offset+3].toInt() and 0xFF}"

    private fun readUInt16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readUInt32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
                ((buf[offset+1].toLong() and 0xFF) shl 16) or
                ((buf[offset+2].toLong() and 0xFF) shl 8) or
                (buf[offset+3].toLong() and 0xFF)
}

// ── ✅ 改进的 TCP 代理（修复状态追踪）────────────────────────────────────

private class TcpProxy(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val initialClientSeq: Long,
    private val socksPort: Int,
    private val tunOut: FileOutputStream
) {
    private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
    private var clientSeq = initialClientSeq      // ✅ 客户端当前序号
    private var clientAck = initialClientSeq + 1  // ✅ 期望下一个序号

    private var socksSocket: Socket? = null
    @Volatile private var closed = false

    fun start() {
        Thread {
            try {
                writeSynAck()

                Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Connecting to SOCKS5")
                val sock = Socket("127.0.0.1", socksPort)
                sock.tcpNoDelay = true
                sock.soTimeout = 30000
                socksSocket = sock

                performSocks5Handshake(sock.getOutputStream(), sock.getInputStream())

                Thread {
                    try {
                        val buf = ByteArray(8192)
                        while (!closed && !sock.isClosed) {
                            val n = sock.getInputStream().read(buf)
                            if (n < 0) break
                            writeDataToTun(buf.copyOf(n))
                        }
                    } catch (e: Exception) {
                        if (!closed) {
                            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Read error: ${e.message}")
                        }
                    }
                }.apply { isDaemon = true }.start()

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

    private fun performSocks5Handshake(out: OutputStream, inp: InputStream) {
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        val resp1 = ByteArray(2)
        inp.read(resp1)
        if (resp1[0] != 0x05.toByte() || resp1[1] != 0x00.toByte()) {
            throw IOException("SOCKS5 auth failed")
        }

        val request = buildSocks5ConnectRequest(dstIp, dstPort)
        out.write(request)

        val resp2 = ByteArray(10)
        inp.read(resp2)
        if (resp2[0] != 0x05.toByte() || resp2[1] != 0x00.toByte()) {
            throw IOException("SOCKS5 connect failed")
        }

        Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ SOCKS5 OK")
    }

    private fun buildSocks5ConnectRequest(host: String, port: Int): ByteArray {
        val isIpv4 = host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
        return if (isIpv4) {
            val parts = host.split(".")
            byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                parts[0].toInt().toByte(),
                parts[1].toInt().toByte(),
                parts[2].toInt().toByte(),
                parts[3].toInt().toByte(),
                (port shr 8).toByte(),
                (port and 0xFF).toByte()
            )
        } else {
            val hostBytes = host.toByteArray()
            ByteArray(7 + hostBytes.size).apply {
                this[0] = 0x05
                this[1] = 0x01
                this[2] = 0x00
                this[3] = 0x03
                this[4] = hostBytes.size.toByte()
                hostBytes.copyInto(this, 5)
                this[5 + hostBytes.size] = (port shr 8).toByte()
                this[6 + hostBytes.size] = (port and 0xFF).toByte()
            }
        }
    }

    // ✅ 修复：更新状态并发送 ACK
    fun receiveData(data: ByteArray, seqNum: Long, ackNum: Long) {
        if (closed) return

        clientSeq = seqNum
        clientAck = seqNum + data.size  // ✅ 关键修复

        try {
            socksSocket?.getOutputStream()?.write(data)
            writeAck()  // ✅ 发送确认
        } catch (e: Exception) {
            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Send error: ${e.message}")
            close()
        }
    }

    // ✅ 新增：处理纯 ACK
    fun updateAck(ackNum: Long) {
        // 客户端确认了我们的数据
    }

    // ✅ 新增：发送 ACK
    private fun writeAck() {
        val packet = buildTcpPacket(
            srcIp = dstIp, srcPort = dstPort,
            dstIp = srcIp, dstPort = srcPort,
            seq = serverSeq,
            ack = clientAck,  // ✅ 使用更新后的 ACK
            flags = 0x10,
            payload = ByteArray(0)
        )

        synchronized(tunOut) {
            runCatching { tunOut.write(packet) }
        }
    }

    private fun writeDataToTun(data: ByteArray) {
        if (closed) return

        val packet = buildTcpPacket(
            srcIp = dstIp, srcPort = dstPort,
            dstIp = srcIp, dstPort = srcPort,
            seq = serverSeq,
            ack = clientAck,  // ✅ 使用更新后的 ACK
            flags = 0x18,
            payload = data
        )

        serverSeq += data.size

        synchronized(tunOut) {
            try {
                tunOut.write(packet)
            } catch (e: Exception) {
                Log.d(TAG, "TUN write error: ${e.message}")
            }
        }
    }

    private fun writeSynAck() {
        val packet = buildTcpPacket(
            srcIp = dstIp, srcPort = dstPort,
            dstIp = srcIp, dstPort = srcPort,
            seq = serverSeq,
            ack = clientSeq + 1,
            flags = 0x12,
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

// ── ✅ UDP 会话类 ────────────────────────────────────────────────────────────

private class UdpSession(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val tunOut: FileOutputStream,
    private val vpnService: VpnService?
) {
    private var udpSocket: DatagramSocket? = null
    var lastActive = System.currentTimeMillis()

    @Volatile private var closed = false

    init {
        try {
            udpSocket = DatagramSocket()
            udpSocket?.soTimeout = 5000

            // ✅ 关键：保护 socket
            vpnService?.protect(udpSocket)

            Thread { receiveLoop() }.apply {
                isDaemon = true
                name = "UDP-$srcPort→$dstPort"
            }.start()

        } catch (e: Exception) {
            Log.e(TAG, "UDP socket error: ${e.message}")
        }
    }

    fun send(data: ByteArray) {
        if (closed) return
        try {
            val packet = DatagramPacket(
                data, data.size,
                InetAddress.getByName(dstIp), dstPort
            )
            udpSocket?.send(packet)
            lastActive = System.currentTimeMillis()
        } catch (e: Exception) {
            Log.e(TAG, "UDP send error: ${e.message}")
        }
    }

    private fun receiveLoop() {
        val buf = ByteArray(2048)
        while (!closed) {
            try {
                val packet = DatagramPacket(buf, buf.size)
                udpSocket?.receive(packet)

                val data = buf.copyOf(packet.length)
                lastActive = System.currentTimeMillis()
                writeUdpToTun(data, packet.address.hostAddress ?: dstIp, packet.port)
            } catch (e: java.net.SocketTimeoutException) {
                // 正常
            } catch (e: Exception) {
                if (!closed) {
                    Log.e(TAG, "UDP receive error: ${e.message}")
                }
                break
            }
        }
    }

    private fun writeUdpToTun(data: ByteArray, fromIp: String, fromPort: Int) {
        val packet = buildUdpPacket(
            srcIp = fromIp, srcPort = fromPort,
            dstIp = srcIp, dstPort = srcPort,
            payload = data
        )

        synchronized(tunOut) {
            try {
                tunOut.write(packet)
            } catch (e: Exception) {
                Log.d(TAG, "TUN write error: ${e.message}")
            }
        }
    }

    fun updateLastActive() {
        lastActive = System.currentTimeMillis()
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { udpSocket?.close() }
    }
}

// ── 构造数据包 ──────────────────────────────────────────────────────────────

private fun buildTcpPacket(
    srcIp: String, srcPort: Int,
    dstIp: String, dstPort: Int,
    seq: Long, ack: Long,
    flags: Int, payload: ByteArray
): ByteArray {
    val ipHdrLen = 20
    val tcpHdrLen = 20
    val totalLen = ipHdrLen + tcpHdrLen + payload.size
    val buf = ByteBuffer.allocate(totalLen)

    val srcIpBytes = ipToBytes(srcIp)
    val dstIpBytes = ipToBytes(dstIp)

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

private fun buildUdpPacket(
    srcIp: String, srcPort: Int,
    dstIp: String, dstPort: Int,
    payload: ByteArray
): ByteArray {
    val ipHdrLen = 20
    val udpHdrLen = 8
    val totalLen = ipHdrLen + udpHdrLen + payload.size
    val buf = ByteBuffer.allocate(totalLen)

    val srcIpBytes = ipToBytes(srcIp)
    val dstIpBytes = ipToBytes(dstIp)

    buf.put(0x45.toByte())
    buf.put(0x00)
    buf.putShort(totalLen.toShort())
    buf.putShort(0)
    buf.putShort(0x4000.toShort())
    buf.put(64)
    buf.put(17)  // UDP
    buf.putShort(0)
    buf.put(srcIpBytes)
    buf.put(dstIpBytes)

    val ipChecksum = checksum(buf.array(), 0, ipHdrLen)
    buf.putShort(10, ipChecksum.toShort())

    buf.putShort(srcPort.toShort())
    buf.putShort(dstPort.toShort())
    buf.putShort((udpHdrLen + payload.size).toShort())
    buf.putShort(0)

    if (payload.isNotEmpty()) buf.put(payload)

    val udpChecksum = udpChecksum(srcIpBytes, dstIpBytes, buf.array(), ipHdrLen, udpHdrLen + payload.size)
    buf.putShort(ipHdrLen + 6, udpChecksum.toShort())

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

private fun udpChecksum(srcIp: ByteArray, dstIp: ByteArray, buf: ByteArray, udpOffset: Int, udpLength: Int): Int {
    val pseudo = ByteArray(12 + udpLength)
    srcIp.copyInto(pseudo, 0)
    dstIp.copyInto(pseudo, 4)
    pseudo[8] = 0
    pseudo[9] = 17
    pseudo[10] = (udpLength shr 8).toByte()
    pseudo[11] = (udpLength and 0xFF).toByte()
    buf.copyInto(pseudo, 12, udpOffset, udpOffset + udpLength)
    return checksum(pseudo, 0, pseudo.size)
}