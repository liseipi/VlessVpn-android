package com.musicses.vlessvpn// ============================================================================
// 补丁 1：在 TunHandler.handleIpPacket 中添加 UDP 支持
// ============================================================================

// 在 TunHandler 类中添加 UDP 会话管理
private val udpSessions = ConcurrentHashMap<String, UdpSession>()

// 修改 handleIpPacket 方法
private fun handleIpPacket(packet: ByteArray, tunOut: FileOutputStream) {
    try {
        val bb = ByteBuffer.wrap(packet)
        val version = (bb.get(0).toInt() and 0xFF) ushr 4
        if (version != 4) return

        val protocol = bb.get(9).toInt() and 0xFF
        
        // ✅ 修复：添加 UDP 和 ICMP 支持
        when (protocol) {
            6 -> handleTcpPacket(packet, bb, tunOut)  // TCP
            17 -> handleUdpPacket(packet, bb, tunOut) // ✅ NEW: UDP
            1 -> handleIcmpPacket(packet, bb, tunOut) // ✅ NEW: ICMP
        }

    } catch (e: Exception) {
        // 静默忽略
    }
}

// ✅ 新增：UDP 包处理
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

// ✅ 新增：ICMP 包处理（Ping）
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

// ✅ 新增：UDP 会话类
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
            
            // ✅ 关键：保护 socket 避免路由回 VPN
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
                // 正常超时
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

// ✅ 新增：构造 UDP 数据包
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

    // IPv4 头
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

    // UDP 头
    buf.putShort(srcPort.toShort())
    buf.putShort(dstPort.toShort())
    buf.putShort((udpHdrLen + payload.size).toShort())
    buf.putShort(0)

    if (payload.isNotEmpty()) buf.put(payload)

    val udpChecksum = udpChecksum(srcIpBytes, dstIpBytes, buf.array(), ipHdrLen, udpHdrLen + payload.size)
    buf.putShort(ipHdrLen + 6, udpChecksum.toShort())

    return buf.array()
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

// 辅助函数
private fun readUInt16(buf: ByteArray, offset: Int): Int {
    return ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
}
