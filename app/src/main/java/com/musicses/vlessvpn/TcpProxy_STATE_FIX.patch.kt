package com.musicses.vlessvpn// ============================================================================
// 补丁 2：修复 TcpProxy 的 TCP 状态追踪和 ACK 机制
// ============================================================================

// 在 TcpProxy 类中修改状态变量
private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
private var clientSeq = initialClientSeq      // ✅ NEW: 客户端当前序号
private var clientAck = initialClientSeq + 1  // ✅ NEW: 期望下一个序号

// ✅ 修复：在 handleTcpPacket 中解析序号和 ACK
private fun handleTcpPacket(packet: ByteArray, bb: ByteBuffer, tunOut: FileOutputStream) {
    val ihl = (bb.get(0).toInt() and 0x0F) * 4
    if (packet.size < ihl + 20) return

    val srcIp  = formatIp(packet, 12)
    val dstIp  = formatIp(packet, 16)
    val srcPort = readUInt16(packet, ihl)
    val dstPort = readUInt16(packet, ihl + 2)

    // ✅ NEW: 读取序号和 ACK 号
    val seqNum = readUInt32(packet, ihl + 4)
    val ackNum = readUInt32(packet, ihl + 8)
    
    val flags = packet[ihl + 13].toInt() and 0xFF
    val isSyn = (flags and 0x02) != 0
    val isFin = (flags and 0x01) != 0
    val isRst = (flags and 0x04) != 0
    val isAck = (flags and 0x10) != 0  // ✅ NEW

    val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"

    val dataOffset = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
    val payloadStart = ihl + dataOffset
    val payload = if (packet.size > payloadStart) {
        packet.copyOfRange(payloadStart, packet.size)
    } else {
        ByteArray(0)
    }

    when {
        isSyn && !isAck -> {  // ✅ 修改：纯 SYN（不含 ACK）
            Log.d(TAG, "[$flowKey] SYN (seq=$seqNum)")
            handleNewTcpConnection(srcIp, srcPort, dstIp, dstPort, seqNum, tunOut, flowKey)
        }

        isFin || isRst -> {
            Log.d(TAG, "[$flowKey] ${if (isFin) "FIN" else "RST"}")
            tcpFlows.remove(flowKey)?.close()
        }

        payload.isNotEmpty() -> {
            // ✅ 修改：传递序号信息
            tcpFlows[flowKey]?.receiveData(payload, seqNum, ackNum)
        }
        
        isAck && payload.isEmpty() -> {
            // ✅ NEW: 处理纯 ACK 包
            tcpFlows[flowKey]?.updateAck(ackNum)
        }
    }
}

// ✅ 修改：TcpProxy 的数据接收方法（旧方法名 sendData）
// 旧方法（错误）：
/*
fun sendData(data: ByteArray) {
    if (closed) return
    try {
        socksSocket?.getOutputStream()?.write(data)
    } catch (e: Exception) {
        close()
    }
}
*/

// ✅ 新方法（正确）：
fun receiveData(data: ByteArray, seqNum: Long, ackNum: Long) {
    if (closed) return
    
    // ✅ 更新客户端状态
    clientSeq = seqNum
    clientAck = seqNum + data.size  // ✅ 关键：期望下一个序号
    
    try {
        socksSocket?.getOutputStream()?.write(data)
        lastActive = System.currentTimeMillis()
        
        // ✅ 重要：发送 ACK 确认收到数据
        writeAck()
    } catch (e: Exception) {
        Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Send error: ${e.message}")
        close()
    }
}

// ✅ 新增：更新 ACK（处理纯 ACK 包）
fun updateAck(ackNum: Long) {
    // 客户端确认了我们发送的数据
    lastActive = System.currentTimeMillis()
}

// ✅ 新增：发送纯 ACK 包
private fun writeAck() {
    val packet = buildTcpPacket(
        srcIp   = dstIp,
        srcPort = dstPort,
        dstIp   = srcIp,
        dstPort = srcPort,
        seq     = serverSeq,
        ack     = clientAck,  // ✅ 使用更新后的 ACK
        flags   = 0x10,       // 只有 ACK 标志
        payload = ByteArray(0)
    )

    synchronized(tunOut) {
        runCatching { tunOut.write(packet) }
    }
}

// ✅ 修改：writeDataToTun 使用更新后的 ACK
private fun writeDataToTun(data: ByteArray) {
    if (closed) return

    val packet = buildTcpPacket(
        srcIp   = dstIp,
        srcPort = dstPort,
        dstIp   = srcIp,
        dstPort = srcPort,
        seq     = serverSeq,
        ack     = clientAck,  // ✅ 使用更新后的 ACK（而非固定值）
        flags   = 0x18,       // PSH + ACK
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

// 辅助函数：读取 32 位序号
private fun readUInt32(buf: ByteArray, offset: Int): Long {
    return ((buf[offset].toLong() and 0xFF) shl 24) or
           ((buf[offset+1].toLong() and 0xFF) shl 16) or
           ((buf[offset+2].toLong() and 0xFF) shl 8) or
           (buf[offset+3].toLong() and 0xFF)
}
