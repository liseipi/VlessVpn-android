package com.musicses.vlessvpn

import android.net.VpnService
import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private const val TAG = "PacketTunnel"
private const val MTU = 1500

/**
 * 核心转发引擎：
 *  1. 从 TUN fd 读取原始 IPv4/TCP 数据包
 *  2. 解析目标 IP:Port
 *  3. 为每条 TCP 流建立一个 VlessTunnel
 *  4. 双向中继数据
 *  5. 构造假的 TCP ACK 回包写回 TUN，让本地 TCP 栈正常工作
 *
 * 流标识：srcIP:srcPort -> dstIP:dstPort
 *
 * ★ 修复：增加连接超时时间为 15 秒，因为 VLESS 连接建立可能较慢
 */
class PacketTunnel(
    private val fd: FileDescriptor,
    private val cfg: VlessConfig,
    private val vpnService: VpnService? = null,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor   = Executors.newCachedThreadPool()
    private val tunIn      = FileInputStream(fd)
    private val tunOut     = FileOutputStream(fd)
    private val flows      = ConcurrentHashMap<String, TcpFlow>()

    @Volatile private var running = false
    private var totalIn  = 0L
    private var totalOut = 0L

    fun start() {
        running = true
        executor.submit { readLoop() }
        Log.i(TAG, "PacketTunnel started")
    }

    fun stop() {
        running = false
        flows.values.forEach { it.close() }
        flows.clear()
        executor.shutdownNow()
        runCatching { tunIn.close() }
        runCatching { tunOut.close() }
    }

    // ── TUN 读取主循环 ────────────────────────────────────────────────────────

    private fun readLoop() {
        val buf = ByteArray(MTU)
        while (running) {
            try {
                val n = tunIn.read(buf)
                if (n < 20) continue

                val pkt = buf.copyOf(n)
                val bb  = ByteBuffer.wrap(pkt)

                val version = (bb.get(0).toInt() and 0xFF) ushr 4
                if (version != 4) continue

                val protocol = bb.get(9).toInt() and 0xFF
                if (protocol != 6) continue

                handleTcpPacket(pkt, bb)
            } catch (e: Exception) {
                if (running) Log.e(TAG, "readLoop: ${e.message}")
            }
        }
    }

    // ── TCP 包处理 ───────────────────────────────────────────────────────────

    private fun handleTcpPacket(pkt: ByteArray, bb: ByteBuffer) {
        val ihl = (bb.get(0).toInt() and 0x0F) * 4
        if (pkt.size < ihl + 20) return

        val srcIp  = formatIp(pkt, 12)
        val dstIp  = formatIp(pkt, 16)

        val srcPort = ((pkt[ihl].toInt() and 0xFF) shl 8) or (pkt[ihl + 1].toInt() and 0xFF)
        val dstPort = ((pkt[ihl + 2].toInt() and 0xFF) shl 8) or (pkt[ihl + 3].toInt() and 0xFF)

        val flags = pkt[ihl + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0

        val flowKey = "$srcIp:$srcPort->$dstIp:$dstPort"

        val dataOffset = ((pkt[ihl + 12].toInt() and 0xFF) ushr 4) * 4
        val payloadStart = ihl + dataOffset
        val payload = if (pkt.size > payloadStart) pkt.copyOfRange(payloadStart, pkt.size)
        else ByteArray(0)

        when {
            isSyn && (flags and 0x10) == 0 -> {  // SYN without ACK
                Log.d(TAG, "SYN: $flowKey")
                val flow = TcpFlow(
                    srcIp, srcPort, dstIp, dstPort,
                    seqFromPkt(pkt, ihl),
                    cfg, vpnService, tunOut
                ) { bytesIn, bytesOut ->
                    totalIn  += bytesIn
                    totalOut += bytesOut
                    onStats(totalIn, totalOut)
                }
                flows[flowKey] = flow
                flow.handleSyn()
            }
            isFin || isRst -> {
                Log.d(TAG, "${if (isFin) "FIN" else "RST"}: $flowKey")
                flows.remove(flowKey)?.close()
            }
            payload.isNotEmpty() -> {
                flows[flowKey]?.send(payload)
            }
        }
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

// ── 单条 TCP 流 ───────────────────────────────────────────────────────────────

private class TcpFlow(
    private val srcIp:   String,
    private val srcPort: Int,
    private val dstIp:   String,
    private val dstPort: Int,
    private val clientSeq: Long,
    private val cfg: VlessConfig,
    private val vpnService: VpnService?,
    private val tunOut: FileOutputStream,
    private val onStats: (Long, Long) -> Unit
) {
    private val tunnel  = VlessTunnel(cfg, vpnService)
    private val pipe    = java.io.PipedOutputStream()
    private val pipeIn  = java.io.PipedInputStream(pipe, 65536)

    // ★ 关键修复：增加超时时间为 15 秒
    private val connectLatch = CountDownLatch(1)

    private var serverSeq = System.currentTimeMillis() and 0xFFFFFFFFL
    private var clientAck = clientSeq + 1

    @Volatile private var closed = false
    @Volatile private var connected = false

    fun handleSyn() {
        writeSynAck()

        // 异步建立隧道连接
        tunnel.connect(dstIp, dstPort) { ok ->
            if (!ok) {
                Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Tunnel connection failed")
                connectLatch.countDown()  // 释放锁（连接失败）
                close()
                return@connect
            }

            connected = true
            connectLatch.countDown()  // 释放锁（连接成功）
            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✓ Tunnel connected, starting relay")

            // 启动中继线程
            Thread {
                try {
                    val tunOutputStream = TunOutputStream(
                        srcIp   = dstIp,
                        srcPort = dstPort,
                        dstIp   = srcIp,
                        dstPort = srcPort,
                        seq     = serverSeq,
                        ack     = clientAck,
                        tunOut  = tunOut,
                        onStats = onStats
                    )

                    tunnel.relay(pipeIn, tunOutputStream)
                    Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Relay completed")
                } catch (e: Exception) {
                    Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Relay error: ${e.message}")
                } finally {
                    close()
                }
            }.apply {
                name = "TcpFlow-$srcPort→$dstPort"
                isDaemon = true
            }.start()
        }
    }

    fun send(data: ByteArray) {
        if (closed) return

        // ★ 等待连接建立（增加到 15 秒）
        if (!connectLatch.await(15, TimeUnit.SECONDS)) {
            Log.w(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✗ Connection timeout (15s), dropping ${data.size}B")
            close()
            return
        }

        // 检查连接是否成功
        if (!connected) {
            Log.w(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] ✗ Connection failed, dropping ${data.size}B")
            return
        }

        try {
            pipe.write(data)
            pipe.flush()
        } catch (e: Exception) {
            Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Send error: ${e.message}")
            close()
        }
    }

    fun close() {
        if (closed) return
        closed = true
        Log.d(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Closing flow")
        runCatching { pipe.close() }
        tunnel.close()
    }

    private fun writeSynAck() {
        val pkt = buildTcpPacket(
            srcIp   = dstIp,   srcPort = dstPort,
            dstIp   = srcIp,   dstPort = srcPort,
            seq     = serverSeq,
            ack     = clientSeq + 1,
            flags   = 0x12,  // SYN + ACK
            payload = ByteArray(0)
        )
        serverSeq++
        runCatching { tunOut.write(pkt) }
    }
}

// ── 把服务器响应数据包装成 TCP 包写回 TUN ─────────────────────────────────────

private class TunOutputStream(
    private val srcIp:   String,
    private val srcPort: Int,
    private val dstIp:   String,
    private val dstPort: Int,
    private var seq:     Long,
    private val ack:     Long,
    private val tunOut:  FileOutputStream,
    private val onStats: (Long, Long) -> Unit
) : OutputStream() {

    private var totalIn = 0L

    override fun write(b: Int) = write(byteArrayOf(b.toByte()))

    override fun write(buf: ByteArray, off: Int, len: Int) {
        if (len == 0) return

        val data = buf.copyOfRange(off, off + len)
        val pkt  = buildTcpPacket(
            srcIp   = srcIp,   srcPort = srcPort,
            dstIp   = dstIp,   dstPort = dstPort,
            seq     = seq,
            ack     = ack,
            flags   = 0x18,    // PSH + ACK
            payload = data
        )
        seq += data.size
        totalIn += data.size
        onStats(totalIn, 0L)

        try {
            tunOut.write(pkt)
        } catch (e: Exception) {
            Log.e(TAG, "[$srcIp:$srcPort→$dstIp:$dstPort] Write error: ${e.message}")
            throw e
        }
    }

    override fun write(b: ByteArray) = write(b, 0, b.size)
    override fun close() {}
}

// ── 构造 IPv4 + TCP 数据包 ────────────────────────────────────────────────────

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