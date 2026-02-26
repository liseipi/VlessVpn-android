package com.musicses.vlessvpn

import android.util.Log
import java.nio.ByteBuffer

private const val TAG = "VlessProtocol"

/**
 * VLESS v0 协议实现
 *
 * 请求格式：
 * +------+------+------+---------+------+----------+--------+
 * | Ver  | UUID | Alen | Command | Port | AddrType |  Addr  |
 * +------+------+------+---------+------+----------+--------+
 * |  1   |  16  |  1   |    1    |  2   |    1     |  Vary  |
 * +------+------+------+---------+------+----------+--------+
 *
 * 响应格式：
 * +------+------+----------+
 * | Ver  | Alen |  Addon   | Payload
 * +------+------+----------+
 * |  1   |  1   |   Vary   | ...
 * +------+------+----------+
 */
object VlessProtocol {

    fun buildHeader(uuid: String, host: String, port: Int): ByteArray {
        Log.d(TAG, "Building VLESS header:")
        Log.d(TAG, "  UUID: $uuid")
        Log.d(TAG, "  Target: $host:$port")

        val uid = uuidToBytes(uuid)

        val (atype, addrBytes) = when {
            isIPv4(host) -> {
                Log.d(TAG, "  Address type: IPv4")
                val b = host.split(".").map { it.toInt().toByte() }.toByteArray()
                0x01.toByte() to b
            }
            isIPv6(host) -> {
                Log.d(TAG, "  Address type: IPv6")
                val cleaned = host.trimStart('[').trimEnd(']')
                0x03.toByte() to ipv6ToBytes(cleaned)
            }
            else -> {
                Log.d(TAG, "  Address type: Domain")
                Log.d(TAG, "  Domain: $host (${host.length} chars)")
                val db = host.toByteArray(Charsets.UTF_8)
                val buf = ByteArray(1 + db.size)
                buf[0] = db.size.toByte()
                db.copyInto(buf, 1)
                0x02.toByte() to buf
            }
        }

        // 构建完整头部
        val totalSize = 22 + addrBytes.size
        val header = ByteArray(totalSize)
        var offset = 0

        // [0] 版本
        header[offset++] = 0x00
        Log.d(TAG, "  [0] Version: 0x00")

        // [1-16] UUID
        uid.copyInto(header, offset)
        offset += 16
        Log.d(TAG, "  [1-16] UUID: ${uid.joinToString("") { "%02x".format(it) }}")

        // [17] 附加信息长度
        header[offset++] = 0x00
        Log.d(TAG, "  [17] Addon length: 0x00")

        // [18] 命令（TCP）
        header[offset++] = 0x01
        Log.d(TAG, "  [18] Command: 0x01 (TCP)")

        // [19-20] 端口（大端序）
        header[offset++] = (port ushr 8).toByte()
        header[offset++] = (port and 0xFF).toByte()
        Log.d(TAG, "  [19-20] Port: $port (0x${"%04x".format(port)})")

        // [21] 地址类型
        header[offset++] = atype
        Log.d(TAG, "  [21] Address type: 0x${"%02x".format(atype.toInt() and 0xFF)}")

        // [22+] 地址数据
        addrBytes.copyInto(header, offset)
        Log.d(TAG, "  [22+] Address data: ${addrBytes.size} bytes")

        Log.d(TAG, "  Total header size: $totalSize bytes")
        return header
    }

    /**
     * 跳过 VLESS 响应头
     *
     * 响应格式：
     * [0] = Version (0x00)
     * [1] = Addon length (N)
     * [2...1+N] = Addon data
     * [2+N...] = Payload
     */
    fun stripResponseHeader(data: ByteArray): ByteArray {
        if (data.size < 2) {
            Log.w(TAG, "Response too short: ${data.size} bytes")
            return ByteArray(0)
        }

        val version = data[0].toInt() and 0xFF
        val addonLen = data[1].toInt() and 0xFF
        val headerLen = 2 + addonLen

        Log.d(TAG, "Response header:")
        Log.d(TAG, "  Version: 0x${"%02x".format(version)}")
        Log.d(TAG, "  Addon length: $addonLen")
        Log.d(TAG, "  Header length: $headerLen")
        Log.d(TAG, "  Total data: ${data.size} bytes")
        Log.d(TAG, "  Payload: ${data.size - headerLen} bytes")

        if (version != 0) {
            Log.w(TAG, "Unexpected version: $version (expected 0)")
        }

        return if (data.size > headerLen) {
            data.copyOfRange(headerLen, data.size)
        } else {
            Log.w(TAG, "No payload after header")
            ByteArray(0)
        }
    }

    // ── 内部工具 ──────────────────────────────────────────────────────────────

    private fun uuidToBytes(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        if (hex.length != 32) {
            Log.e(TAG, "Invalid UUID length: ${hex.length} (expected 32)")
            throw IllegalArgumentException("Invalid UUID: $uuid")
        }

        return try {
            ByteArray(16) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (e: NumberFormatException) {
            Log.e(TAG, "Invalid UUID hex: $hex", e)
            throw IllegalArgumentException("Invalid UUID format: $uuid", e)
        }
    }

    private fun isIPv4(host: String) =
        host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))

    private fun isIPv6(host: String) =
        host.contains(":") || (host.startsWith("[") && host.endsWith("]"))

    /**
     * IPv6 地址转字节数组
     * 支持缩写格式（::）
     */
    private fun ipv6ToBytes(addr: String): ByteArray {
        val groups: List<String> = if (addr.contains("::")) {
            val parts = addr.split("::")
            val left  = if (parts[0].isNotEmpty()) parts[0].split(":") else emptyList()
            val right = if (parts.size > 1 && parts[1].isNotEmpty()) parts[1].split(":") else emptyList()
            val mid   = List(8 - left.size - right.size) { "0" }
            left + mid + right
        } else {
            addr.split(":")
        }

        if (groups.size != 8) {
            Log.e(TAG, "Invalid IPv6 format: $addr (got ${groups.size} groups)")
            throw IllegalArgumentException("Invalid IPv6: $addr")
        }

        val buf = ByteBuffer.allocate(16)
        groups.forEach { g ->
            val value = (g.ifEmpty { "0" }).toInt(16).toShort()
            buf.putShort(value)
        }
        return buf.array()
    }
}