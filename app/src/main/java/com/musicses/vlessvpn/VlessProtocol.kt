package com.musicses.vlessvpn

import java.nio.ByteBuffer

/**
 * 完整对应 client.js 的 buildVlessHeader() 和 ipv6ToBytes()
 *
 * VLESS v0 帧格式：
 *  [0]      版本 = 0x00
 *  [1..16]  UUID (16 字节)
 *  [17]     附加信息长度 = 0x00
 *  [18]     命令 = 0x01 (TCP)
 *  [19..20] 目标端口 (big-endian)
 *  [21]     地址类型: 1=IPv4  2=域名  3=IPv6
 *  [22..]   地址数据
 */
object VlessProtocol {

    fun buildHeader(uuid: String, host: String, port: Int): ByteArray {
        val uid = uuidToBytes(uuid)

        val (atype, addrBytes) = when {
            isIPv4(host) -> {
                val b = host.split(".").map { it.toInt().toByte() }.toByteArray()
                0x01.toByte() to b
            }
            isIPv6(host) -> {
                // 对应 client.js atype = 3  （注意 JS 里 IPv6 用 atype=3，域名 atype=2）
                val cleaned = host.trimStart('[').trimEnd(']')
                0x03.toByte() to ipv6ToBytes(cleaned)
            }
            else -> {
                // 域名  atype = 2
                val db = host.toByteArray(Charsets.UTF_8)
                val buf = ByteArray(1 + db.size)
                buf[0] = db.size.toByte()
                db.copyInto(buf, 1)
                0x02.toByte() to buf
            }
        }

        // 固定头 22 字节
        val fixed = ByteArray(22)
        var o = 0
        fixed[o++] = 0x00                         // version
        uid.copyInto(fixed, o); o += 16           // UUID
        fixed[o++] = 0x00                         // addon len
        fixed[o++] = 0x01                         // command: TCP
        fixed[o++] = (port ushr 8).toByte()       // port high
        fixed[o++] = (port and 0xFF).toByte()     // port low
        fixed[o]   = atype                        // address type

        return fixed + addrBytes
    }

    /**
     * 跳过 VLESS 响应头的前 2 字节（对应 client.js 的 buf.slice(2)）
     */
    fun stripResponseHeader(data: ByteArray): ByteArray =
        if (data.size > 2) data.copyOfRange(2, data.size) else ByteArray(0)

    // ── 内部工具 ──────────────────────────────────────────────────────────────

    private fun uuidToBytes(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        return ByteArray(16) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun isIPv4(host: String) =
        host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))

    private fun isIPv6(host: String) =
        host.contains(":") || (host.startsWith("[") && host.endsWith("]"))

    /**
     * 对应 client.js ipv6ToBytes()
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
        val buf = ByteBuffer.allocate(16)
        groups.forEach { g -> buf.putShort((g.ifEmpty { "0" }).toInt(16).toShort()) }
        return buf.array()
    }
}
