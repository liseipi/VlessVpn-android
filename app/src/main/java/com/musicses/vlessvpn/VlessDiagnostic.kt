package com.musicses.vlessvpn

import android.util.Log
import okhttp3.*
import java.util.concurrent.TimeUnit

private const val TAG = "VlessDiagnostic"

/**
 * VLESS 连接诊断工具
 *
 * 用于检查：
 * 1. WebSocket 连接是否正常
 * 2. TLS/SNI 配置是否正确
 * 3. VLESS 协议握手是否成功
 */
object VlessDiagnostic {

    /**
     * 测试 VLESS 配置
     *
     * @return 错误信息，如果为 null 表示测试通过
     */
    fun testConfig(cfg: VlessConfig): String? {
        Log.i(TAG, "========== VLESS Configuration Diagnostic ==========")
        Log.i(TAG, "Profile: ${cfg.name}")
        Log.i(TAG, "Server: ${cfg.server}:${cfg.port}")
        Log.i(TAG, "UUID: ${cfg.uuid}")
        Log.i(TAG, "Path: ${cfg.path}")
        Log.i(TAG, "Security: ${cfg.security}")
        Log.i(TAG, "SNI: ${cfg.sni}")
        Log.i(TAG, "WS Host: ${cfg.wsHost}")
        Log.i(TAG, "WS URL: ${cfg.wsUrl}")
        Log.i(TAG, "===================================================")

        // 检查 1: UUID 格式
        val uuidRegex = Regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
        if (!cfg.uuid.matches(uuidRegex)) {
            return "Invalid UUID format: ${cfg.uuid}"
        }
        Log.i(TAG, "✓ UUID format valid")

        // 检查 2: Path 格式
        if (!cfg.path.startsWith("/")) {
            return "Path must start with '/': ${cfg.path}"
        }
        Log.i(TAG, "✓ Path format valid")

        // 检查 3: TLS 配置一致性
        if (cfg.security == "tls") {
            if (!cfg.wsUrl.startsWith("wss://")) {
                return "TLS enabled but URL is not wss://"
            }
            if (cfg.sni.isEmpty()) {
                Log.w(TAG, "⚠ TLS enabled but SNI is empty (will use server address)")
            }
        } else {
            if (cfg.wsUrl.startsWith("wss://")) {
                return "TLS disabled but URL is wss://"
            }
        }
        Log.i(TAG, "✓ TLS configuration consistent")

        return null
    }

    /**
     * 测试 WebSocket 连接（不发送 VLESS 数据）
     */
    fun testWebSocket(cfg: VlessConfig, callback: (success: Boolean, error: String?) -> Unit) {
        Log.i(TAG, "Testing WebSocket connection to ${cfg.wsUrl}")

        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        val request = Request.Builder()
            .url(cfg.wsUrl)
            .header("Host", cfg.wsHost)
            .header("User-Agent", "Mozilla/5.0")
            .build()

        var opened = false

        client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "✓ WebSocket opened successfully")
                Log.i(TAG, "  Protocol: ${response.protocol}")
                Log.i(TAG, "  Response code: ${response.code}")
                opened = true
                webSocket.close(1000, "Test complete")
                callback(true, null)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "✗ WebSocket connection failed: ${t.message}")
                response?.let {
                    Log.e(TAG, "  Response code: ${it.code}")
                    Log.e(TAG, "  Response message: ${it.message}")
                }
                if (!opened) {
                    callback(false, t.message)
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closing: $code $reason")
                webSocket.close(1000, null)
            }
        })
    }

    /**
     * 分析 VLESS 服务器响应
     */
    fun analyzeServerBehavior(
        receivedBytes: Int,
        closeCode: Int,
        closeReason: String
    ): String {
        return buildString {
            appendLine("========== Server Behavior Analysis ==========")
            appendLine("Received: $receivedBytes bytes")
            appendLine("Close code: $closeCode")
            appendLine("Close reason: ${closeReason.ifEmpty { "(empty)" }}")
            appendLine()

            when {
                closeCode == 1000 && receivedBytes > 0 && receivedBytes < 100 -> {
                    appendLine("❌ LIKELY ISSUE: Server sent small response and closed")
                    appendLine("   This usually means:")
                    appendLine("   1. UUID is incorrect or not authorized")
                    appendLine("   2. VLESS protocol version mismatch")
                    appendLine("   3. Server rejected the connection request")
                }

                closeCode == 1000 && receivedBytes == 0 -> {
                    appendLine("❌ LIKELY ISSUE: Server closed without sending data")
                    appendLine("   This usually means:")
                    appendLine("   1. WebSocket upgrade succeeded but VLESS auth failed")
                    appendLine("   2. Server doesn't support VLESS protocol")
                    appendLine("   3. Path or Host header is incorrect")
                }

                closeCode == 1006 -> {
                    appendLine("❌ ABNORMAL CLOSE: Connection dropped without proper close")
                    appendLine("   This usually means:")
                    appendLine("   1. Network issue or timeout")
                    appendLine("   2. Server crashed or rejected connection")
                    appendLine("   3. Firewall/proxy interference")
                }

                closeCode == 1002 -> {
                    appendLine("❌ PROTOCOL ERROR: Server detected protocol violation")
                    appendLine("   Check VLESS header format")
                }

                receivedBytes > 1000 -> {
                    appendLine("✓ Likely successful - received substantial data")
                }

                else -> {
                    appendLine("⚠ Unusual behavior - check server logs")
                }
            }
            appendLine("================================================")
        }
    }

    /**
     * 详细的 VLESS 头部验证
     */
    fun validateVlessHeader(header: ByteArray): String? {
        if (header.size < 22) {
            return "Header too short: ${header.size} bytes (minimum 22)"
        }

        // 检查版本
        if (header[0] != 0x00.toByte()) {
            return "Invalid version: 0x${"%02x".format(header[0])} (expected 0x00)"
        }

        // 检查 UUID（应该是 16 字节）
        val uuid = header.copyOfRange(1, 17)
        if (uuid.all { it == 0x00.toByte() }) {
            return "UUID is all zeros"
        }

        // 检查附加信息长度
        val addonLen = header[17].toInt() and 0xFF
        if (addonLen > 0) {
            Log.d(TAG, "Header has addon data: $addonLen bytes")
        }

        // 检查命令
        val command = header[18].toInt() and 0xFF
        if (command != 0x01) {
            return "Invalid command: 0x${"%02x".format(command)} (expected 0x01 for TCP)"
        }

        // 检查端口
        val port = ((header[19].toInt() and 0xFF) shl 8) or (header[20].toInt() and 0xFF)
        if (port == 0) {
            return "Invalid port: 0"
        }

        // 检查地址类型
        val addrType = header[21].toInt() and 0xFF
        when (addrType) {
            0x01 -> Log.d(TAG, "Address type: IPv4")
            0x02 -> Log.d(TAG, "Address type: Domain")
            0x03 -> Log.d(TAG, "Address type: IPv6")
            else -> return "Invalid address type: 0x${"%02x".format(addrType)}"
        }

        Log.i(TAG, "✓ VLESS header structure is valid")
        return null
    }
}