package com.vlessvpn.model

import java.net.URLDecoder

/**
 * VLESS 配置数据模型
 * 支持解析格式:
 * vless://uuid@host:port?encryption=none&security=tls&sni=xxx&type=ws&host=xxx&path=xxx#remark
 */
data class VlessConfig(
    val uuid: String,
    val serverHost: String,
    val serverPort: Int,
    val encryption: String = "none",
    val security: String = "none",    // "tls" or "none"
    val sni: String = "",
    val type: String = "ws",           // network type
    val wsHost: String = "",
    val wsPath: String = "/",
    val remark: String = "",
    val id: Long = System.currentTimeMillis()
) {
    companion object {
        /**
         * 解析 vless:// URI
         */
        fun parse(uri: String): VlessConfig {
            require(uri.startsWith("vless://")) { "不是有效的 VLESS 链接" }

            val withoutScheme = uri.removePrefix("vless://")

            // 分离 remark (#后面部分)
            val remarkIdx = withoutScheme.indexOf('#')
            val remark = if (remarkIdx >= 0)
                URLDecoder.decode(withoutScheme.substring(remarkIdx + 1), "UTF-8")
            else ""
            val withoutRemark = if (remarkIdx >= 0) withoutScheme.substring(0, remarkIdx) else withoutScheme

            // 分离 query (?后面部分)
            val queryIdx = withoutRemark.indexOf('?')
            val queryStr = if (queryIdx >= 0) withoutRemark.substring(queryIdx + 1) else ""
            val mainPart = if (queryIdx >= 0) withoutRemark.substring(0, queryIdx) else withoutRemark

            // 解析 uuid@host:port
            val atIdx = mainPart.indexOf('@')
            require(atIdx >= 0) { "VLESS 链接缺少 @ 符号" }
            val uuid = mainPart.substring(0, atIdx)
            val hostPort = mainPart.substring(atIdx + 1)

            // 处理 IPv6 地址 [::1]:port
            val (host, port) = if (hostPort.startsWith("[")) {
                val closeBracket = hostPort.indexOf(']')
                val h = hostPort.substring(1, closeBracket)
                val p = hostPort.substring(closeBracket + 2).toIntOrNull() ?: 443
                Pair(h, p)
            } else {
                val lastColon = hostPort.lastIndexOf(':')
                if (lastColon >= 0) {
                    Pair(hostPort.substring(0, lastColon), hostPort.substring(lastColon + 1).toIntOrNull() ?: 443)
                } else {
                    Pair(hostPort, 443)
                }
            }

            // 解析 query 参数
            val params = mutableMapOf<String, String>()
            if (queryStr.isNotEmpty()) {
                queryStr.split("&").forEach { pair ->
                    val eqIdx = pair.indexOf('=')
                    if (eqIdx >= 0) {
                        val k = pair.substring(0, eqIdx)
                        val v = URLDecoder.decode(pair.substring(eqIdx + 1), "UTF-8")
                        params[k] = v
                    }
                }
            }

            val security = params["security"] ?: "none"
            val sni = params["sni"] ?: host
            val type = params["type"] ?: "ws"
            val wsHost = params["host"] ?: host
            // path 可能含有 ?ed=2560 这样的参数，完整保留
            val wsPath = params["path"] ?: "/"

            return VlessConfig(
                uuid = uuid,
                serverHost = host,
                serverPort = port,
                encryption = params["encryption"] ?: "none",
                security = security,
                sni = sni,
                type = type,
                wsHost = wsHost,
                wsPath = wsPath,
                remark = remark.ifEmpty { host }
            )
        }

        /**
         * 构建用于显示的链接字符串
         */
        fun toUri(config: VlessConfig): String {
            return buildString {
                append("vless://")
                append(config.uuid)
                append("@")
                append(config.serverHost)
                append(":")
                append(config.serverPort)
                append("?encryption=${config.encryption}")
                append("&security=${config.security}")
                append("&sni=${config.sni}")
                append("&type=${config.type}")
                append("&host=${config.wsHost}")
                append("&path=${config.wsPath}")
                append("#${config.remark}")
            }
        }
    }

    /**
     * 构建 WebSocket URL (与 client.js buildWsUrl() 逻辑完全一致)
     */
    fun buildWsUrl(): String {
        val scheme = if (security == "tls" || serverPort == 443) "wss" else "ws"
        val qIdx = wsPath.indexOf("?")
        return if (qIdx >= 0) {
            val p = wsPath.substring(0, qIdx)
            val q = wsPath.substring(qIdx + 1)
            "$scheme://$serverHost:$serverPort$p?$q"
        } else {
            "$scheme://$serverHost:$serverPort$wsPath"
        }
    }

    /**
     * 是否使用 TLS
     */
    fun isTls() = security == "tls" || serverPort == 443

    /**
     * 显示名称
     */
    fun displayName() = remark.ifEmpty { "$serverHost:$serverPort" }
}
