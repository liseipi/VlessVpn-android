package com.musicses.vlessvpn

import android.content.Context
import org.json.JSONObject

/**
 * 对应 client.js 的 CFG 对象，支持持久化到 SharedPreferences
 */
data class VlessConfig(
    val server: String  = "vs.musicses.vip",
    val port: Int       = 443,
    val uuid: String    = "55a95ae1-4ae8-4461-8484-457279821b40",
    val path: String    = "/?ed=2560",
    val sni: String     = "vs.musicses.vip",
    val wsHost: String  = "vs.musicses.vip",
    val rejectUnauthorized: Boolean = false,
    val dns1: String    = "8.8.8.8",
    val dns2: String    = "8.8.4.4",
) {
    /** wss://server:port/path */
    val wsUrl: String get() = "wss://$server:$port$path"

    companion object {
        private const val PREF  = "vless_config"
        private const val KEY   = "json"

        fun load(ctx: Context): VlessConfig {
            val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .getString(KEY, null) ?: return VlessConfig()
            return try {
                val o = JSONObject(raw)
                VlessConfig(
                    server             = o.optString("server", "vs.musicses.vip"),
                    port               = o.optInt("port", 443),
                    uuid               = o.optString("uuid", "55a95ae1-4ae8-4461-8484-457279821b40"),
                    path               = o.optString("path", "/?ed=2560"),
                    sni                = o.optString("sni", "vs.musicses.vip"),
                    wsHost             = o.optString("wsHost", "vs.musicses.vip"),
                    rejectUnauthorized = o.optBoolean("rejectUnauthorized", false),
                    dns1               = o.optString("dns1", "8.8.8.8"),
                    dns2               = o.optString("dns2", "8.8.4.4"),
                )
            } catch (_: Exception) { VlessConfig() }
        }

        fun save(ctx: Context, cfg: VlessConfig) {
            val o = JSONObject().apply {
                put("server",             cfg.server)
                put("port",               cfg.port)
                put("uuid",               cfg.uuid)
                put("path",               cfg.path)
                put("sni",                cfg.sni)
                put("wsHost",             cfg.wsHost)
                put("rejectUnauthorized", cfg.rejectUnauthorized)
                put("dns1",               cfg.dns1)
                put("dns2",               cfg.dns2)
            }
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putString(KEY, o.toString()).apply()
        }
    }
}
