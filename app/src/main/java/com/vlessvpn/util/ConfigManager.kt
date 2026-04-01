package com.vlessvpn.util

import android.content.Context
import android.content.SharedPreferences
import com.vlessvpn.model.VlessConfig
import org.json.JSONArray
import org.json.JSONObject

/**
 * 配置持久化管理器，使用 SharedPreferences 存储
 */
object ConfigManager {

    private const val PREF_NAME = "vless_configs"
    private const val KEY_CONFIGS = "configs"
    private const val KEY_SELECTED_ID = "selected_id"
    private const val KEY_SOCKS_PORT = "socks_port"

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
    }

    // ── 配置列表 ──────────────────────────────────────────────────────────────

    fun getConfigs(): MutableList<VlessConfig> {
        val json = prefs.getString(KEY_CONFIGS, "[]") ?: "[]"
        val arr = JSONArray(json)
        val list = mutableListOf<VlessConfig>()
        for (i in 0 until arr.length()) {
            try {
                list.add(fromJson(arr.getJSONObject(i)))
            } catch (e: Exception) {
                // skip malformed
            }
        }
        return list
    }

    fun saveConfigs(configs: List<VlessConfig>) {
        val arr = JSONArray()
        configs.forEach { arr.put(toJson(it)) }
        prefs.edit().putString(KEY_CONFIGS, arr.toString()).apply()
    }

    fun addConfig(config: VlessConfig): List<VlessConfig> {
        val list = getConfigs()
        list.add(config)
        saveConfigs(list)
        return list
    }

    fun removeConfig(id: Long): List<VlessConfig> {
        val list = getConfigs().filter { it.id != id }.toMutableList()
        saveConfigs(list)
        // 如果删除的是选中项，清除选择
        if (getSelectedId() == id) {
            setSelectedId(-1L)
        }
        return list
    }

    fun updateConfig(config: VlessConfig): List<VlessConfig> {
        val list = getConfigs().map { if (it.id == config.id) config else it }.toMutableList()
        saveConfigs(list)
        return list
    }

    // ── 当前选中配置 ──────────────────────────────────────────────────────────

    fun getSelectedId(): Long = prefs.getLong(KEY_SELECTED_ID, -1L)

    fun setSelectedId(id: Long) {
        prefs.edit().putLong(KEY_SELECTED_ID, id).apply()
    }

    fun getSelectedConfig(): VlessConfig? {
        val id = getSelectedId()
        return getConfigs().find { it.id == id }
    }

    // ── SOCKS 端口 ────────────────────────────────────────────────────────────

    fun getSocksPort(): Int = prefs.getInt(KEY_SOCKS_PORT, 1099)

    fun setSocksPort(port: Int) {
        prefs.edit().putInt(KEY_SOCKS_PORT, port).apply()
    }

    // ── JSON 序列化 ───────────────────────────────────────────────────────────

    private fun toJson(c: VlessConfig): JSONObject = JSONObject().apply {
        put("id", c.id)
        put("uuid", c.uuid)
        put("serverHost", c.serverHost)
        put("serverPort", c.serverPort)
        put("encryption", c.encryption)
        put("security", c.security)
        put("sni", c.sni)
        put("type", c.type)
        put("wsHost", c.wsHost)
        put("wsPath", c.wsPath)
        put("remark", c.remark)
    }

    private fun fromJson(o: JSONObject): VlessConfig = VlessConfig(
        id = o.optLong("id", System.currentTimeMillis()),
        uuid = o.getString("uuid"),
        serverHost = o.getString("serverHost"),
        serverPort = o.getInt("serverPort"),
        encryption = o.optString("encryption", "none"),
        security = o.optString("security", "none"),
        sni = o.optString("sni", ""),
        type = o.optString("type", "ws"),
        wsHost = o.optString("wsHost", ""),
        wsPath = o.optString("wsPath", "/"),
        remark = o.optString("remark", "")
    )
}
