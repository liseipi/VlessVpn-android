package com.vlessvpn.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.MutableLiveData
import com.vlessvpn.model.VlessConfig
import com.vlessvpn.util.ConfigManager

class MainViewModel(app: Application) : AndroidViewModel(app) {

    val selectedConfig = MutableLiveData<VlessConfig?>()
    val configs = MutableLiveData<List<VlessConfig>>()
    val toastMessage = MutableLiveData<String?>()

    init {
        loadConfigs()
    }

    fun loadConfigs() {
        val list = ConfigManager.getConfigs()
        configs.value = list
        selectedConfig.value = ConfigManager.getSelectedConfig()
            ?: list.firstOrNull()?.also { ConfigManager.setSelectedId(it.id) }
    }

    fun importConfig(uri: String) {
        try {
            val config = VlessConfig.parse(uri)
            ConfigManager.addConfig(config)
            ConfigManager.setSelectedId(config.id)
            loadConfigs()
            toastMessage.value = "配置已导入: ${config.displayName()}"
        } catch (e: Exception) {
            toastMessage.value = "链接格式错误: ${e.message}"
        }
    }

    fun selectConfig(config: VlessConfig) {
        ConfigManager.setSelectedId(config.id)
        selectedConfig.value = config
    }

    fun deleteConfig(config: VlessConfig) {
        ConfigManager.removeConfig(config.id)
        loadConfigs()
    }

    fun clearToast() {
        toastMessage.value = null
    }
}
