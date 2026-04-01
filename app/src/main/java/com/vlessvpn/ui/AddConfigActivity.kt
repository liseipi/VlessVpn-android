package com.vlessvpn.ui

import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.vlessvpn.databinding.ActivityAddConfigBinding
import com.vlessvpn.model.VlessConfig
import com.vlessvpn.util.ConfigManager

class AddConfigActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAddConfigBinding
    private var editingConfig: VlessConfig? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAddConfigBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        // 判断是新增还是编辑
        val configId = intent.getLongExtra("config_id", -1L)
        if (configId != -1L) {
            editingConfig = ConfigManager.getConfigs().find { it.id == configId }
            editingConfig?.let { fillForm(it) }
            supportActionBar?.title = "编辑配置"
        } else {
            supportActionBar?.title = "添加配置"
        }

        binding.btnPasteUri.setOnClickListener { pasteFromClipboard() }
        binding.btnParseUri.setOnClickListener { parseUriField() }
        binding.btnSave.setOnClickListener { saveConfig() }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }

    private fun pasteFromClipboard() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = cm.primaryClip?.getItemAt(0)?.text?.toString()
        if (!text.isNullOrBlank()) {
            binding.etUri.setText(text)
            if (text.startsWith("vless://")) parseUriField()
        } else {
            Toast.makeText(this, "剪贴板为空", Toast.LENGTH_SHORT).show()
        }
    }

    private fun parseUriField() {
        val uri = binding.etUri.text?.toString()?.trim() ?: ""
        if (uri.isBlank()) {
            Toast.makeText(this, "请输入 VLESS 链接", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val config = VlessConfig.parse(uri)
            fillForm(config)
            Toast.makeText(this, "解析成功", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "解析失败: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun fillForm(config: VlessConfig) {
        binding.etRemark.setText(config.remark)
        binding.etUuid.setText(config.uuid)
        binding.etServer.setText(config.serverHost)
        binding.etPort.setText(config.serverPort.toString())
        binding.etSni.setText(config.sni)
        binding.etWsHost.setText(config.wsHost)
        binding.etWsPath.setText(config.wsPath)
        binding.switchTls.isChecked = config.isTls()
        binding.etUri.setText(VlessConfig.toUri(config))
    }

    private fun saveConfig() {
        val remark  = binding.etRemark.text?.toString()?.trim() ?: ""
        val uuid    = binding.etUuid.text?.toString()?.trim() ?: ""
        val server  = binding.etServer.text?.toString()?.trim() ?: ""
        val portStr = binding.etPort.text?.toString()?.trim() ?: ""
        val sni     = binding.etSni.text?.toString()?.trim() ?: ""
        val wsHost  = binding.etWsHost.text?.toString()?.trim() ?: ""
        val wsPath  = binding.etWsPath.text?.toString()?.trim().let { if (it.isNullOrBlank()) "/" else it }
        val tls     = binding.switchTls.isChecked

        if (uuid.isBlank() || server.isBlank() || portStr.isBlank()) {
            Toast.makeText(this, "UUID、服务器地址和端口不能为空", Toast.LENGTH_SHORT).show()
            return
        }
        val port = portStr.toIntOrNull()
        if (port == null || port !in 1..65535) {
            Toast.makeText(this, "端口号无效", Toast.LENGTH_SHORT).show()
            return
        }

        val config = VlessConfig(
            id         = editingConfig?.id ?: System.currentTimeMillis(),
            uuid       = uuid,
            serverHost = server,
            serverPort = port,
            encryption = "none",
            security   = if (tls) "tls" else "none",
            sni        = sni.ifBlank { server },
            type       = "ws",
            wsHost     = wsHost.ifBlank { server },
            wsPath     = wsPath,
            remark     = remark.ifBlank { server }
        )

        if (editingConfig != null) {
            ConfigManager.updateConfig(config)
            Toast.makeText(this, "配置已更新", Toast.LENGTH_SHORT).show()
        } else {
            ConfigManager.addConfig(config)
            ConfigManager.setSelectedId(config.id)
            Toast.makeText(this, "配置已保存", Toast.LENGTH_SHORT).show()
        }
        finish()
    }
}
