package com.vlessvpn.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import com.vlessvpn.R
import com.vlessvpn.databinding.ActivityMainBinding
import com.vlessvpn.service.VlessVpnService
import com.vlessvpn.util.VpnStateManager
import com.vlessvpn.viewmodel.MainViewModel

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: MainViewModel

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, "需要 VPN 权限才能连接", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        viewModel = ViewModelProvider(this)[MainViewModel::class.java]

        setupObservers()
        setupListeners()

        // 处理从剪贴板或分享导入的链接
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIncomingIntent(it) }
    }

    override fun onResume() {
        super.onResume()
        viewModel.loadConfigs()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_add -> {
                startActivity(Intent(this, AddConfigActivity::class.java))
                true
            }
            R.id.action_configs -> {
                startActivity(Intent(this, ConfigListActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun setupObservers() {
        // VPN 状态变化
        VpnStateManager.state.observe(this) { state ->
            updateUiForState(state)
        }

        // 当前选中配置
        viewModel.selectedConfig.observe(this) { config ->
            if (config != null) {
                binding.tvServerName.text = config.displayName()
                binding.tvServerDetail.text = "${config.serverHost}:${config.serverPort}"
                binding.tvProtocol.text = buildString {
                    append(config.type.uppercase())
                    if (config.isTls()) append(" + TLS")
                }
            } else {
                binding.tvServerName.text = "未选择配置"
                binding.tvServerDetail.text = "请添加或选择服务器"
                binding.tvProtocol.text = "-"
            }
        }

        viewModel.toastMessage.observe(this) { msg ->
            if (msg != null) {
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
                viewModel.clearToast()
            }
        }
    }

    private fun setupListeners() {
        binding.btnConnect.setOnClickListener {
            when (VpnStateManager.state.value) {
                VpnStateManager.State.CONNECTED,
                VpnStateManager.State.CONNECTING -> stopVpn()
                else -> requestVpnPermissionAndStart()
            }
        }

        binding.cardServer.setOnClickListener {
            startActivity(Intent(this, ConfigListActivity::class.java))
        }

        binding.btnImport.setOnClickListener {
            val clipboard = getSystemService(android.content.ClipboardManager::class.java)
            val text = clipboard?.primaryClip?.getItemAt(0)?.text?.toString()
            if (!text.isNullOrBlank() && text.startsWith("vless://")) {
                viewModel.importConfig(text)
            } else {
                // 打开手动输入界面
                startActivity(Intent(this, AddConfigActivity::class.java))
            }
        }
    }

    private fun updateUiForState(state: VpnStateManager.State) {
        when (state) {
            VpnStateManager.State.DISCONNECTED -> {
                binding.btnConnect.text = "连 接"
                binding.btnConnect.isEnabled = true
                binding.tvStatus.text = "未连接"
                binding.tvStatus.setTextColor(getColor(R.color.status_disconnected))
                binding.vpnStatusIndicator.setImageResource(R.drawable.ic_vpn_off)
                binding.animationView.visibility = android.view.View.INVISIBLE
            }
            VpnStateManager.State.CONNECTING -> {
                binding.btnConnect.text = "取 消"
                binding.btnConnect.isEnabled = true
                binding.tvStatus.text = "正在连接..."
                binding.tvStatus.setTextColor(getColor(R.color.status_connecting))
                binding.vpnStatusIndicator.setImageResource(R.drawable.ic_vpn_connecting)
                binding.animationView.visibility = android.view.View.VISIBLE
            }
            VpnStateManager.State.CONNECTED -> {
                binding.btnConnect.text = "断 开"
                binding.btnConnect.isEnabled = true
                binding.tvStatus.text = "已连接"
                binding.tvStatus.setTextColor(getColor(R.color.status_connected))
                binding.vpnStatusIndicator.setImageResource(R.drawable.ic_vpn_on)
                binding.animationView.visibility = android.view.View.INVISIBLE
            }
            VpnStateManager.State.DISCONNECTING -> {
                binding.btnConnect.isEnabled = false
                binding.tvStatus.text = "正在断开..."
                binding.tvStatus.setTextColor(getColor(R.color.status_connecting))
            }
            VpnStateManager.State.ERROR -> {
                binding.btnConnect.text = "重 试"
                binding.btnConnect.isEnabled = true
                binding.tvStatus.text = "连接失败"
                binding.tvStatus.setTextColor(getColor(R.color.status_error))
                binding.vpnStatusIndicator.setImageResource(R.drawable.ic_vpn_off)
                binding.animationView.visibility = android.view.View.INVISIBLE
                val errMsg = VpnStateManager.errorMessage.value
                if (!errMsg.isNullOrBlank()) {
                    Toast.makeText(this, errMsg, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun requestVpnPermissionAndStart() {
        val selected = viewModel.selectedConfig.value
        if (selected == null) {
            Toast.makeText(this, "请先添加并选择服务器配置", Toast.LENGTH_SHORT).show()
            startActivity(Intent(this, AddConfigActivity::class.java))
            return
        }

        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val config = viewModel.selectedConfig.value ?: return
        val intent = Intent(this, VlessVpnService::class.java).apply {
            action = VlessVpnService.ACTION_START
            putExtra(VlessVpnService.EXTRA_CONFIG_ID, config.id)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, VlessVpnService::class.java).apply {
            action = VlessVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun handleIncomingIntent(intent: Intent) {
        // 处理通过 scheme 或 ACTION_VIEW 传入的 vless:// 链接
        val uri = intent.dataString ?: intent.getStringExtra(Intent.EXTRA_TEXT)
        if (!uri.isNullOrBlank() && uri.startsWith("vless://")) {
            viewModel.importConfig(uri)
        }
    }
}
