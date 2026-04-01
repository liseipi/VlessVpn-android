package com.vlessvpn.ui

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vlessvpn.R
import com.vlessvpn.databinding.ActivityConfigListBinding
import com.vlessvpn.databinding.ItemConfigBinding
import com.vlessvpn.model.VlessConfig
import com.vlessvpn.util.ConfigManager

class ConfigListActivity : AppCompatActivity() {

    private lateinit var binding: ActivityConfigListBinding
    private lateinit var adapter: ConfigAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConfigListBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "服务器列表"

        adapter = ConfigAdapter(
            onSelect = { config ->
                ConfigManager.setSelectedId(config.id)
                Toast.makeText(this, "已选择: ${config.displayName()}", Toast.LENGTH_SHORT).show()
                adapter.notifyDataSetChanged()
            },
            onEdit = { config ->
                startActivity(Intent(this, AddConfigActivity::class.java).apply {
                    putExtra("config_id", config.id)
                })
            },
            onDelete = { config ->
                AlertDialog.Builder(this)
                    .setTitle("删除配置")
                    .setMessage("确定删除「${config.displayName()}」吗？")
                    .setPositiveButton("删除") { _, _ ->
                        ConfigManager.removeConfig(config.id)
                        loadConfigs()
                        Toast.makeText(this, "已删除", Toast.LENGTH_SHORT).show()
                    }
                    .setNegativeButton("取消", null)
                    .show()
            },
            onShare = { config ->
                val uri = VlessConfig.toUri(config)
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, uri)
                }
                startActivity(Intent.createChooser(intent, "分享配置"))
            }
        )

        binding.recyclerView.layoutManager = LinearLayoutManager(this)
        binding.recyclerView.adapter = adapter

        binding.fabAdd.setOnClickListener {
            startActivity(Intent(this, AddConfigActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        loadConfigs()
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }

    private fun loadConfigs() {
        val configs = ConfigManager.getConfigs()
        val selectedId = ConfigManager.getSelectedId()
        adapter.setData(configs, selectedId)
        binding.tvEmpty.visibility = if (configs.isEmpty()) View.VISIBLE else View.GONE
    }
}

class ConfigAdapter(
    private val onSelect: (VlessConfig) -> Unit,
    private val onEdit:   (VlessConfig) -> Unit,
    private val onDelete: (VlessConfig) -> Unit,
    private val onShare:  (VlessConfig) -> Unit
) : RecyclerView.Adapter<ConfigAdapter.ViewHolder>() {

    private var configs: List<VlessConfig> = emptyList()
    private var selectedId: Long = -1L

    fun setData(list: List<VlessConfig>, selId: Long) {
        configs = list
        selectedId = selId
        notifyDataSetChanged()
    }

    inner class ViewHolder(val binding: ItemConfigBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val b = ItemConfigBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(b)
    }

    override fun getItemCount() = configs.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val config = configs[position]
        val isSelected = config.id == selectedId
        with(holder.binding) {
            tvName.text = config.displayName()
            tvDetail.text = "${config.serverHost}:${config.serverPort}"
            tvProtocol.text = buildString {
                append(config.type.uppercase())
                if (config.isTls()) append(" + TLS")
            }
            ivSelected.visibility = if (isSelected) View.VISIBLE else View.INVISIBLE
            cardConfig.strokeWidth = if (isSelected) 3 else 0
            root.setOnClickListener { onSelect(config) }
            btnEdit.setOnClickListener { onEdit(config) }
            btnDelete.setOnClickListener { onDelete(config) }
            btnShare.setOnClickListener { onShare(config) }
        }
    }
}
