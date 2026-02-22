package com.musicses.vlessvpn

import android.app.Activity
import android.content.*
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.*
import androidx.compose.ui.window.Dialog
import com.musicses.vlessvpn.ui.theme.VlessVpnTheme

// ── 颜色 ─────────────────────────────────────────────────────────────────────
private val BgDark     = Color(0xFF0F1117)
private val CardBg     = Color(0xFF1E2130)
private val Accent     = Color(0xFF5B8DEF)
private val TextPri    = Color(0xFFE8EAF0)
private val TextSec    = Color(0xFF8892A4)
private val GreenOk    = Color(0xFF4CAF50)
private val RedErr     = Color(0xFFE53935)
private val OrangeWait = Color(0xFFFF9800)
private val DividerCol = Color(0xFF2A2F45)

class MainActivity : ComponentActivity() {

    private var vpnReceiver: BroadcastReceiver? = null
    private val _status   = mutableStateOf("DISCONNECTED")
    private val _bytesIn  = mutableStateOf(0L)
    private val _bytesOut = mutableStateOf(0L)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        vpnReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                _status.value   = intent.getStringExtra(VlessVpnService.EXTRA_STATUS) ?: return
                _bytesIn.value  = intent.getLongExtra(VlessVpnService.EXTRA_IN, _bytesIn.value)
                _bytesOut.value = intent.getLongExtra(VlessVpnService.EXTRA_OUT, _bytesOut.value)
            }
        }
        registerReceiver(vpnReceiver, IntentFilter(VlessVpnService.BROADCAST), RECEIVER_NOT_EXPORTED)

        setContent {
            VlessVpnTheme(darkTheme = true, dynamicColor = false) {
                MainScreen(_status, _bytesIn, _bytesOut)
            }
        }
    }

    override fun onDestroy() {
        vpnReceiver?.let { unregisterReceiver(it) }
        super.onDestroy()
    }
}

// ── 主屏 ──────────────────────────────────────────────────────────────────────

@Composable
fun MainScreen(
    statusState:   MutableState<String>,
    bytesInState:  MutableState<Long>,
    bytesOutState: MutableState<Long>,
) {
    val ctx       = LocalContext.current
    val clipboard = LocalClipboardManager.current

    val status   by statusState
    val bytesIn  by bytesInState
    val bytesOut by bytesOutState

    // ── 配置列表状态 ──────────────────────────────────────────────────────────
    var configs   by remember { mutableStateOf(ConfigStore.loadAll(ctx)) }
    var activeId  by remember { mutableStateOf(ConfigStore.loadActive(ctx).id) }
    val activeCfg = configs.firstOrNull { it.id == activeId } ?: configs.first()

    // ── 弹窗状态 ──────────────────────────────────────────────────────────────
    var showEditor   by remember { mutableStateOf(false) }
    var editingCfg   by remember { mutableStateOf<VlessConfig?>(null) }   // null = 新增
    var showImport   by remember { mutableStateOf(false) }
    var showUriPaste by remember { mutableStateOf("") }   // 粘贴框内容

    // ── VPN 权限 ──────────────────────────────────────────────────────────────
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpn(ctx)
    }

    fun onConnectToggle() {
        if (status == "CONNECTED") {
            stopVpn(ctx)
        } else {
            ConfigStore.saveActiveId(ctx, activeId)
            val intent = VpnService.prepare(ctx)
            if (intent != null) vpnLauncher.launch(intent) else startVpn(ctx)
        }
    }

    fun saveConfigs(list: List<VlessConfig>) {
        configs = list
        ConfigStore.saveAll(ctx, list)
    }

    // ── 布局 ──────────────────────────────────────────────────────────────────
    Surface(color = BgDark, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .systemBarsPadding()
                .padding(16.dp)
        ) {
            // 标题栏
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("VLESS VPN", fontSize = 24.sp, fontWeight = FontWeight.Bold,
                    color = Accent, modifier = Modifier.weight(1f))
                // 导入按钮
                TextButton(onClick = { showImport = true }) {
                    Text("Import", color = TextSec, fontSize = 13.sp)
                }
                // 新增按钮
                IconButton(onClick = { editingCfg = null; showEditor = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Add",
                        tint = Accent)
                }
            }

            // ── 状态卡片 ──────────────────────────────────────────────────────
            StatusCard(status, bytesIn, bytesOut, ::onConnectToggle)

            Spacer(Modifier.height(16.dp))

            // ── 配置列表 ──────────────────────────────────────────────────────
            Text("Configurations", color = TextSec, fontSize = 12.sp,
                modifier = Modifier.padding(bottom = 8.dp))

            configs.forEach { cfg ->
                ProfileRow(
                    cfg       = cfg,
                    isActive  = cfg.id == activeId,
                    isConnected = status == "CONNECTED" && cfg.id == activeId,
                    onSelect  = { activeId = cfg.id; ConfigStore.saveActiveId(ctx, cfg.id) },
                    onEdit    = { editingCfg = cfg; showEditor = true },
                    onExport  = {
                        clipboard.setText(AnnotatedString(cfg.toVlessUri()))
                        Toast.makeText(ctx, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    onDelete  = {
                        if (configs.size > 1) {
                            val newList = configs.filter { it.id != cfg.id }
                            if (activeId == cfg.id) activeId = newList.first().id
                            saveConfigs(newList)
                        } else {
                            Toast.makeText(ctx, "Cannot delete the only config", Toast.LENGTH_SHORT).show()
                        }
                    }
                )
                Spacer(Modifier.height(8.dp))
            }

            Spacer(Modifier.height(8.dp))
            Text("Routing all traffic via VLESS/WS tunnel",
                color = TextSec, fontSize = 11.sp,
                modifier = Modifier.fillMaxWidth().wrapContentWidth())
        }
    }

    // ── 编辑/新增弹窗 ──────────────────────────────────────────────────────────
    if (showEditor) {
        ProfileEditorDialog(
            initial  = editingCfg,
            onDismiss = { showEditor = false },
            onSave   = { cfg ->
                val newList = if (editingCfg == null) {
                    configs + cfg
                } else {
                    configs.map { if (it.id == cfg.id) cfg else it }
                }
                saveConfigs(newList)
                if (editingCfg == null) activeId = cfg.id
                showEditor = false
            }
        )
    }

    // ── 导入弹窗 ──────────────────────────────────────────────────────────────
    if (showImport) {
        ImportDialog(
            onDismiss = { showImport = false },
            onImport  = { uri ->
                val cfg = VlessConfig.fromVlessUri(uri)
                if (cfg != null) {
                    saveConfigs(configs + cfg)
                    activeId = cfg.id
                    showImport = false
                    Toast.makeText(ctx, "Imported: ${cfg.name}", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(ctx, "Invalid VLESS URI", Toast.LENGTH_SHORT).show()
                }
            }
        )
    }
}

// ── 状态卡片 ──────────────────────────────────────────────────────────────────

@Composable
private fun StatusCard(status: String, bytesIn: Long, bytesOut: Long, onToggle: () -> Unit) {
    val (statusText, statusColor) = when (status) {
        "CONNECTED"  -> "● Connected"   to GreenOk
        "CONNECTING" -> "◌ Connecting…" to OrangeWait
        "ERROR"      -> "✕ Error"       to RedErr
        else         -> "○ Disconnected" to TextSec
    }
    val btnText  = if (status == "CONNECTED") "Disconnect" else "Connect"
    val btnColor = if (status == "CONNECTED") RedErr else Accent

    Card(shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        modifier = Modifier.fillMaxWidth()) {
        Column(horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(24.dp)) {
            Text(statusText, color = statusColor, fontSize = 18.sp, fontWeight = FontWeight.Medium)
            if (status == "CONNECTED") {
                Spacer(Modifier.height(4.dp))
                Text("↓ ${fmtBytes(bytesIn)}   ↑ ${fmtBytes(bytesOut)}",
                    color = TextSec, fontSize = 13.sp)
            }
            Spacer(Modifier.height(16.dp))
            Button(onClick = onToggle,
                colors = ButtonDefaults.buttonColors(containerColor = btnColor),
                modifier = Modifier.width(200.dp).height(48.dp)) {
                Text(btnText, fontSize = 16.sp)
            }
        }
    }
}

// ── 配置行 ────────────────────────────────────────────────────────────────────

@Composable
private fun ProfileRow(
    cfg: VlessConfig,
    isActive: Boolean,
    isConnected: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit,
) {
    val borderColor = if (isActive) Accent else DividerCol
    Card(shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        border = BorderStroke(if (isActive) 1.5.dp else 0.5.dp, borderColor),
        modifier = Modifier.fillMaxWidth().clickable { onSelect() }) {
        Row(modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically) {
            // 选中指示器
            Box(modifier = Modifier.size(10.dp).background(
                if (isConnected) GreenOk else if (isActive) Accent else Color(0xFF3A3F55),
                shape = RoundedCornerShape(50)
            ))
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(cfg.name, color = TextPri, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                Text("${cfg.server}:${cfg.port}  ${if (cfg.security == "tls") "TLS" else "WS"}",
                    color = TextSec, fontSize = 12.sp)
            }
            // 导出（复制）
            TextButton(onClick = onExport, contentPadding = PaddingValues(0.dp),
                modifier = Modifier.size(36.dp)) {
                Text("⎘", color = TextSec, fontSize = 16.sp)
            }
            // 编辑
            TextButton(onClick = onEdit, contentPadding = PaddingValues(0.dp),
                modifier = Modifier.size(36.dp)) {
                Text("✎", color = TextSec, fontSize = 16.sp)
            }
            // 删除
            IconButton(onClick = onDelete, modifier = Modifier.size(36.dp)) {
                Icon(Icons.Default.Delete, contentDescription = "Delete",
                    tint = RedErr.copy(alpha = 0.7f), modifier = Modifier.size(18.dp))
            }
        }
    }
}

// ── 编辑/新增弹窗 ──────────────────────────────────────────────────────────────

@Composable
private fun ProfileEditorDialog(
    initial: VlessConfig?,
    onDismiss: () -> Unit,
    onSave: (VlessConfig) -> Unit,
) {
    val isNew = initial == null
    var name      by remember { mutableStateOf(initial?.name     ?: "New Config") }
    var server    by remember { mutableStateOf(initial?.server   ?: "") }
    var port      by remember { mutableStateOf(initial?.port?.toString() ?: "443") }
    var uuid      by remember { mutableStateOf(initial?.uuid     ?: "") }
    var path      by remember { mutableStateOf(initial?.path     ?: "/") }
    var sni       by remember { mutableStateOf(initial?.sni      ?: "") }
    var wsHost    by remember { mutableStateOf(initial?.wsHost   ?: "") }
    var security  by remember { mutableStateOf(initial?.security ?: "none") }
    val useTls    = security == "tls"

    // 也支持直接粘贴 URI 解析
    val clipboard = LocalClipboardManager.current
    var pasteError by remember { mutableStateOf("") }

    fun fillFromUri(uri: String) {
        val cfg = VlessConfig.fromVlessUri(uri)
        if (cfg != null) {
            name    = cfg.name;   server  = cfg.server
            port    = cfg.port.toString(); uuid    = cfg.uuid
            path    = cfg.path;   sni     = cfg.sni
            wsHost  = cfg.wsHost; security = cfg.security
            pasteError = ""
        } else {
            pasteError = "Invalid VLESS URI"
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        Card(shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = CardBg),
            modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier
                .verticalScroll(rememberScrollState())
                .padding(20.dp)) {

                Text(if (isNew) "New Configuration" else "Edit Configuration",
                    color = Accent, fontSize = 16.sp, fontWeight = FontWeight.Bold)

                Spacer(Modifier.height(12.dp))

                // 快速粘贴 URI 行
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Paste VLESS URI", color = TextSec, fontSize = 12.sp,
                        modifier = Modifier.weight(1f))
                    OutlinedButton(
                        onClick = {
                            val text = clipboard.getText()?.text ?: ""
                            fillFromUri(text)
                        },
                        border = BorderStroke(1.dp, Accent),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp)
                    ) { Text("Paste & Parse", fontSize = 12.sp) }
                }
                if (pasteError.isNotEmpty()) {
                    Text(pasteError, color = RedErr, fontSize = 11.sp)
                }

                HorizontalDivider(color = DividerCol, modifier = Modifier.padding(vertical = 10.dp))

                DlgField("Profile Name", name, KeyboardType.Text) { name = it }
                DlgField("Server Host", server, KeyboardType.Uri) { server = it }
                DlgField("Port", port, KeyboardType.Number) { port = it }
                DlgField("UUID", uuid, KeyboardType.Text) { uuid = it }
                DlgField("WebSocket Path", path, KeyboardType.Uri) { path = it }
                DlgField("SNI", sni, KeyboardType.Uri) { sni = it }
                DlgField("Host Header", wsHost, KeyboardType.Uri) { wsHost = it }

                // TLS 开关
                Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text("Enable TLS", color = TextPri, fontSize = 14.sp,
                        modifier = Modifier.weight(1f))
                    Switch(checked = useTls,
                        onCheckedChange = { security = if (it) "tls" else "none" },
                        colors = SwitchDefaults.colors(checkedThumbColor = Accent))
                }

                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onDismiss, modifier = Modifier.weight(1f),
                        border = BorderStroke(1.dp, TextSec),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec)) {
                        Text("Cancel")
                    }
                    Button(onClick = {
                        val cfg = (initial ?: VlessConfig()).copy(
                            name     = name.trim(),
                            server   = server.trim(),
                            port     = port.toIntOrNull() ?: 443,
                            uuid     = uuid.trim(),
                            path     = path.trim(),
                            sni      = sni.trim(),
                            wsHost   = wsHost.trim(),
                            security = security,
                            rejectUnauthorized = security != "tls",
                        )
                        onSave(cfg)
                    }, modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)) {
                        Text("Save")
                    }
                }
            }
        }
    }
}

// ── 导入弹窗 ──────────────────────────────────────────────────────────────────

@Composable
private fun ImportDialog(onDismiss: () -> Unit, onImport: (String) -> Unit) {
    var uriText by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current

    Dialog(onDismissRequest = onDismiss) {
        Card(shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = CardBg),
            modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text("Import VLESS URI", color = Accent, fontSize = 16.sp,
                    fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = uriText,
                    onValueChange = { uriText = it },
                    placeholder = { Text("vless://...", color = TextSec) },
                    minLines = 3,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor   = Accent,
                        unfocusedBorderColor = DividerCol,
                        focusedTextColor     = TextPri,
                        unfocusedTextColor   = TextPri,
                        cursorColor          = Accent,
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                // 从剪贴板粘贴
                OutlinedButton(
                    onClick = { uriText = clipboard.getText()?.text ?: "" },
                    border = BorderStroke(1.dp, TextSec),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Paste from Clipboard") }

                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onDismiss, modifier = Modifier.weight(1f),
                        border = BorderStroke(1.dp, TextSec),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec)) {
                        Text("Cancel")
                    }
                    Button(onClick = { onImport(uriText.trim()) },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)) {
                        Text("Import")
                    }
                }
            }
        }
    }
}

// ── 工具组件 ──────────────────────────────────────────────────────────────────

@Composable
private fun DlgField(label: String, value: String, kbd: KeyboardType, onChange: (String) -> Unit) {
    Text(label, color = TextSec, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
    OutlinedTextField(
        value = value, onValueChange = onChange, singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = kbd),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor   = Accent,
            unfocusedBorderColor = DividerCol,
            focusedTextColor     = TextPri,
            unfocusedTextColor   = TextPri,
            cursorColor          = Accent,
        ),
        modifier = Modifier.fillMaxWidth()
    )
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

private fun fmtBytes(b: Long) = when {
    b < 1024L    -> "${b}B"
    b < 1048576L -> "${"%.1f".format(b / 1024.0)}K"
    else         -> "${"%.1f".format(b / 1048576.0)}M"
}

private fun startVpn(ctx: Context) =
    ctx.startService(Intent(ctx, VlessVpnService::class.java).setAction(VlessVpnService.ACTION_START))

private fun stopVpn(ctx: Context) =
    ctx.startService(Intent(ctx, VlessVpnService::class.java).setAction(VlessVpnService.ACTION_STOP))