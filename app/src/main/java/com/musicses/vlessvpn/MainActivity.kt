package com.musicses.vlessvpn

import android.app.Activity
import android.content.*
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.*
import com.musicses.vlessvpn.ui.theme.VlessVpnTheme

// ── 颜色 ─────────────────────────────────────────────────────────────────────
private val BgDark    = Color(0xFF0F1117)
private val CardBg    = Color(0xFF1E2130)
private val Accent    = Color(0xFF5B8DEF)
private val TextSec   = Color(0xFF8892A4)
private val GreenOk   = Color(0xFF4CAF50)
private val RedErr    = Color(0xFFE53935)
private val OrangeWait= Color(0xFFFF9800)

class MainActivity : ComponentActivity() {

    private var vpnReceiver: BroadcastReceiver? = null

    // Compose 状态（用 mutableStateOf 从 receiver 回调更新）
    private val _status   = mutableStateOf("DISCONNECTED")
    private val _bytesIn  = mutableStateOf(0L)
    private val _bytesOut = mutableStateOf(0L)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // 注册 VPN 状态广播
        vpnReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                _status.value   = intent.getStringExtra(VlessVpnService.EXTRA_STATUS) ?: return
                _bytesIn.value  = intent.getLongExtra(VlessVpnService.EXTRA_IN, _bytesIn.value)
                _bytesOut.value = intent.getLongExtra(VlessVpnService.EXTRA_OUT, _bytesOut.value)
            }
        }
        registerReceiver(
            vpnReceiver,
            IntentFilter(VlessVpnService.BROADCAST),
            RECEIVER_NOT_EXPORTED
        )

        setContent {
            VlessVpnTheme(darkTheme = true, dynamicColor = false) {
                VpnScreen(
                    statusState   = _status,
                    bytesInState  = _bytesIn,
                    bytesOutState = _bytesOut,
                )
            }
        }
    }

    override fun onDestroy() {
        vpnReceiver?.let { unregisterReceiver(it) }
        super.onDestroy()
    }
}

// ── 主界面 ────────────────────────────────────────────────────────────────────

@Composable
fun VpnScreen(
    statusState:   MutableState<String>,
    bytesInState:  MutableState<Long>,
    bytesOutState: MutableState<Long>,
) {
    val ctx     = LocalContext.current
    val status  by statusState
    val bytesIn by bytesInState
    val bytesOut by bytesOutState

    // 读取已保存的配置
    var cfg by remember { mutableStateOf(VlessConfig.load(ctx)) }
    var server  by remember { mutableStateOf(cfg.server)  }
    var port    by remember { mutableStateOf(cfg.port.toString()) }
    var uuid    by remember { mutableStateOf(cfg.uuid)    }
    var path    by remember { mutableStateOf(cfg.path)    }
    var sni     by remember { mutableStateOf(cfg.sni)     }
    var wsHost  by remember { mutableStateOf(cfg.wsHost)  }
    var verifyTls by remember { mutableStateOf(!cfg.rejectUnauthorized) }
    var snackMsg by remember { mutableStateOf("") }

    // VPN 权限请求
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpn(ctx)
        else snackMsg = "VPN permission denied"
    }

    fun onConnectClick() {
        if (status == "CONNECTED") {
            stopVpn(ctx)
        } else {
            // 先保存配置
            val newCfg = VlessConfig(
                server             = server.trim(),
                port               = port.toIntOrNull() ?: 443,
                uuid               = uuid.trim(),
                path               = path.trim(),
                sni                = sni.trim(),
                wsHost             = wsHost.trim(),
                rejectUnauthorized = !verifyTls,
            )
            VlessConfig.save(ctx, newCfg)
            // 申请 VPN 权限
            val intent = VpnService.prepare(ctx)
            if (intent != null) vpnLauncher.launch(intent) else startVpn(ctx)
        }
    }

    Surface(color = BgDark, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .systemBarsPadding()
                .padding(16.dp)
        ) {
            // ── 标题 ─────────────────────────────────────────────────────────
            Text(
                "VLESS VPN",
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold,
                color = Accent,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp)
                    .wrapContentWidth()
            )

            // ── 状态卡片 ──────────────────────────────────────────────────────
            StatusCard(status, bytesIn, bytesOut, ::onConnectClick)

            Spacer(Modifier.height(16.dp))

            // ── 配置卡片 ──────────────────────────────────────────────────────
            ConfigCard(
                server = server,    onServer = { server = it },
                port   = port,      onPort   = { port = it },
                uuid   = uuid,      onUuid   = { uuid = it },
                path   = path,      onPath   = { path = it },
                sni    = sni,       onSni    = { sni = it },
                wsHost = wsHost,    onWsHost = { wsHost = it },
                verifyTls = verifyTls, onVerifyTls = { verifyTls = it },
                onSave = {
                    val newCfg = VlessConfig(
                        server             = server.trim(),
                        port               = port.toIntOrNull() ?: 443,
                        uuid               = uuid.trim(),
                        path               = path.trim(),
                        sni                = sni.trim(),
                        wsHost             = wsHost.trim(),
                        rejectUnauthorized = !verifyTls,
                    )
                    VlessConfig.save(ctx, newCfg)
                    snackMsg = "Saved ✓"
                }
            )

            if (snackMsg.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text(snackMsg, color = Accent, fontSize = 13.sp,
                    modifier = Modifier.fillMaxWidth().wrapContentWidth())
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "Routing all traffic via VLESS/WS tunnel",
                color = TextSec, fontSize = 11.sp,
                modifier = Modifier.fillMaxWidth().wrapContentWidth()
            )
        }
    }
}

// ── 状态卡片 ──────────────────────────────────────────────────────────────────

@Composable
private fun StatusCard(
    status: String,
    bytesIn: Long,
    bytesOut: Long,
    onToggle: () -> Unit
) {
    val (statusText, statusColor) = when (status) {
        "CONNECTED"    -> "● Connected"    to GreenOk
        "CONNECTING"   -> "◌ Connecting…"  to OrangeWait
        "ERROR"        -> "✕ Error"        to RedErr
        else           -> "○ Disconnected" to TextSec
    }
    val btnText = if (status == "CONNECTED") "Disconnect" else "Connect"
    val btnColor = if (status == "CONNECTED") RedErr else Accent

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(24.dp)
        ) {
            Text(statusText, color = statusColor, fontSize = 18.sp, fontWeight = FontWeight.Medium)

            if (status == "CONNECTED") {
                Spacer(Modifier.height(6.dp))
                Text(
                    "↓ ${fmtBytes(bytesIn)}   ↑ ${fmtBytes(bytesOut)}",
                    color = TextSec, fontSize = 13.sp
                )
            }

            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onToggle,
                colors = ButtonDefaults.buttonColors(containerColor = btnColor),
                modifier = Modifier.width(200.dp).height(52.dp)
            ) {
                Text(btnText, fontSize = 16.sp)
            }
        }
    }
}

// ── 配置卡片 ──────────────────────────────────────────────────────────────────

@Composable
private fun ConfigCard(
    server: String,    onServer: (String) -> Unit,
    port: String,      onPort:   (String) -> Unit,
    uuid: String,      onUuid:   (String) -> Unit,
    path: String,      onPath:   (String) -> Unit,
    sni: String,       onSni:    (String) -> Unit,
    wsHost: String,    onWsHost: (String) -> Unit,
    verifyTls: Boolean,onVerifyTls: (Boolean) -> Unit,
    onSave: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Server Configuration", color = Accent,
                fontSize = 14.sp, fontWeight = FontWeight.Bold)

            Spacer(Modifier.height(12.dp))

            CfgField("Server Host",        server,  onServer)
            CfgField("Port",               port,    onPort, KeyboardType.Number)
            CfgField("UUID",               uuid,    onUuid)
            CfgField("WebSocket Path",     path,    onPath)
            CfgField("SNI",                sni,     onSni)
            CfgField("Host Header",        wsHost,  onWsHost)

            // TLS 验证开关
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Verify TLS Certificate",
                    color = Color(0xFFE8EAF0), fontSize = 14.sp,
                    modifier = Modifier.weight(1f))
                Switch(
                    checked = verifyTls,
                    onCheckedChange = onVerifyTls,
                    colors = SwitchDefaults.colors(checkedThumbColor = Accent)
                )
            }

            Spacer(Modifier.height(16.dp))
            OutlinedButton(
                onClick = onSave,
                modifier = Modifier.fillMaxWidth(),
                border = BorderStroke(1.dp, Accent),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent)
            ) {
                Text("Save Configuration")
            }
        }
    }
}

@Composable
private fun CfgField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    keyboardType: KeyboardType = KeyboardType.Uri
) {
    Text(label, color = TextSec, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor   = Accent,
            unfocusedBorderColor = Color(0xFF3A3F55),
            focusedTextColor     = Color(0xFFE8EAF0),
            unfocusedTextColor   = Color(0xFFE8EAF0),
            cursorColor          = Accent,
        ),
        modifier = Modifier.fillMaxWidth().padding(bottom = 2.dp)
    )
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

private fun fmtBytes(b: Long) = when {
    b < 1024L        -> "${b}B"
    b < 1048576L     -> "${"%.1f".format(b / 1024.0)}K"
    else             -> "${"%.1f".format(b / 1048576.0)}M"
}

private fun startVpn(ctx: Context) =
    ctx.startService(Intent(ctx, VlessVpnService::class.java).setAction(VlessVpnService.ACTION_START))

private fun stopVpn(ctx: Context) =
    ctx.startService(Intent(ctx, VlessVpnService::class.java).setAction(VlessVpnService.ACTION_STOP))
