# VlessVPN - Android VLESS+WebSocket VPN

基于 VLESS + WebSocket + tun2socks 的 Android VPN 应用，使用 Kotlin 开发。

---

## 项目结构

```
VlessVPN/
├── app/                          # 主应用模块（Kotlin）
│   └── src/main/java/com/vlessvpn/
│       ├── VlessVpnApp.kt        # Application 类
│       ├── model/
│       │   └── VlessConfig.kt    # VLESS 配置数据模型 + URI 解析
│       ├── util/
│       │   ├── ConfigManager.kt  # 配置持久化（SharedPreferences）
│       │   └── VpnStateManager.kt # VPN 状态 LiveData
│       ├── service/
│       │   ├── VlessVpnService.kt # Android VpnService（串联 tun2socks）
│       │   └── LocalProxyServer.kt # 本地 SOCKS5 代理（VLESS WebSocket 隧道）
│       ├── ui/
│       │   ├── MainActivity.kt    # 主界面（连接/断开）
│       │   ├── AddConfigActivity.kt # 添加/编辑配置
│       │   └── ConfigListActivity.kt # 服务器列表
│       └── viewmodel/
│           └── MainViewModel.kt
│
└── tun2socks/                    # tun2socks 原生库模块
    └── src/main/
        ├── java/com/musicses/vlessvpn/Tun2Socks.java  # JNI Java 包装
        └── cpp/
            ├── tun2socks.cpp     # JNI 桥接
            ├── CMakeLists.txt
            └── prebuilt/
                ├── include/tun2socks/tun2socks.h
                └── lib/
                    ├── arm64-v8a/libtun2socks.a   ← 需要你放入
                    ├── armeabi-v7a/libtun2socks.a ← 需要你放入
                    ├── x86/libtun2socks.a         ← 需要你放入
                    └── x86_64/libtun2socks.a      ← 需要你放入
```

---

## 构建前必须完成的步骤

### 1. 放入 libtun2socks.a 静态库

将你已有的 `.a` 文件复制到对应架构目录：

```bash
tun2socks/src/main/cpp/prebuilt/lib/arm64-v8a/libtun2socks.a
tun2socks/src/main/cpp/prebuilt/lib/armeabi-v7a/libtun2socks.a
tun2socks/src/main/cpp/prebuilt/lib/x86/libtun2socks.a
tun2socks/src/main/cpp/prebuilt/lib/x86_64/libtun2socks.a
```

如果你只有 arm64-v8a 版本，可以先只放这一个，然后修改 `tun2socks/build.gradle`：

```gradle
ndk {
    abiFilters 'arm64-v8a'   // 只保留有 .a 文件的架构
}
```

### 2. 构建

```bash
./gradlew assembleDebug
# 或
./gradlew assembleRelease
```

---

## 使用方法

### 导入配置

**方法一：剪贴板导入（最快）**
1. 复制 `vless://...` 链接
2. 打开 App，点击「从剪贴板导入 VLESS 链接」

**方法二：URI Scheme**
在浏览器地址栏打开 `vless://uuid@host:port?...` 即可自动跳转导入

**方法三：手动填写**
点击右上角 `+` → 填写各字段 → 保存

### 连接

1. 确保已选择一个配置（服务器卡片显示服务器名称）
2. 点击「连接」按钮
3. 首次使用需授权 VPN 权限

---

## 技术架构

```
Android App
    │
    ├── VlessVpnService（Android VpnService）
    │       │
    │       ├── 创建 TUN 虚拟网卡接口
    │       └── 启动 tun2socks（处理 TUN 流量 → SOCKS5）
    │
    └── LocalProxyServer（本地 SOCKS5 服务器，127.0.0.1:1099）
            │
            └── 每个连接：手动 HTTP Upgrade → WebSocket
                    │
                    └── VLESS 协议封装 → 远端服务器
```

### 与 client.js 的对应关系

| client.js | Kotlin 实现 |
|---|---|
| `buildVlessHeader()` | `LocalProxyServer.buildVlessHeader()` |
| `buildWsUrl()` | `VlessConfig.buildWsUrl()` |
| `new WebSocket(url, {...})` | 手动 HTTP Upgrade（`openTunnel()`） |
| `relay()` + VLESS 响应头跳过 | `LocalProxyServer.relay()` |
| `handleSocks5()` | `LocalProxyServer.handleSocks5()` |
| `rejectUnauthorized: false` | 自定义 `TrustManager` 信任所有证书 |

### VLESS 响应头解析

与 client.js 完全一致：
```
byte[0] = version
byte[1] = addon_len
总头长  = 2 + addon_len
```

---

## 支持的 VLESS 链接格式

```
vless://UUID@HOST:PORT?encryption=none&security=tls&sni=SNI&type=ws&host=WS_HOST&path=WS_PATH#REMARK
```

示例：
```
vless://7e409f0a-745d-485b-9546-a7a38ac2f20b@vs.musicses.vip:443?encryption=none&security=tls&sni=vs.musicses.vip&type=ws&host=vs.musicses.vip&path=/?ed=2560#vs.musicses.vip
```

---

## 常见问题

**Q: 连接后网络不通？**
- 检查服务器地址、UUID、端口是否正确
- 确认 TLS 设置与服务器一致（port 443 自动启用 TLS）
- 查看 logcat 过滤 `LocalProxy` 标签

**Q: 只有 arm64-v8a 的 .a 文件怎么办？**
- 修改 `tun2socks/build.gradle` 中 `abiFilters` 只保留 `'arm64-v8a'`
- 现代设备（2018年后）基本都是 arm64-v8a

**Q: 如何调试连接问题？**
```bash
adb logcat -s LocalProxy VlessVpnService tun2socks
```
