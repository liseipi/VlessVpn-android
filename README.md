# VlessVPN

A lightweight Android VPN client that tunnels all device traffic through a [VLESS](https://github.com/xtls/xray-core) proxy over WebSocket transport.

## Architecture

```
┌──────────────┐
│  Android App │
└──────┬───────┘
       │ all traffic
       ▼
┌──────────────────────────────┐
│  TUN Interface               │
│  10.0.0.2/24   fd00::2/120   │
│  MTU 1500                    │
└──────┬───────────────────────┘
       │ raw IP packets
       ▼
┌──────────────────────────────┐
│  badvpn-tun2socks (native C) │
│  IP → SOCKS5 translation     │
└──────┬───────────────────────┘
       │ TCP / UDP
       ▼
┌──────────────────────────────┐
│  Local SOCKS5 Server         │
│  127.0.0.1 (random port)     │
│  CONNECT + UDP ASSOCIATE     │
└──────┬───────────────────────┘
       │ VLESS protocol
       ▼
┌──────────────────────────────┐
│  VlessTunnel                 │
│  OkHttp WebSocket            │
│  (VpnService.protect'd)      │
└──────┬───────────────────────┘
       │ WSS / WS
       ▼
┌──────────────────────────────┐
│  Remote VLESS Server         │
│  (Xray / V2Ray)              │
└──────────────────────────────┘
```

## Features

- **Full-device VPN** — all TCP and UDP traffic routed through the tunnel
- **VLESS v0 protocol** — lightweight, no encryption overhead (relies on TLS)
- **WebSocket transport** — compatible with CDNs, avoids traffic fingerprinting
- **IPv4 + IPv6** — dual-stack TUN interface with Happy Eyeballs support
- **SOCKS5 proxy** — local server with CONNECT (TCP) and UDP ASSOCIATE
- **DNS over tunnel** — all DNS queries proxied through the remote server
- **Multiple profiles** — import/export via VLESS URI with SharedPreferences persistence
- **Foreground service** — Android notification with connect/disconnect and live throughput stats
- **Dark theme UI** — Jetpack Compose with Material 3

## Prerequisites

- **Android Studio** (Hedgehog or later) with AGP 8.13+
- **JDK 17**
- **NDK** (for native tun2socks library — prebuilt `.a` files included for arm64-v8a, armeabi-v7a, x86, x86_64)
- **Gradle 9.2.1** (wrapper included)

## Build

```bash
# Debug build
./gradlew assembleDebug

# Release build
./gradlew assembleRelease
```

The release APK requires signing configuration in `app/build.gradle.kts`.

## Configuration

### VLESS URI Format

```
vless://<uuid>@<server>:<port>?encryption=none&security=tls&sni=<sni>&type=ws&host=<host>&path=<path>#<name>
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `uuid` | Yes | VLESS user UUID |
| `server` | Yes | Server hostname or IP |
| `port` | Yes | Server port (usually 443 for WSS) |
| `security` | No | `tls` for WSS, `none` for plain WS |
| `sni` | No | TLS SNI (defaults to server) |
| `host` | No | WebSocket Host header |
| `path` | No | WebSocket path (e.g. `/?ed=2560`) |
| `name` | No | Profile display name |

### Example

```
vless://55a95ae1-4ae8-4461-8484-457279821b40@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=/ws#My Server
```

## Project Structure

```
app/
├── src/main/java/com/musicses/vlessvpn/
│   ├── MainActivity.kt          # Compose UI, VPN lifecycle, config management
│   ├── VlessVpnService.kt       # VpnService foreground service, TUN setup
│   ├── VlessTunnel.kt           # VLESS-over-WebSocket tunnel, OkHttp client
│   ├── VlessProtocol.kt         # VLESS v0 wire protocol (header build/parse)
│   ├── VlessConfig.kt           # Config data model, VLESS URI import/export
│   ├── LocalSocks5Server.kt     # Local SOCKS5 proxy (CONNECT + UDP ASSOCIATE)
│   └── VlessDiagnostic.kt       # Diagnostic and testing utilities
├── src/main/res/
│   ├── values/strings.xml       # String resources
│   ├── values/colors.xml        # Dark theme color palette
│   └── xml/network_security_config.xml
└── proguard-rules.pro           # OkHttp/Okio keep rules

tun2socks/
├── src/main/java/com/musicses/vlessvpn/
│   └── Tun2Socks.java           # JNI bridge to badvpn-tun2socks
└── src/main/cpp/
    ├── tun2socks.cpp            # JNI implementation, logcat redirect
    ├── CMakeLists.txt           # Native build config
    └── prebuilt/                # Prebuilt static libraries + headers
        ├── include/tun2socks/tun2socks.h
        └── lib/<abi>/libtun2socks.a
```

## How It Works

1. **VPN Service starts** — creates a TUN interface (`10.0.0.2/24` + `fd00::2/120`) and routes all traffic (`0.0.0.0/0` + `::/0`) through it, excluding the app itself to prevent routing loops.

2. **tun2socks starts** — the native badvpn-tun2socks process reads raw IP packets from the TUN fd and translates them into SOCKS5 connections to a local server on `127.0.0.1`.

3. **SOCKS5 handles connections** — for TCP, it relays bytes through a VLESS tunnel. For UDP (DNS), it wraps packets in SOCKS5-UDP framing.

4. **VLESS tunnel** — each connection opens a WebSocket to the remote VLESS server. The first message is a VLESS protocol header (UUID + target address). Subsequent messages are raw TCP payload.

5. **Socket protection** — OkHttp sockets are `VpnService.protect()`'d so the tunnel's own traffic bypasses the TUN interface and goes directly to the network.

6. **DNS resolution** — the VLESS server's hostname is resolved via protected UDP sockets directly to `8.8.8.8`/`8.8.4.4`. All other DNS queries flow through the tunnel and are resolved by the remote server.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Kotlin, Java, C (JNI) |
| UI | Jetpack Compose, Material 3 |
| HTTP | OkHttp 4.12 |
| Tun2Socks | badvpn-tun2socks (native C) |
| Min SDK | 26 (Android 8.0) |
| Target SDK | 36 (Android 16) |

## Credits

- [badvpn](https://github.com/ambrop72/badvpn) — tun2socks implementation by Ambroz Bizjak
- [badvpn-android](https://github.com/mokhtarabadi/badvpn) — Android NDK adaptation by M. R. Mokhtarabadi
- [Xray-core](https://github.com/xtls/xray-core) — VLESS protocol specification
