# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / Test Commands

```bash
./gradlew assembleDebug          # Debug build
./gradlew assembleRelease        # Release build (needs signing config)
./gradlew test                   # Unit tests (placeholder)
./gradlew connectedAndroidTest   # Instrumentation tests (placeholder)
```

Run a single test class:
```bash
./gradlew app:testDebugUnitTest --tests com.musicses.vlessvpn.ExampleUnitTest
```

## Project Architecture

Two-module Gradle project: `app` (Android application, Kotlin/Compose) and `tun2socks` (Android library, Java + native C via JNI).

### Data flow (the key insight)

```
TUN iface → [badvpn-tun2socks native] → SOCKS5 localhost → VlessTunnel (WS) → remote server
```

All device traffic enters the TUN interface, is converted to SOCKS5 by the native tun2socks library, routed through a local SOCKS5 server on 127.0.0.1, then sent over WebSocket to the remote VLESS server. The WebSocket sockets are `VpnService.protect()`'d to avoid looping back into the TUN.

### Key classes and their roles

- **VlessVpnService** — extends `VpnService`. Creates the TUN, starts tun2socks + SOCKS5 + stats. Handles START/STOP/RECONNECT actions. All state guarded by `synchronized(lock)` or `AtomicBoolean`.
- **LocalSocks5Server** — SOCKS5 proxy with CONNECT (TCP) and UDP ASSOCIATE. ThreadPoolExecutor (core 4, max 256, LinkedBlockingQueue 128). Each connection spawns a `VlessTunnel`.
- **VlessTunnel** — OkHttp WebSocket to the remote server. `inQueue` (LinkedBlockingQueue, cap 4000) bridges WS messages to relay threads. Uses a shared OkHttpClient per VpnService instance (companion `getOrCreateClient` / `clearSharedClients`).
- **VlessProtocol** — builds 22+ byte VLESS v0 request header. First WS message is header + optional early data.
- **VlessConfig** — data class + `ConfigStore` object for SharedPreferences persistence. `dns1`/`dns2` are pushed into the TUN builder.

### DNS: two code paths

1. **Server hostname** → `ProtectedDns` inside VlessTunnel resolves via VpnService-protected UDP sockets to 8.8.8.8/8.8.4.4 (parallel, first reply wins). Cached globally across sessions.
2. **All other hostnames** → `Dns.SYSTEM.lookup()` → goes through TUN → SOCKS5 UDP ASSOCIATE → remote server resolves.

### TUN configuration

- IPv4: `10.0.0.2/24`, gateway `10.0.0.1`, netmask `255.255.255.0`
- IPv6: `fd00::2/120`, gateway `fd00::1`
- Routes: `0.0.0.0/0` + `::/0` (all traffic)
- MTU: 1500
- DNS servers from active config (`cfg.dns1`, `cfg.dns2`)
- App's own traffic excluded via `addDisallowedApplication(packageName)`

### tun2socks native module

JNI bridge in `Tun2Socks.java` → `tun2socks.cpp` → `libtun2socks.a` (prebuilt for arm64-v8a, armeabi-v7a, x86, x86_64). The C++ code redirects stdout/stderr to logcat via pipes. Built with CMake, C++11, static C++ runtime.

### OkHttp client construction

One shared OkHttpClient per VpnService instance. Trust-all SSL (`X509TrustManager`) unless `rejectUnauthorized == true`. Custom `SocketFactory` wraps the default factory and calls `vpnService.protect(socket)` on every created socket. Shared client is cleared on stop via `clearSharedClients()`.

### Reconnect flow

`ACTION_RECONNECT` → sets `userStopped = false` → refreshes foreground notification → `fullStop()` → 200ms sleep → `fullStart()`. This re-resolves the server IP and rebuilds the OkHttpClient.

## Constraints to know

- `VpnService.prepare()` must be called before starting the VPN; the UI handles this via `ActivityResultContracts`.
- `startForeground()` on API 34+ requires `FOREGROUND_SERVICE_TYPE_SPECIAL_USE`.
- The `tun2socks` library's `namespace` in its manifest is `com.londonx.tun2socks` but the Java class lives in `com.musicses.vlessvpn` (the app's package).
- Release builds have minification disabled (`isMinifyEnabled = false`). ProGuard rules exist for OkHttp but are not currently exercised.
- The C++ `start_redirecting_stdout_stderr()` is called on every `startTun2Socks()` invocation. It creates new pipes and threads each time.
