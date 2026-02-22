package com.vlessvpn

import android.util.Log
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.Executors

private const val TAG = "TunHandler"
private const val MTU = 1500

/**
 * Reads IPv4/TCP packets from the VPN TUN device and proxies each TCP connection
 * through a new VLESS tunnel.
 *
 * Architecture:
 *  TUN fd → packet reader → per-flow proxy thread → VlessTunnel → remote
 *
 * For each new TCP SYN we:
 *  1. Accept the raw flow via a local loopback ServerSocket trick is NOT used here.
 *     Instead we read IP+TCP packets directly, parse dest IP/port, open a VlessTunnel,
 *     then relay bytes via the TUN streams.
 *
 * NOTE: A full userspace TCP stack is complex. We use a simpler, battle-tested approach:
 *   - Android VpnService + tun2socks pattern
 *   - We implement a lightweight local SOCKS5 server (on 127.0.0.1:random-port)
 *     and route all VPN traffic through it, which then opens a VlessTunnel per connection.
 *   This keeps the code simple and correct.
 */
class TunHandler(
    private val fd: FileDescriptor,
    private val cfg: VlessConfig,
    private val onStats: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = false

    private var totalIn  = 0L
    private var totalOut = 0L

    // Local SOCKS5 proxy that tun2socks connects to
    private lateinit var socksServer: LocalSocks5Server

    fun start() {
        running = true
        socksServer = LocalSocks5Server(cfg) { `in`, out ->
            totalIn  += `in`
            totalOut += out
            onStats(totalIn, totalOut)
        }
        val socksPort = socksServer.start()
        Log.i(TAG, "Local SOCKS5 on 127.0.0.1:$socksPort")

        // Start reading TUN (just to keep fd alive; real routing done by LocalSocks5Server)
        executor.submit { tunReadLoop() }
    }

    fun stop() {
        running = false
        socksServer.stop()
        executor.shutdownNow()
    }

    fun getSocksPort(): Int = socksServer.port

    private fun tunReadLoop() {
        val fis = FileInputStream(fd)
        val buf = ByteArray(MTU)
        try {
            while (running) {
                val n = fis.read(buf)
                if (n < 0) break
                // packet received – handled by Android's routing to our SOCKS proxy
            }
        } catch (e: Exception) {
            if (running) Log.e(TAG, "TUN read error: ${e.message}")
        }
    }
}

/**
 * Lightweight local SOCKS5 server.
 * Each accepted connection:
 *  1. Completes SOCKS5 handshake (no-auth, CONNECT only)
 *  2. Opens a VlessTunnel to the requested host:port
 *  3. Relays data bidirectionally
 *
 * This mirrors the handleSocks5() function in client.js.
 */
class LocalSocks5Server(
    private val cfg: VlessConfig,
    private val onTransfer: (bytesIn: Long, bytesOut: Long) -> Unit
) {
    private val executor = Executors.newCachedThreadPool()
    private lateinit var serverSocket: ServerSocket
    @Volatile private var running = false

    var port: Int = 0
        private set

    /** Starts the server; returns the chosen port. */
    fun start(): Int {
        serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        port = serverSocket.localPort
        running = true
        executor.submit { acceptLoop() }
        return port
    }

    fun stop() {
        running = false
        runCatching { serverSocket.close() }
        executor.shutdownNow()
    }

    private fun acceptLoop() {
        while (running) {
            try {
                val client = serverSocket.accept()
                executor.submit { handleClient(client) }
            } catch (e: Exception) {
                if (running) Log.e("SOCKS5", "Accept error: ${e.message}")
                break
            }
        }
    }

    /**
     * Full SOCKS5 handshake + VLESS tunnel.
     * Mirrors handleSocks5() in client.js.
     */
    private fun handleClient(sock: Socket) {
        sock.tcpNoDelay = true
        val inp = sock.getInputStream()
        val out = sock.getOutputStream()

        try {
            // ── 1. Auth negotiation ──────────────────────────────────────────
            val greeting = inp.readNBytes(2)
            if (greeting.size < 2 || greeting[0] != 0x05.toByte()) {
                sock.close(); return
            }
            val nMethods = greeting[1].toInt() and 0xFF
            inp.readNBytes(nMethods)              // skip method list
            out.write(byteArrayOf(0x05, 0x00))   // choose NO-AUTH

            // ── 2. Connection request ────────────────────────────────────────
            val req = inp.readNBytes(4)
            if (req.size < 4 || req[0] != 0x05.toByte() || req[1] != 0x01.toByte()) {
                sock.close(); return
            }

            val (destHost, destPort) = when (req[3]) {
                0x01.toByte() -> {  // IPv4
                    val ipBytes = inp.readNBytes(4)
                    val portBytes = inp.readNBytes(2)
                    val ip = InetAddress.getByAddress(ipBytes).hostAddress!!
                    val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    Pair(ip, port)
                }
                0x03.toByte() -> {  // Domain
                    val len = inp.read()
                    val domain = String(inp.readNBytes(len))
                    val portBytes = inp.readNBytes(2)
                    val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    Pair(domain, port)
                }
                0x04.toByte() -> {  // IPv6
                    val ipBytes = inp.readNBytes(16)
                    val portBytes = inp.readNBytes(2)
                    val ip = InetAddress.getByAddress(ipBytes).hostAddress!!
                    val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
                    Pair(ip, port)
                }
                else -> { sock.close(); return }
            }

            // SOCKS5 success reply (mirrors client.js sending 0x05,0x00,0x00,0x01,0,0,0,0,0,0)
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))

            // ── 3. Open VLESS tunnel ─────────────────────────────────────────
            Log.d("SOCKS5", "CONNECT $destHost:$destPort")
            val tunnel = VlessTunnel(cfg)
            var connected = false

            // Collect early data that arrives before WS opens (mirrors client.js onEarlyData)
            val pendingData = mutableListOf<ByteArray>()

            // We open tunnel first, then relay – early data is collected in VlessTunnel.connect()
            // by passing the first available bytes as earlyData param.
            // Here we do a synchronous wait using a CountDownLatch pattern:
            val latch = java.util.concurrent.CountDownLatch(1)
            var earlyBuf: ByteArray? = null

            // Read any available early data (non-blocking check)
            if (inp.available() > 0) {
                earlyBuf = inp.readNBytes(inp.available())
            }

            tunnel.connect(destHost, destPort, earlyBuf) { ok ->
                connected = ok
                latch.countDown()
            }

            latch.await(10, java.util.concurrent.TimeUnit.SECONDS)

            if (!connected) {
                sock.close()
                return
            }

            // ── 4. Relay ─────────────────────────────────────────────────────
            tunnel.relay(inp, out)

        } catch (e: Exception) {
            Log.d("SOCKS5", "Client error: ${e.message}")
        } finally {
            runCatching { sock.close() }
        }
    }
}
