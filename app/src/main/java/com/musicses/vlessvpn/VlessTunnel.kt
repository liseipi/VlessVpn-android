package com.musicses.vlessvpn

import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.*

private const val TAG = "VlessTunnel"

/**
 * 单条 VLESS-over-WebSocket 隧道。
 *
 * 对应 client.js：
 *   openTunnel()   → connect()
 *   relay()        → relay()
 *   首包合并逻辑    → connect() 中的 earlyData 参数
 */
class VlessTunnel(private val cfg: VlessConfig) {

    private var ws: WebSocket? = null

    // WS 入站数据队列；null 表示 EOF
    private val inQueue = LinkedBlockingQueue<ByteArray?>()
    private var firstMsg = true

    // ── 建立连接 ──────────────────────────────────────────────────────────────

    /**
     * 建立 WS 并发送 VLESS 头（+ 可选的早期数据）。
     *
     * 对应 client.js：
     *   openTunnel() 回调后立即执行 ws.send(vlessHdr + pendingData)
     *
     * @param destHost  目标主机
     * @param destPort  目标端口
     * @param earlyData 在 WS 建立期间已到达的数据（早期数据），可为 null
     * @param onResult  true=成功，false=失败
     */
    fun connect(
        destHost: String,
        destPort: Int,
        earlyData: ByteArray? = null,
        onResult: (Boolean) -> Unit
    ) {
        val client = buildClient()

        val req = Request.Builder()
            .url(cfg.wsUrl)
            .header("Host",          cfg.wsHost)
            .header("User-Agent",    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .header("Cache-Control", "no-cache")
            .header("Pragma",        "no-cache")
            .build()

        var resultSent = false

        client.newWebSocket(req, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                ws = webSocket
                // 首包合并：VLESS 头 + 早期数据  （对应 client.js 的 firstPkt = Buffer.concat([vlessHdr, ...pending])）
                val header = VlessProtocol.buildHeader(cfg.uuid, destHost, destPort)
                val firstPkt = if (!earlyData.isNullOrEmpty()) header + earlyData else header
                webSocket.send(firstPkt.toByteString())

                if (!resultSent) { resultSent = true; onResult(true) }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                inQueue.put(bytes.toByteArray())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                inQueue.put(text.toByteArray(Charsets.UTF_8))
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                inQueue.put(null); webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                inQueue.put(null)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "WS failure: ${t.message}")
                inQueue.put(null)
                if (!resultSent) { resultSent = true; onResult(false) }
            }
        })
    }

    // ── 双向中继 ──────────────────────────────────────────────────────────────

    /**
     * 将 [localIn]/[localOut] 与 WS 隧道双向中继，直到任意一端关闭。
     *
     * 对应 client.js relay()：
     *  - WS → local：首帧跳过前 2 字节（VLESS 响应头）
     *  - local → WS：直接 ws.send(data)
     */
    fun relay(localIn: InputStream, localOut: OutputStream) {
        // 线程1：WS → local（消费 inQueue）
        val t1 = Thread {
            try {
                while (true) {
                    val chunk = inQueue.poll(30, TimeUnit.SECONDS) ?: break
                    val payload = if (firstMsg) {
                        firstMsg = false
                        VlessProtocol.stripResponseHeader(chunk)  // 跳过 2 字节响应头
                    } else chunk
                    if (payload.isNotEmpty()) localOut.write(payload)
                }
            } catch (e: Exception) {
                Log.d(TAG, "WS→local: ${e.message}")
            } finally {
                runCatching { localOut.close() }
                ws?.cancel()
            }
        }

        // 线程2：local → WS
        val t2 = Thread {
            try {
                val buf = ByteArray(8192)
                while (true) {
                    val n = localIn.read(buf)
                    if (n < 0) break
                    ws?.send(buf.copyOf(n).toByteString())
                }
            } catch (e: Exception) {
                Log.d(TAG, "local→WS: ${e.message}")
            } finally {
                inQueue.put(null)
                ws?.close(1000, null)
            }
        }

        t1.isDaemon = true; t2.isDaemon = true
        t1.start();         t2.start()
        t1.join();          t2.join()
    }

    fun close() {
        ws?.cancel()
        inQueue.put(null)
    }

    // ── OkHttp 客户端（支持跳过 TLS 验证） ────────────────────────────────────

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0,  TimeUnit.SECONDS)   // 流式，不超时
            .writeTimeout(10, TimeUnit.SECONDS)

        if (!cfg.rejectUnauthorized) {
            // 对应 client.js rejectUnauthorized: false
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
                override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val sc = SSLContext.getInstance("TLS").also {
                it.init(null, arrayOf(trustAll), SecureRandom())
            }
            builder.sslSocketFactory(sc.socketFactory, trustAll)
            builder.hostnameVerifier { _, _ -> true }
        }

        return builder.build()
    }
}
