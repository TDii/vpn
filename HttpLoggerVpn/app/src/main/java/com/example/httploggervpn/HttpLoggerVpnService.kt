package com.example.httploggervpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log // 临时用于日志
import com.example.httploggervpn.R // 用于 R.string.app_name
import java.io.FileInputStream // 现在需要
import java.io.FileOutputStream // 虽然没用上，但保持导入为后续可能扩展
import java.io.IOException // For try-catch block in worker thread
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.os.Build
import androidx.core.app.NotificationCompat

class HttpLoggerVpnService : VpnService() {

    private val NOTIFICATION_CHANNEL_ID = "HttpLoggerVpnChannel"
    private val NOTIFICATION_ID = 1

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnWorkerThread: Thread? = null

    companion object {
        const val ACTION_CONNECT = "com.example.httploggervpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.httploggervpn.DISCONNECT"
        var isRunning: Boolean = false
            private set // Only allow modification within this class

        fun startVpnService(context: Context) {
            val intent = Intent(context, HttpLoggerVpnService::class.java).setAction(ACTION_CONNECT)
            context.startService(intent)
        }

        fun stopVpnService(context: Context) {
            val intent = Intent(context, HttpLoggerVpnService::class.java).setAction(ACTION_DISCONNECT)
            context.startService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "HTTP Logger VPN Service Channel",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null // 通常 VPN 服务不直接绑定，返回 null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let { action ->
            when (action) {
                ACTION_CONNECT -> {
                    if (!isRunning) {
                        startVpn()
                    }
                }
                ACTION_DISCONNECT -> {
                    if (isRunning) {
                        stopVpn()
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        // VpnService.prepare() 应该在 Activity 中调用，这里我们先假设权限已授予
        // 在实际应用中，你需要从 Activity 获取权限结果
        if (prepare(this) == null) {
            // 权限已授予或不需要
            vpnInterface = Builder()
                .setSession(getString(R.string.app_name)) // 需要在 strings.xml 中定义 app_name
                .addAddress("10.0.0.2", 24) // 虚拟 IP 地址
                .addRoute("0.0.0.0", 0)    // 捕获所有 IPv4 流量
                // .addDnsServer("8.8.8.8") // 可选的 DNS 服务器
                .establish()

            if (vpnInterface == null) {
                // 连接建立失败，可能的原因包括权限问题或配置错误
                Log.e("HttpLoggerVpnService", "Failed to establish VPN interface.")
                stopSelf() // 停止服务
                return
            }

            isRunning = true
            Log.i("HttpLoggerVpnService", "VPN Service started successfully.")

            // Start Foreground Service
            val notificationIntent = Intent(this, MainActivity::class.java) // Intent to open when notification is tapped
            val pendingIntentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
            val pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, pendingIntentFlags)

            val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("HttpLoggerVpn Active")
                .setContentText("VPN service is running to log HTTP requests.")
                .setSmallIcon(R.drawable.ic_launcher_foreground) // Replace with a proper icon
                .setContentIntent(pendingIntent)
                .build()
            startForeground(NOTIFICATION_ID, notification)

            // start vpnWorkerThread as before
            vpnWorkerThread = Thread {
                Log.i("HttpLoggerVpnService", "VPN worker thread started.")
                val inputStream = ParcelFileDescriptor.AutoCloseInputStream(vpnInterface)
                // We don't write back to the VPN output stream in this logger
                // val outputStream = ParcelFileDescriptor.AutoCloseOutputStream(vpnInterface)
                val buffer = ByteArray(32767)

                while (isRunning && !Thread.currentThread().isInterrupted) {
                    try {
                        val length = inputStream.read(buffer)
                        if (length > 0) {
                            parseAndLogHttpRequest(buffer, length)
                            // To make the device actually connect to the internet,
                            // the packet needs to be sent to its actual destination.
                            // This VPN service, as currently designed, only logs.
                            // If you wanted to allow traffic, you'd need to:
                            // 1. Protect the socket used for sending from the VPN itself.
                            // 2. Create a raw socket or use a DatagramChannel/SocketChannel
                            //    to send the IP packet to its original destination.
                            // outputStream.write(buffer, 0, length) // This would just loop back
                        } else if (length == -1) {
                            Log.i("HttpLoggerVpnService", "VPN input stream closed (EOF).")
                            // This can happen if the VPN is externally disconnected or if an error occurs.
                            // Consider whether to attempt a reconnect or just stop.
                            // For now, we'll let the loop condition handle it or an external stopVpn call.
                            // isRunning = false // Option: stop if EOF
                        }
                    } catch (e: IOException) {
                        if (isRunning) { // Only log if we expect to be running
                            Log.e("HttpLoggerVpnService", "VPN worker thread IO error", e)
                        }
                        // Depending on the error, might want to stopVpn() or break
                        break // Exit loop on IO error
                    } catch (e: Exception) {
                        Log.e("HttpLoggerVpnService", "VPN worker thread error", e)
                        break // Exit loop on other errors
                    }
                }
                Log.i("HttpLoggerVpnService", "VPN worker thread stopping.")
            }.apply {
                name = "HttpLoggerVpnWorker" // 给线程命名，方便调试
                start()
            }

            // 通知系统 VPN 已连接 (如果需要显示状态图标)
            // val notification = ... (创建 Notification)
            // startForeground(1, notification)

        } else {
            // 需要用户授权，Activity 应该处理 VpnService.prepare() 返回的 Intent
            Log.e("HttpLoggerVpnService", "VPN permission not granted or VpnService.prepare failed.")
            stopSelf() // 如果没有权限，服务无法运行
        }
    }

    private fun stopVpn() {
        Log.i("HttpLoggerVpnService", "Stopping VPN Service.")
        isRunning = false // Set early to stop loops

        vpnWorkerThread?.interrupt()
        try {
            vpnWorkerThread?.join(1000) // Wait for thread to die
        } catch (e: InterruptedException) {
            Log.w("HttpLoggerVpnService", "Interrupted while waiting for worker thread to join.", e)
            Thread.currentThread().interrupt() // Preserve interrupt status
        }
        vpnWorkerThread = null

        try {
            vpnInterface?.close()
            Log.d("HttpLoggerVpnService", "VPN interface closed.")
        } catch (e: java.io.IOException) {
            Log.e("HttpLoggerVpnService", "Error closing VPN interface", e)
        }
        vpnInterface = null

        stopForeground(true) // true = remove notification
        stopSelf() // Stop the service itself
        Log.i("HttpLoggerVpnService", "VPN Service stopped.")
    }

    override fun onRevoke() {
        Log.w("HttpLoggerVpnService", "VPN permission revoked by user or system.")
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        Log.i("HttpLoggerVpnService", "VPN Service Destroyed")
        stopVpn()
        super.onDestroy()
    }

    private fun parseAndLogHttpRequest(packet: ByteArray, length: Int) {
        if (length < 20) return // IP header min length

        // IPv4 Check (version and header length)
        val version = packet[0].toInt() shr 4
        if (version != 4) return // Not IPv4
        val ipHeaderLength = (packet[0].toInt() and 0x0F) * 4
        if (length < ipHeaderLength) return // Packet too short for IP header

        // Protocol Check (TCP is 6)
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 6) return // Not TCP

        val sourceIp = packetToIp(packet, 12)
        val destIp = packetToIp(packet, 16)

        // TCP Header (starts after IP header)
        if (length < ipHeaderLength + 20) return // TCP header min length
        val tcpOffset = ipHeaderLength
        val sourcePort = bytesToShort(packet[tcpOffset], packet[tcpOffset + 1]).toInt() and 0xFFFF
        val destPort = bytesToShort(packet[tcpOffset + 2], packet[tcpOffset + 3]).toInt() and 0xFFFF

        if (destPort != 80) return // Simplification: only standard HTTP port

        val tcpHeaderLength = ((packet[tcpOffset + 12].toInt() and 0xF0) shr 4) * 4
        val payloadOffset = tcpOffset + tcpHeaderLength

        if (payloadOffset >= length) return // No payload

        try {
            val payload = String(packet, payloadOffset, length - payloadOffset, Charsets.UTF_8)

            // Basic HTTP Request Line Parsing
            val requestLineEnd = payload.indexOf("\r\n")
            if (requestLineEnd == -1) return
            val requestLine = payload.substring(0, requestLineEnd)

            val parts = requestLine.split(" ")
            if (parts.size < 2) return // Expecting METHOD URI (VERSION is optional for parsing)
            val method = parts[0]
            val uri = parts[1]
            // val httpVersion = if (parts.size > 2) parts[2] else "HTTP/1.0" // Optional

            val httpMethods = listOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH")
            if (!httpMethods.any { method.equals(it, ignoreCase = true) }) {
                return // Not a standard HTTP method or malformed
            }

            // Basic Header Parsing (Host and User-Agent)
            var host = "N/A"
            var userAgent = "N/A"

            val headersPartStart = requestLineEnd + 2 // +2 for \r\n
            if (headersPartStart >= payload.length) return // No headers part

            val headersPart = payload.substring(headersPartStart)

            headersPart.lines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.startsWith("Host:", ignoreCase = true)) {
                    host = trimmedLine.substring("Host:".length).trim()
                } else if (trimmedLine.startsWith("User-Agent:", ignoreCase = true)) {
                    userAgent = trimmedLine.substring("User-Agent:".length).trim()
                }
                if (trimmedLine.isEmpty()) return@forEach // End of headers is marked by an empty line after CRLF
            }

            Log.i("HttpLogger", "HTTP Request: $sourceIp:$sourcePort -> $destIp:$destPort | $method $uri | Host: $host | User-Agent: $userAgent")
        } catch (e: Exception) {
            // Log.e("HttpLogger", "Error parsing HTTP payload", e) // Avoid log spam for non-HTTP or malformed
        }
    }

    private fun packetToIp(packet: ByteArray, offset: Int): String {
        if (offset + 4 > packet.size) return "InvalidIP"
        return "${packet[offset].toInt() and 0xFF}.${packet[offset + 1].toInt() and 0xFF}.${packet[offset + 2].toInt() and 0xFF}.${packet[offset + 3].toInt() and 0xFF}"
    }

    private fun bytesToShort(b1: Byte, b2: Byte): Short {
        return ((b1.toInt() and 0xFF shl 8) or (b2.toInt() and 0xFF)).toShort()
    }
}
