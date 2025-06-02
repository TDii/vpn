package com.example.httploggervpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder // Needed for buildIpTcpPacket
import java.nio.channels.DatagramChannel
import java.nio.channels.FileChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.channels.ClosedSelectorException
import java.util.concurrent.ConcurrentHashMap
import java.util.Random

enum class SessionStatus {
    SYN_RECEIVED,
    CONNECTING_TO_SERVER,
    CONNECTED_TO_SERVER,
    SYN_ACK_SENT_TO_CLIENT,
    ESTABLISHED,
    CLIENT_FIN_RECEIVED,    // Client sent FIN, VPN ACKed, VPN processing/sent FIN to Server
    SERVER_FIN_RECEIVED,    // Server sent FIN (EOF), VPN ACKed, VPN processing/sent FIN to Client
    LAST_ACK_FROM_CLIENT,   // VPN sent FIN to client, waiting for client's final ACK
    LAST_ACK_FROM_SERVER,   // VPN sent FIN to server, waiting for server's final ACK
    TIME_WAIT,              // (Optional, for active closer)
    CLOSING,                // General closing state if more specific not used
    CLOSED
}

data class VpnSession(
    val sessionKey: String,
    val clientIp: InetAddress,
    val clientPort: Int,
    val remoteIp: InetAddress,
    val remotePort: Int,

    var clientInitialSequenceNumber: Long = 0,    // ISN from client's SYN packet
    var vpnServerInitialSequenceNumber: Long = 0, // ISN in SYN-ACK from VPN to Client

    var vpnNextSeqToClient: Long = 0,
    var vpnExpectedAckFromClient: Long = 0,
    var vpnNextSeqToServer: Long = 0,
    var vpnExpectedAckFromServer: Long = 0,

    var serverSocketChannel: SocketChannel? = null,
    var serverSelectionKey: SelectionKey? = null,
    var status: SessionStatus = SessionStatus.SYN_RECEIVED,
    var creationTime: Long = System.currentTimeMillis(),
    var lastActivityTime: Long = System.currentTimeMillis(),
    var closingInitiator: String? = null,
    var clientSentFin: Boolean = false,
    var serverSentFin: Boolean = false,
    var vpnSentFinToClient: Boolean = false,
    var vpnSentFinToServer: Boolean = false,
    var vpnFinToClientAckedByClient: Boolean = false,
    var vpnFinToServerAckedByServer: Boolean = false
) {
    fun initializeSequenceNumbersAfterClientAckToOurSynAck(clientAckPacketSeqNum: Long) {
        vpnNextSeqToClient = vpnServerInitialSequenceNumber + 1
        vpnExpectedAckFromClient = clientInitialSequenceNumber + 1
        vpnNextSeqToServer = clientInitialSequenceNumber + 1
        vpnExpectedAckFromServer = 0
        Log.d("VpnSession", "Session $sessionKey initialized seq numbers: "+
                "vpnNextSeqToClient=$vpnNextSeqToClient, vpnExpectedAckFromClient=$vpnExpectedAckFromClient, "+
                "vpnNextSeqToServer=$vpnNextSeqToServer, vpnExpectedAckFromServer=$vpnExpectedAckFromServer")
    }
}

object PacketUtil {
    const val IPPROTO_TCP: Byte = 6
    const val TCP_FIN_FLAG: Byte = 0x01
    const val TCP_SYN_FLAG: Byte = 0x02
    const val TCP_RST_FLAG: Byte = 0x04
    const val TCP_PSH_FLAG: Byte = 0x08
    const val TCP_ACK_FLAG: Byte = 0x10
    const val TCP_URG_FLAG: Byte = 0x20

    fun buildIpTcpPacket(
        sourceIp: InetAddress,
        destinationIp: InetAddress,
        sourcePort: Short,
        destinationPort: Short,
        sequenceNumber: Long, // 32-bit
        acknowledgementNumber: Long, // 32-bit
        tcpFlags: Byte,
        windowSize: Short,
        payload: ByteArray, // Can be empty: ByteArray(0)
        ipId: Short = (Random().nextInt(0xFFFF + 1)).toShort(),
        ttl: Byte = 64
    ): ByteArray {
        val ipHeaderLength = 20
        val tcpHeaderLength = 20 // No TCP options for simplicity
        val payloadLength = payload.size
        val totalIpLength = ipHeaderLength + tcpHeaderLength + payloadLength

        val buffer = ByteBuffer.allocate(totalIpLength)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // IP Header
        val totalLengthPosition: Int // To store position for later update
        val ipChecksumPosition: Int

        buffer.put(0x45.toByte()) // Version (4), IHL (5)
        buffer.put(0x00.toByte()) // DSCP (0), ECN (0)
        totalLengthPosition = buffer.position()
        buffer.putShort(0.toShort()) // Placeholder for Total Length
        buffer.putShort(ipId)       // Identification
        buffer.putShort(0x4000.toShort()) // Flags (Don't Fragment), Fragment Offset (0)
        buffer.put(ttl)           // Time To Live
        buffer.put(IPPROTO_TCP)   // Protocol (TCP)
        ipChecksumPosition = buffer.position()
        buffer.putShort(0.toShort()) // Placeholder for IP Header Checksum
        buffer.put(sourceIp.address)
        buffer.put(destinationIp.address)
        // Assert buffer.position() == ipHeaderLength

        // TCP Header
        val tcpHeaderStartPosition = buffer.position()
        val tcpChecksumPosition: Int

        buffer.putShort(sourcePort)
        buffer.putShort(destinationPort)
        buffer.putInt(sequenceNumber.toInt())
        buffer.putInt(acknowledgementNumber.toInt())
        buffer.put(((tcpHeaderLength / 4) shl 4).toByte()) // Data Offset (5 words), Reserved (000), NS (0)
        buffer.put(tcpFlags)      // Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
        buffer.putShort(windowSize)
        tcpChecksumPosition = buffer.position()
        buffer.putShort(0.toShort()) // Placeholder for TCP Checksum
        buffer.putShort(0.toShort()) // Urgent Pointer
        // Assert buffer.position() == tcpHeaderStartPosition + tcpHeaderLength

        // Payload
        if (payload.isNotEmpty()) {
            buffer.put(payload)
        }
        // Assert buffer.position() == totalIpLength

        // Fill in Total Length in IP Header
        buffer.putShort(totalLengthPosition, totalIpLength.toShort())

        // Calculate IP Header Checksum
        buffer.putShort(ipChecksumPosition, 0.toShort()) // Zero out checksum field for calculation
        val ipChecksum = calculateGenericChecksumInternal(buffer.duplicate(), 0, ipHeaderLength) // Use duplicate to not alter original buffer's pos/limit for this read
        buffer.putShort(ipChecksumPosition, ipChecksum)

        // Calculate TCP Checksum
        buffer.putShort(tcpChecksumPosition, 0.toShort()) // Zero out TCP checksum field
        val tcpSegmentLength = tcpHeaderLength + payloadLength
        val pseudoHeaderAndTcpSegment = ByteBuffer.allocate(12 + tcpSegmentLength)
        pseudoHeaderAndTcpSegment.order(ByteOrder.BIG_ENDIAN)
        pseudoHeaderAndTcpSegment.put(sourceIp.address)
        pseudoHeaderAndTcpSegment.put(destinationIp.address)
        pseudoHeaderAndTcpSegment.put(0.toByte()) // Reserved zero byte
        pseudoHeaderAndTcpSegment.put(IPPROTO_TCP) // Protocol
        pseudoHeaderAndTcpSegment.putShort(tcpSegmentLength.toShort())

        // Copy TCP header and payload from main buffer to checksum calculation buffer
        val mainBufferDuplicate = buffer.duplicate() // Use a duplicate to read from main buffer
        mainBufferDuplicate.position(tcpHeaderStartPosition)
        mainBufferDuplicate.limit(tcpHeaderStartPosition + tcpSegmentLength) // Limit to TCP header + payload
        pseudoHeaderAndTcpSegment.put(mainBufferDuplicate)
        pseudoHeaderAndTcpSegment.flip()

        val tcpChecksum = calculateGenericChecksumInternal(pseudoHeaderAndTcpSegment, 0, pseudoHeaderAndTcpSegment.limit())
        buffer.putShort(tcpChecksumPosition, tcpChecksum)

        // Finalize
        val finalPacket = ByteArray(totalIpLength)
        buffer.rewind()
        buffer.get(finalPacket, 0, totalIpLength)
        return finalPacket
    }

    internal fun calculateGenericChecksumInternal(buffer: ByteBuffer, start: Int, length: Int): Short {
        var sum = 0
        // Create a duplicate to avoid modifying the original buffer's position and limit,
        // especially if the original buffer is the main packet buffer being modified elsewhere.
        val duplicateBuffer = buffer.duplicate()
        duplicateBuffer.position(start)
        duplicateBuffer.limit(start + length)

        var count = length
        while (count > 1) {
            sum += (duplicateBuffer.getShort().toInt() and 0xFFFF)
            count -= 2
        }
        if (count > 0) { sum += ((duplicateBuffer.get().toInt() and 0xFF) shl 8) }

        while ((sum shr 16) > 0) { sum = (sum and 0xFFFF) + (sum shr 16) }
        return sum.inv().toShort()
    }
}

class HttpLoggerVpnService : VpnService() {
        val originalLimit = buffer.limit()
        buffer.position(start)
        buffer.limit(start + length)
        var count = length
        while (count > 1) {
            sum += (buffer.getShort().toInt() and 0xFFFF)
            count -= 2
        }
        if (count > 0) { sum += ((buffer.get().toInt() and 0xFF) shl 8) }
        buffer.position(originalPosition)
        buffer.limit(originalLimit)
        while ((sum shr 16) > 0) { sum = (sum and 0xFFFF) + (sum shr 16) }
        return sum.inv().toShort()
    }
}

class HttpLoggerVpnService : VpnService() {

    private val NOTIFICATION_CHANNEL_ID = "HttpLoggerVpnChannel"
    private val NOTIFICATION_ID = 1

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnWorkerThread: Thread? = null
    private var selector: Selector? = null
    private val sessions: ConcurrentHashMap<String, VpnSession> = ConcurrentHashMap()
    private var vpnInputChannel: FileChannel? = null
    private var vpnOutputStream: ParcelFileDescriptor.AutoCloseOutputStream? = null

    companion object { /* ... companion object content from previous state ... */
        const val ACTION_CONNECT = "com.example.httploggervpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.httploggervpn.DISCONNECT"
        var isRunning: Boolean = false
            private set
        fun startVpnService(context: Context) {
            val intent = Intent(context, HttpLoggerVpnService::class.java).setAction(ACTION_CONNECT)
            context.startService(intent)
        }
        fun stopVpnService(context: Context) {
            val intent = Intent(context, HttpLoggerVpnService::class.java).setAction(ACTION_DISCONNECT)
            context.startService(intent)
        }
    }

    override fun onCreate() { super.onCreate(); createNotificationChannel() }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID, "HTTP Logger VPN Service Channel",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(serviceChannel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.action?.let {
            when (it) {
                ACTION_CONNECT -> if (!isRunning) startVpn()
                ACTION_DISCONNECT -> if (isRunning) stopVpn()
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (prepare(this) == null) {
            vpnInterface = Builder()
                .setSession(getString(R.string.app_name))
                .addAddress("10.0.0.2", 24)
                .apply {
                    try { addAllowedApplication("mark.via") } catch (e: PackageManager.NameNotFoundException) {
                        Log.e("HttpLoggerVpnService", "Allowed app 'mark.via' not found.", e) }
                }
                .establish()

            if (vpnInterface == null) { Log.e("HttpLoggerVpnService", "Failed to establish VPN."); stopSelf(); return }
            Log.i("HttpLoggerVpnService", "VPN interface established.")
            isRunning = true
            try { selector = Selector.open() } catch (e: IOException) { Log.e("HttpLoggerVpnService", "Selector open failed", e); stopVpn(); return }

            val localVpnInterface = vpnInterface ?: run { stopVpn(); return }
            vpnInputChannel = FileInputStream(localVpnInterface.fileDescriptor).channel
            vpnOutputStream = ParcelFileDescriptor.AutoCloseOutputStream(localVpnInterface)
            try {
                vpnInputChannel?.configureBlocking(false)
                vpnInputChannel?.register(selector, SelectionKey.OP_READ)
            } catch (e: IOException) { Log.e("HttpLoggerVpnService", "VPN input channel register failed", e); stopVpn(); return }

            val notificationIntent = Intent(this, MainActivity::class.java)
            val pendingIntentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_UPDATE_CURRENT
            val pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, pendingIntentFlags)
            val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("HttpLoggerVpn Active").setContentText("VPN service running (NIO VpnSession Corrected).")
                .setSmallIcon(R.drawable.ic_launcher_foreground).setContentIntent(pendingIntent).build()
            startForeground(NOTIFICATION_ID, notification)

            vpnWorkerThread = Thread(this::runVpnLoop, "HttpLoggerVpnWorker_VpnSessionCorrected")
            vpnWorkerThread?.start()
            Log.i("HttpLoggerVpnService", "VPN started (NIO VpnSession Corrected).")
        } else { Log.e("HttpLoggerVpnService", "VPN permission not granted."); stopSelf() }
    }

    private fun runVpnLoop() {
        Log.i("HttpLoggerVpnService", "NIO VPN loop started.")
        val readBuffer = ByteBuffer.allocate(32767)
        try {
            while (isRunning && selector?.isOpen == true && !Thread.currentThread().isInterrupted) {
                val numKeys = selector?.select()
                if (Thread.currentThread().isInterrupted) { Log.i("HttpLoggerVpnService", "VPN loop interrupted."); break }
                if (numKeys == null || numKeys == 0) continue
                val selectedKeys = selector!!.selectedKeys()
                val iterator = selectedKeys.iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    if (!key.isValid) { Log.w("HttpLoggerVpnService", "Invalid key."); continue }
                    try {
                        when {
                            key.isConnectable -> handleConnectToServer(key)
                            key.isReadable -> handleReadableKey(key, readBuffer)
                        }
                    } catch (e: IOException) {
                        Log.e("HttpLoggerVpnService", "IOException handling key: ${key.channel()}", e)
                        (key.attachment() as? VpnSession)?.let { closeSession(it, key, true) }
                    } catch (e: Exception) {
                        Log.e("HttpLoggerVpnService", "Exception handling key: ${key.channel()}", e)
                        (key.attachment() as? VpnSession)?.let { closeSession(it, key, true) }
                    }
                }
            }
        } catch (e: ClosedSelectorException) { Log.i("HttpLoggerVpnService", "Selector closed.") }
          catch (e: IOException) { Log.e("HttpLoggerVpnService", "IOException in VPN loop", e); stopVpn() }
          catch (e: Exception) { Log.e("HttpLoggerVpnService", "Exception in VPN loop", e); stopVpn() }
        finally { Log.i("HttpLoggerVpnService", "NIO VPN loop stopping.") }
    }

    private fun handleReadableKey(key: SelectionKey, readBuffer: ByteBuffer) {
        val channel = key.channel()
        if (channel == vpnInputChannel) {
            readBuffer.clear()
            val bytesRead = vpnInputChannel?.read(readBuffer) ?: 0
            if (bytesRead > 0) {
                readBuffer.flip()
                val packet = ByteArray(readBuffer.remaining())
                readBuffer.get(packet)
                handlePacketFromClient(packet)
            } else if (bytesRead == -1) {
                Log.i("HttpLoggerVpnService", "VPN input channel EOF."); stopVpn()
            }
        } else if (channel is SocketChannel) {
            val session = key.attachment() as? VpnSession
            if (session?.serverSocketChannel == channel) {
                readBuffer.clear()
                try {
                    val bytesRead = channel.read(readBuffer)
                    if (bytesRead == -1) { // Server sent FIN (EOF)
                        Log.i("HttpLoggerVpnService", "EOF from server for ${session.sessionKey} (Server FIN).")
                        session.serverSentFin = true
                        key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv()) // No more reading from server

                        if (session.status == SessionStatus.ESTABLISHED) {
                            session.closingInitiator = "server"
                            sendTcpPacketToClient(session, (PacketUtil.TCP_FIN_FLAG or PacketUtil.TCP_ACK_FLAG).toByte(), ByteArray(0))
                            // vpnSentFinToClient flag is set inside sendTcpPacketToClient if FIN is sent
                            session.status = SessionStatus.SERVER_FIN_RECEIVED // We've sent FIN, waiting for client's ACK
                        } else if (session.status == SessionStatus.CLIENT_FIN_RECEIVED) { // Client already sent FIN
                            Log.i("HttpLoggerVpnService", "Server FIN received after client FIN for ${session.sessionKey} (simultaneous close).")
                            // Client already processed our ACK for its FIN. We might have sent FIN+ACK to server.
                            // Now server sends FIN. We should ACK this if not already done by previous FIN+ACK from us.
                            // For simplicity here, assume previous FIN+ACK to server also acked any pending server data.
                            // Our FIN to client was already sent when we processed client's FIN and server hadn't sent FIN yet.
                            // Or if we sent FIN to client in SERVER_FIN_RECEIVED state.
                            // This state implies both have initiated close, and we are likely waiting for final ACKs.
                            // If client also ACKed our FIN, this session can be closed.
                            // If client's FIN was acked, and now server's FIN is acked (implicitly by our FIN to client, or explicitly)
                            session.status = SessionStatus.TIME_WAIT // Or CLOSED
                            closeSession(session, key)
                        } else {
                             Log.w("HttpLoggerVpnService", "Server FIN received in unexpected state ${session.status} for ${session.sessionKey}")
                             // Potentially send RST to client and close.
                             sendRstPacketToClient(session)
                             closeSession(session, key, isRst = true)
                        }
                        // Do not return, allow loop to continue for other keys or cleanup
                    } else if (bytesRead > 0) {
                        Log.d("HttpLoggerVpnService", "Read $bytesRead bytes from server ${session.sessionKey} (Data handling TODO)")
                        // TODO: process data from server, update sequence numbers, forward to client
                        // session.vpnExpectedAckFromServer += bytesRead.toLong()
                        // sendTcpPacketToClient(session, PacketUtil.TCP_ACK_FLAG or PacketUtil.TCP_PSH_FLAG, readPayload)
                        // sendAckToServer(session, session.vpnExpectedAckFromServer) // Acknowledging server's data
                    }
                } catch (e: IOException) { // Likely RST from server or other connection error
                     Log.e("HttpLoggerVpnService", "IOException on server read for ${session.sessionKey} (Server RST or conn error). Closing.", e)
                     sendRstPacketToClient(session)
                     closeSession(session, key, isRst = true)
                }
            }
        }
    }

    private fun handlePacketFromClient(packetData: ByteArray) {
        if (packetData.size < 20) { Log.w("HttpLoggerVpnService", "Packet too short (IP)."); return }
        val ipVersion = packetData[0].toInt() shr 4
        if (ipVersion != 4) { Log.d("HttpLoggerVpnService", "Non-IPv4."); return }
        val ipHeaderLength = (packetData[0].toInt() and 0x0F) * 4
        if (packetData.size < ipHeaderLength + 20) { Log.w("HttpLoggerVpnService", "Packet too short (TCP)."); return }
        val protocol = packetData[9].toInt() and 0xFF
        if (protocol != PacketUtil.IPPROTO_TCP.toInt()) { Log.d("HttpLoggerVpnService", "Non-TCP (proto:$protocol)."); return }

        val sourceIp = InetAddress.getByAddress(packetData.sliceArray(12 until 16))
        val destinationIp = InetAddress.getByAddress(packetData.sliceArray(16 until 20))
        val tcpOffset = ipHeaderLength
        val sourcePort = ((packetData[tcpOffset].toInt() and 0xFF) shl 8) or (packetData[tcpOffset + 1].toInt() and 0xFF)
        val destinationPort = ((packetData[tcpOffset + 2].toInt() and 0xFF) shl 8) or (packetData[tcpOffset + 3].toInt() and 0xFF)
        val sequenceNumber = extractSequenceNumber(packetData, ipHeaderLength)
        val acknowledgementNumber = extractAcknowledgementNumber(packetData, ipHeaderLength)
        val flagsByte = packetData[tcpOffset + 13].toInt() and 0xFF
        val isSYN = (flagsByte and PacketUtil.TCP_SYN_FLAG) != 0.toByte()
        val isACK = (flagsByte and PacketUtil.TCP_ACK_FLAG) != 0.toByte()
        val isRST = (flagsByte and PacketUtil.TCP_RST_FLAG) != 0.toByte()
        val isFIN = (flagsByte and PacketUtil.TCP_FIN_FLAG) != 0.toByte()

        val sessionKey = "$sourceIp:$sourcePort-$destinationIp:$destinationPort"
        var session = sessions[sessionKey]

        if (session != null && isRST) {
            Log.i("HttpLoggerVpnService", "RST from client for ${session.sessionKey}. Closing.")
            sendRstPacketToServer(session) // Stubbed
            closeSession(session, isRst = true); return
        }

        if (isSYN && !isACK && !isRST && !isFIN) { // Pure SYN
            if (session == null || session.status == SessionStatus.CLOSED) {
                session = VpnSession(sessionKey, sourceIp, sourcePort, destinationIp, destinationPort, clientInitialSequenceNumber = sequenceNumber)
                sessions[sessionKey] = session
                Log.i("HttpLoggerVpnService", "New SYN: $sessionKey, ISN: $sequenceNumber")
                try {
                    val serverChannel = SocketChannel.open()
                    serverChannel.configureBlocking(false)
                    if (!VpnService.this.protect(serverChannel.socket())) { Log.e("HttpLoggerVpnService", "Protect failed: $sessionKey."); closeSession(session, isRst = true); return }
                    session.serverSocketChannel = serverChannel
                    session.status = SessionStatus.CONNECTING_TO_SERVER
                    val connected = serverChannel.connect(InetSocketAddress(destinationIp, destinationPort))
                    session.serverSelectionKey = serverChannel.register(selector, if (connected) SelectionKey.OP_READ else SelectionKey.OP_CONNECT, session)
                    if (connected) { Log.i("HttpLoggerVpnService", "Immediately connected: $sessionKey."); handleConnectToServer(session.serverSelectionKey!!) }
                    else { Log.i("HttpLoggerVpnService", "Connection pending: $sessionKey.") }
                } catch (e: IOException) { Log.e("HttpLoggerVpnService", "Conn setup error: $sessionKey", e); closeSession(session, isRst = true) }
            } else { Log.w("HttpLoggerVpnService", "SYN for existing session: $sessionKey, Status: ${session.status}. Ignoring.") }
        } else if (session != null) {
            session.lastActivityTime = System.currentTimeMillis()
            if (session.status == SessionStatus.SYN_ACK_SENT_TO_CLIENT) {
                if (!isSYN && isACK && !isRST && !isFIN) { // Pure ACK for our SYN-ACK
                    val expectedAckNum = session.vpnServerInitialSequenceNumber + 1
                    if (acknowledgementNumber == expectedAckNum) {
                        session.status = SessionStatus.ESTABLISHED
                        session.initializeSequenceNumbersAfterClientAckToOurSynAck(sequenceNumber)
                        session.serverSelectionKey?.takeIf { it.isValid }?.interestOps(SelectionKey.OP_READ)
                        Log.i("HttpLoggerVpnService", "Session ESTABLISHED: ${session.sessionKey}. Client ACKed our SYN-ACK.")
                    } else { Log.w("HttpLoggerVpnService", "Session ${session.sessionKey}: ACK with unexpected ackNum. Expected $expectedAckNum, got $acknowledgementNumber. Ignoring.") }
                } else { Log.w("HttpLoggerVpnService", "Session ${session.sessionKey}: Expected pure ACK for SYN-ACK, got different flags. RST:$isRST, FIN:$isFIN"); if(isRST) closeSession(session, isRst = true) }
            } else if (session.status == SessionStatus.ESTABLISHED) {
                if (isFIN) {
                    Log.i("HttpLoggerVpnService", "FIN from Client for ${session.sessionKey}. Seq: $sequenceNumber")
                    session.clientSentFin = true
                    session.vpnExpectedAckFromClient = sequenceNumber + 1 // FIN consumes 1
                    // TODO: sendAckToClient(session, session.vpnExpectedAckFromClient, session.vpnNextSeqToClient)
                    Log.d("HttpLoggerVpnService", "TODO: Call sendAckToClient for client's FIN ${session.sessionKey}")

                    if (!session.serverSentFin) { // If server hasn't sent FIN yet
                        session.closingInitiator = "client"
                        // TODO: sendFinAckToServer(session)
                        Log.d("HttpLoggerVpnService", "TODO: Call sendFinAckToServer for ${session.sessionKey}")
                        session.status = SessionStatus.CLIENT_FIN_RECEIVED
                    } else { // Server already sent FIN, this is a simultaneous close response or client finally sending FIN
                        session.status = SessionStatus.TIME_WAIT // Or CLOSED
                        Log.i("HttpLoggerVpnService", "Simultaneous close or client FIN after server FIN for ${session.sessionKey}. Status: ${session.status}")
                        closeSession(session)
                    }
                } else if (isACK) {
                     Log.d("HttpLoggerVpnService", "ACK from client in ESTABLISHED ${session.sessionKey}. Seq: $sequenceNumber, Ack: $acknowledgementNumber. Data handling TODO.")
                     // TODO: Data transfer logic
                }
            } else { Log.d("HttpLoggerVpnService", "Packet for session ${session.sessionKey} in status ${session.status}. RST:$isRST, FIN:$isFIN, ACK:$isACK") }
        } else { Log.w("HttpLoggerVpnService", "Non-SYN for unknown session: $sessionKey. RST:$isRST. Ignoring unless RST.") }
    }

    private fun extractAcknowledgementNumber(packetData: ByteArray, ipHeaderLength: Int): Long {
        val tcpOffset = ipHeaderLength
        if (packetData.size < tcpOffset + 12) { // Ack num is at offset 8, length 4 bytes
            Log.w("HttpLoggerVpnService", "Packet too short for TCP Acknowledgement Number")
            return 0L
        }
        return ((packetData[tcpOffset + 8].toLong() and 0xFF) shl 24) or
               ((packetData[tcpOffset + 9].toLong() and 0xFF) shl 16) or
               ((packetData[tcpOffset + 10].toLong() and 0xFF) shl 8) or
               (packetData[tcpOffset + 11].toLong() and 0xFF)
    }

    private fun extractSequenceNumber(packetData: ByteArray, ipHeaderLength: Int): Long {
        val tcpOffset = ipHeaderLength
        if (packetData.size < tcpOffset + 8) { // Seq num is at offset 4, length 4 bytes
            Log.w("HttpLoggerVpnService", "Packet too short for TCP Sequence Number")
            return 0L
        }
        return ((packetData[tcpOffset + 4].toLong() and 0xFF) shl 24) or
               ((packetData[tcpOffset + 5].toLong() and 0xFF) shl 16) or
               ((packetData[tcpOffset + 6].toLong() and 0xFF) shl 8) or
               (packetData[tcpOffset + 7].toLong() and 0xFF)
    }

    private fun handleConnectToServer(key: SelectionKey) {
        val session = key.attachment() as? VpnSession ?: run { Log.e("HttpLoggerVpnService", "No session for OP_CONNECT."); key.cancel(); (key.channel() as? SocketChannel)?.close(); return }
        val serverChannel = key.channel() as SocketChannel
        try {
            if (serverChannel.finishConnect()) {
                Log.i("HttpLoggerVpnService", "Server connection ESTABLISHED: ${session.sessionKey}")
                session.status = SessionStatus.CONNECTED_TO_SERVER
                session.lastActivityTime = System.currentTimeMillis()
                session.vpnServerInitialSequenceNumber = Random().nextInt().toLong() and 0xFFFFFFFFL
                if (sendSynAckToClient(session)) {
                    session.status = SessionStatus.SYN_ACK_SENT_TO_CLIENT
                    Log.i("HttpLoggerVpnService", "SYN-ACK sent to client for ${session.sessionKey} (VPN ISN: ${session.vpnServerInitialSequenceNumber}).")
                } else { Log.e("HttpLoggerVpnService", "Failed to send SYN-ACK for ${session.sessionKey}. Closing."); closeSession(session, key, true); return }
                key.interestOps(SelectionKey.OP_READ)
            } else { Log.e("HttpLoggerVpnService", "finishConnect false: ${session.sessionKey}."); closeSession(session, key, true) }
        } catch (e: IOException) { Log.e("HttpLoggerVpnService", "finishConnect error: ${session.sessionKey}", e); closeSession(session, key, true) }
    }

    private fun sendSynAckToClient(session: VpnSession): Boolean { // This should be correctly implemented from previous steps
        val packet = PacketUtil.buildIpTcpPacket(
            sourceIp = session.remoteIp, destinationIp = session.clientIp,
            sourcePort = session.remotePort.toShort(), destinationPort = session.clientPort.toShort(),
            sequenceNumber = session.vpnServerInitialSequenceNumber,
            acknowledgementNumber = session.clientInitialSequenceNumber + 1,
            tcpFlags = (PacketUtil.TCP_SYN_FLAG or PacketUtil.TCP_ACK_FLAG).toByte(),
            windowSize = 65535.toShort(), payload = ByteArray(0)
        )
        try {
            vpnOutputStream?.write(packet); vpnOutputStream?.flush()
            Log.i("HttpLoggerVpnService", "SYN-ACK sent to client for ${session.sessionKey}")
            // SYN consumes 1 byte of sequence number space
            session.vpnNextSeqToClient = session.vpnServerInitialSequenceNumber + 1
            return true
        } catch (e: IOException) {
            Log.e("HttpLoggerVpnService", "Failed to send SYN-ACK for ${session.sessionKey}", e)
            return false
        }
    }

    private fun sendRstPacketToClient(session: VpnSession) {
        Log.i("HttpLoggerVpnService", "Sending RST to Client for session ${session.sessionKey}")
        val seqForRst = session.vpnNextSeqToClient // Our current/next sequence number to client
        // Ack number for RST can be the sequence number that caused the RST if known, otherwise 0 or current expected.
        // For an unsolicited RST from us, session.vpnExpectedAckFromClient is appropriate.
        val ackForRst = session.vpnExpectedAckFromClient

        val rstPacket = PacketUtil.buildIpTcpPacket(
            sourceIp = session.remoteIp,
            destIp = session.clientIp,
            sourcePort = session.remotePort.toShort(),
            destPort = session.clientPort.toShort(),
            sequenceNumber = seqForRst,
            acknowledgementNumber = ackForRst, // Some stacks might expect this to be 0 for certain RSTs
            tcpFlags = (PacketUtil.TCP_RST_FLAG or PacketUtil.TCP_ACK_FLAG).toByte(), // RST+ACK is common
            windowSize = 0.toShort(), // Window size for RST is often 0
            payload = ByteArray(0)
        )
        try {
            vpnOutputStream?.write(rstPacket)
            vpnOutputStream?.flush()
            Log.i("HttpLoggerVpnService", "RST packet sent to client for ${session.sessionKey}")
        } catch (e: IOException) {
            Log.e("HttpLoggerVpnService", "Failed to send RST to client for ${session.sessionKey}", e)
        }
    }

    private fun sendRstPacketToServer(session: VpnSession) {
        Log.i("HttpLoggerVpnService", "Signaling server connection to close (will likely cause RST or FIN from OS) for session ${session.sessionKey}")
        try {
            session.serverSocketChannel?.close()
        } catch (e: IOException) {
            Log.w("HttpLoggerVpnService", "IOException while closing serverSocketChannel for ${session.sessionKey} during RST propagation.", e)
        }
    }

    // Generic helper to send a TCP packet to the client
    private fun sendTcpPacketToClient(session: VpnSession, flags: Byte, payload: ByteArray) {
        val seq = session.vpnNextSeqToClient
        val ack = session.vpnExpectedAckFromClient // This ACKs data received from client up to this point

        val packet = PacketUtil.buildIpTcpPacket(
            sourceIp = session.remoteIp, // VPN acts as the remote server
            destinationIp = session.clientIp,
            sourcePort = session.remotePort.toShort(),
            destinationPort = session.clientPort.toShort(),
            sequenceNumber = seq,
            acknowledgementNumber = ack,
            tcpFlags = flags,
            windowSize = 65535.toShort(), // Standard window
            payload = payload
        )
        try {
            vpnOutputStream?.write(packet)
            vpnOutputStream?.flush()
            Log.d("HttpLoggerVpnService", "Sent TCP packet to client ${session.clientIp}:${session.clientPort} (Flags: ${Integer.toHexString(flags.toInt())}, Seq: $seq, Ack: $ack, Payload: ${payload.size})")
            if (payload.isNotEmpty() || (flags and PacketUtil.TCP_SYN_FLAG) != 0.toByte() || (flags and PacketUtil.TCP_FIN_FLAG) != 0.toByte()) {
                session.vpnNextSeqToClient += if (payload.isEmpty() && ((flags and PacketUtil.TCP_SYN_FLAG) != 0.toByte() || (flags and PacketUtil.TCP_FIN_FLAG) != 0.toByte())) 1 else payload.size.toLong()
            }
        } catch (e: IOException) {
            Log.e("HttpLoggerVpnService", "IOException writing to client for session ${session.sessionKey}", e)
            closeSession(session, isRst = true)
        }
    }

    // Generic helper to send a TCP packet to the server
    private fun sendTcpPacketToServer(session: VpnSession, flags: Byte, payload: ByteArray) {
        val seq = session.vpnNextSeqToServer
        val ack = session.vpnExpectedAckFromServer // This ACKs data received from server up to this point

        val packet = PacketUtil.buildIpTcpPacket(
            sourceIp = session.clientIp, // VPN acts as the client
            destinationIp = session.remoteIp,
            sourcePort = session.clientPort.toShort(),
            destinationPort = session.remotePort.toShort(),
            sequenceNumber = seq,
            acknowledgementNumber = ack,
            tcpFlags = flags,
            windowSize = 65535.toShort(), // Standard window
            payload = payload
        )
        try {
            session.serverSocketChannel?.write(ByteBuffer.wrap(packet)) // Write to actual server
            Log.d("HttpLoggerVpnService", "Sent TCP packet to server ${session.remoteIp}:${session.remotePort} (Flags: ${Integer.toHexString(flags.toInt())}, Seq: $seq, Ack: $ack, Payload: ${payload.size})")
            if (payload.isNotEmpty() || (flags and PacketUtil.TCP_SYN_FLAG) != 0.toByte() || (flags and PacketUtil.TCP_FIN_FLAG) != 0.toByte()) {
                session.vpnNextSeqToServer += if (payload.isEmpty() && ((flags and PacketUtil.TCP_SYN_FLAG) != 0.toByte() || (flags and PacketUtil.TCP_FIN_FLAG) != 0.toByte())) 1 else payload.size.toLong()
            }
        } catch (e: IOException) {
            Log.e("HttpLoggerVpnService", "IOException writing to server for session ${session.sessionKey}", e)
            sendRstPacketToClient(session) // Inform client about the problem
            closeSession(session, isRst = true)
        }
    }


    private fun closeSession(session: VpnSession, key: SelectionKey? = null, isRst: Boolean = false) {
        Log.i("HttpLoggerVpnService", "Closing session: ${session.sessionKey}, Status: ${session.status}, RST: $isRst")
        session.status = if (isRst) SessionStatus.CLOSED else SessionStatus.CLOSING
        try { session.serverSocketChannel?.close() } catch (e: IOException) { Log.w("HttpLoggerVpnService", "Error closing serverChannel for ${session.sessionKey}",e) }
        key?.cancel()
        session.serverSelectionKey?.cancel()
        sessions.remove(session.sessionKey)
        if (isRst || session.status == SessionStatus.CLOSING) session.status = SessionStatus.CLOSED // Ensure final state is CLOSED
        Log.i("HttpLoggerVpnService", "Session ${session.sessionKey} is now ${session.status}.")
    }

    private fun stopVpn() { /* ... */ }
    override fun onRevoke() { Log.w("HttpLoggerVpnService", "VPN revoked."); stopVpn(); super.onRevoke() }
    override fun onDestroy() { Log.d("HttpLoggerVpnService", "onDestroy."); stopVpn(); super.onDestroy() }

    // Old parsing logic (can be removed or refactored into PacketUtil later)
    private fun parseAndLogHttpRequest(packet: ByteArray, length: Int) { /* ... */ }
    private fun packetToIp(packet: ByteArray, offset: Int): String { /* ... */ return "" }
    private fun bytesToShort(b1: Byte, b2: Byte): Short { /* ... */ return 0 }
}
