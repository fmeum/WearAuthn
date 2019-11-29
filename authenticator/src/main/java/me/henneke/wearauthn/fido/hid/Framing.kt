package me.henneke.wearauthn.fido.hid

import android.os.Handler
import android.os.Looper
import android.util.Log
import com.google.android.gms.common.util.Hex
import kotlinx.coroutines.*
import me.henneke.wearauthn.bytes
import me.henneke.wearauthn.fido.ApduException
import me.henneke.wearauthn.fido.CommandApdu
import me.henneke.wearauthn.fido.ResponseApdu
import me.henneke.wearauthn.fido.StatusWord
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.AuthenticatorStatus
import me.henneke.wearauthn.fido.ctap2.CtapError
import me.henneke.wearauthn.fido.u2f.Request
import me.henneke.wearauthn.fido.u2f.Response
import me.henneke.wearauthn.uIntOf
import me.henneke.wearauthn.uShortOf
import kotlin.coroutines.CoroutineContext
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.math.min
import me.henneke.wearauthn.fido.ctap2.Authenticator as Ctap2Authenticator
import me.henneke.wearauthn.fido.u2f.Authenticator as U2fAuthenticator

private const val TAG = "Framing"

@ExperimentalUnsignedTypes
internal sealed class Packet {
    abstract val channelId: UInt
    abstract val payload: ByteArray

    abstract fun toRawReport(): ByteArray

    data class InitPacket(
        override val channelId: UInt,
        val cmd: CtapHidCommand,
        val totalLength: UShort,
        override val payload: ByteArray
    ) : Packet() {
        override fun toRawReport(): ByteArray {
            check(payload.size <= INIT_PACKET_PAYLOAD_SIZE)
            val padding = ByteArray(INIT_PACKET_PAYLOAD_SIZE - payload.size)
            return channelId.bytes() + (cmd.code or MESSAGE_TYPE_INIT).bytes() + totalLength.bytes() + payload + padding
        }
    }

    data class ContPacket(
        override val channelId: UInt,
        val seq: UByte,
        override val payload: ByteArray
    ) : Packet() {
        override fun toRawReport(): ByteArray {
            check(payload.size <= CONT_PACKET_PAYLOAD_SIZE)
            val padding = ByteArray(CONT_PACKET_PAYLOAD_SIZE - payload.size)
            return channelId.bytes() + seq.bytes() + payload + padding
        }
    }

    companion object {
        fun parse(bytes: ByteArray): Packet {
            val reportOffset = when (bytes.size) {
                HID_REPORT_SIZE + 1 -> 1 // Linux (hidraw) includes the report ID
                HID_REPORT_SIZE -> 0 // Windows (hidsdi.h) does not include the report ID
                else -> throw CtapHidException(CtapHidError.InvalidLen, null)
            }
            val channelId = uIntOf(bytes, reportOffset)
            if (bytes[reportOffset + 4] and MESSAGE_TYPE_MASK == MESSAGE_TYPE_INIT) {
                // Initialization packet
                val cmd = CtapHidCommand.fromByte(bytes[reportOffset + 4] and COMMAND_MASK)
                    ?: throw CtapHidException(CtapHidError.InvalidCmd, channelId)
                val totalLength = uShortOf(bytes, reportOffset + 4 + 1)
                if (totalLength > MAX_PAYLOAD_LENGTH) {
                    throw CtapHidException(CtapHidError.InvalidLen, channelId)
                }
                val data = bytes.sliceArray(reportOffset + 4 + 1 + 2 until bytes.size)
                return InitPacket(channelId, cmd, totalLength, data)
            } else {
                // Continuation packet
                val seq = bytes[reportOffset + 4].toUByte()
                val data = bytes.sliceArray(reportOffset + 4 + 1 until bytes.size)
                return ContPacket(channelId, seq, data)
            }
        }
    }
}

@ExperimentalUnsignedTypes
internal class InMessage(packet: Packet.InitPacket) {
    val channelId = packet.channelId
    val cmd = packet.cmd

    private val totalLength = packet.totalLength
    private var _payload = packet.payload
    private var seq: UByte = 0u

    private val complete: Boolean
        get() = _payload.size >= totalLength.toInt()
    val payloadIfComplete: ByteArray?
        get() = if (complete) {
            if (_payload.size > totalLength.toInt()) {
                _payload = _payload.sliceArray(0 until totalLength.toInt())
            }
            _payload
        } else null


    fun append(packet: Packet.ContPacket): Boolean {
        if (packet.channelId != channelId) {
            // Spurious continuation packets are dropped without error.
            return false
        }
        if (complete || packet.seq != seq) {
            throw CtapHidException(CtapHidError.InvalidSeq, channelId)
        }
        _payload += packet.payload
        seq++
        return true
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InMessage

        if (channelId != other.channelId) return false
        if (cmd != other.cmd) return false

        val ourPayload = payloadIfComplete
        val otherPayload = other.payloadIfComplete ?: return ourPayload == null
        if (ourPayload == null) return false
        if (!ourPayload.contentEquals(otherPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = channelId.hashCode()
        result = 31 * result + cmd.hashCode()
        result = 31 * result + complete.hashCode()
        payloadIfComplete?.let { result = 31 * result + it.contentHashCode() }
        return result
    }

    override fun toString(): String {
        return "InMessage(cid=$channelId, cmd=$cmd, totalLength=$totalLength, payload=${Hex.bytesToStringUppercase(
            _payload
        )})"
    }
}

@ExperimentalUnsignedTypes
internal sealed class OutMessage {
    abstract val channelId: UInt
    abstract fun toRawReports(): Iterable<ByteArray>

    internal fun serializeResponse(cmd: CtapHidCommand, payload: ByteArray): Iterable<ByteArray> {
        require(payload.size <= MAX_PAYLOAD_LENGTH.toInt())
        val totalLength = payload.size
        val rawReports = mutableListOf(
            Packet.InitPacket(
                channelId,
                cmd,
                totalLength.toUShort(),
                payload.sliceArray(0 until min(INIT_PACKET_PAYLOAD_SIZE, payload.size))
            ).toRawReport()
        )
        var offset = INIT_PACKET_PAYLOAD_SIZE
        var seq: UByte = 0u
        while (offset < payload.size) {
            val nextOffset = min(offset + CONT_PACKET_PAYLOAD_SIZE, payload.size)
            rawReports.add(
                Packet.ContPacket(
                    channelId,
                    seq,
                    payload.sliceArray(offset until nextOffset)
                ).toRawReport()
            )
            offset = nextOffset
            seq++
        }
        return rawReports
    }

    data class PingResponse(override val channelId: UInt, val payload: ByteArray) : OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            return serializeResponse(CtapHidCommand.Ping, payload)
        }
    }

    data class MsgResponse(override val channelId: UInt, val payload: ByteArray) : OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            return serializeResponse(CtapHidCommand.Msg, payload)
        }
    }

    data class CborResponse(override val channelId: UInt, val payload: ByteArray) : OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            return serializeResponse(CtapHidCommand.Cbor, payload)
        }
    }

    data class InitResponse(
        override val channelId: UInt,
        val nonce: ByteArray,
        val newChannelId: UInt
    ) : OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            val payload = nonce + newChannelId.bytes() + INIT_CMD_TRAILER
            return listOf(
                Packet.InitPacket(
                    channelId,
                    CtapHidCommand.Init,
                    payload.size.toUShort(),
                    payload
                ).toRawReport()
            )
        }
    }

    data class ErrorResponse(override val channelId: UInt, val error: CtapHidError) : OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            return listOf(
                Packet.InitPacket(
                    channelId,
                    CtapHidCommand.Error,
                    1u,
                    byteArrayOf(error.code)
                ).toRawReport()
            )
        }
    }

    data class KeepaliveResponse(override val channelId: UInt, val status: CtapHidStatus) :
        OutMessage() {
        override fun toRawReports(): Iterable<ByteArray> {
            return listOf(
                Packet.InitPacket(
                    channelId,
                    CtapHidCommand.Keepalive,
                    1u,
                    byteArrayOf(status.code)
                ).toRawReport()
            )
        }
    }
}

@ExperimentalUnsignedTypes
class TransactionManager(private val authenticatorContext: AuthenticatorContext) :
    CoroutineScope {

    init {
        check(authenticatorContext.isHidTransport)
    }

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    private var message: InMessage? = null
    private var activeCborJob: Job? = null
    private var freeChannelId: UInt = 1u

    private val timeoutHandler = Handler(Looper.getMainLooper())

    private fun startTimeout(submit: (rawReports: Iterable<ByteArray>) -> Unit) {
        timeoutHandler.postDelayed({
            message?.let {
                submit(
                    OutMessage.ErrorResponse(
                        it.channelId,
                        CtapHidError.MsgTimeout
                    ).toRawReports()
                )
            }
            message = null
        }, HID_CONT_TIMEOUT_MS)
    }

    private fun haltTimeout() {
        timeoutHandler.removeCallbacksAndMessages(null)
    }

    private fun resetTransaction() {
        haltTimeout()
        message = null
        activeCborJob = null
    }

    private fun handleError(
        hidException: CtapHidException,
        submit: (rawReports: Iterable<ByteArray>) -> Unit
    ) {
        Log.w(TAG, "HID error: ${hidException.error}")
        hidException.channelId?.let {
            if (message?.channelId == it) {
                resetTransaction()
            }
            submit(OutMessage.ErrorResponse(it, hidException.error).toRawReports())
        }
    }

    @ExperimentalUnsignedTypes
    private data class U2fContinuation(
        val message: InMessage,
        val confirmationRequest: Deferred<Boolean>,
        val cont: () -> Response
    )

    private var activeU2fConfirmation: U2fContinuation? = null
    private val u2fRetryTimeoutHandler = Handler(Looper.getMainLooper())
    private fun rearmU2fRetryTimeout() {
        haltU2fRetryTimeout()
        u2fRetryTimeoutHandler.postDelayed({
            Log.w(TAG, "Request requiring user confirmation timed out")
            resetU2fContinuation()
        }, HID_MSG_TIMEOUT_MS)
    }

    private fun haltU2fRetryTimeout() {
        u2fRetryTimeoutHandler.removeCallbacksAndMessages(null)
    }

    private fun resetU2fContinuation() {
        haltU2fRetryTimeout()
        activeU2fConfirmation?.confirmationRequest?.cancel()
        activeU2fConfirmation = null
    }

    @ExperimentalCoroutinesApi
    private fun handleMessageIfComplete(submit: (rawReports: Iterable<ByteArray>) -> Unit): Boolean {
        message?.let { message ->
            val payload = message.payloadIfComplete ?: return false
            Log.i(TAG, "Handling complete ${message.cmd} message")
            when (message.cmd) {
                CtapHidCommand.Ping -> submit(
                    OutMessage.PingResponse(message.channelId, payload).toRawReports()
                )
                CtapHidCommand.Msg -> {
                    activeU2fConfirmation?.let {
                        // We have an active user confirmation request. If the current message
                        // is just a retry of the message that initiated the confirmation,
                        // we reply with the status, otherwise we cancel the confirmation
                        // request.
                        if (message == it.message) {
                            when {
                                it.confirmationRequest.isActive -> {
                                    // Still waiting for user confirmation; let the client retry.
                                    rearmU2fRetryTimeout()
                                    submit(
                                        OutMessage.MsgResponse(
                                            message.channelId,
                                            StatusWord.CONDITIONS_NOT_SATISFIED.value.toByteArray()
                                        ).toRawReports()
                                    )
                                }
                                it.confirmationRequest.isCancelled -> {
                                    Log.w(TAG, "Confirmation request already cancelled")
                                    resetU2fContinuation()
                                }
                                else -> {
                                    val userPresent = it.confirmationRequest.getCompleted()
                                    if (userPresent) {
                                        val responsePayload = try {
                                            val u2fResponse = it.cont()
                                            val u2fResponseApdu =
                                                ResponseApdu(
                                                    u2fResponse.data,
                                                    u2fResponse.statusWord
                                                )
                                            u2fResponseApdu.next()
                                        } catch (e: ApduException) {
                                            Log.w(
                                                TAG,
                                                "Continued transaction failed with status ${e.statusWord}"
                                            )
                                            e.statusWord.value
                                        }
                                        submit(
                                            OutMessage.MsgResponse(
                                                message.channelId,
                                                responsePayload.toByteArray()
                                            ).toRawReports()
                                        )
                                    }
                                    resetU2fContinuation()
                                }
                            }
                            resetTransaction()
                            return true
                        }
                        Log.i(TAG, "Received new message, cancelling user confirmation")
                        resetU2fContinuation()
                        // Fall through to usual message handling
                    }
                    val responsePayload = try {
                        val u2fRequestApdu =
                            CommandApdu(payload.toUByteArray())
                        val u2fRequest = Request.parse(u2fRequestApdu)
                        val (requestInfo, cont) =
                            U2fAuthenticator.handle(authenticatorContext, u2fRequest)
                        if (requestInfo == null) {
                            // No user presence check needed, continue right away
                            val u2fResponse = cont()
                            val u2fResponseApdu =
                                ResponseApdu(
                                    u2fResponse.data,
                                    u2fResponse.statusWord
                                )
                            u2fResponseApdu.next().toByteArray()
                        } else {
                            // User presence check required; confirm asynchronously and return
                            // CONDITIONS_NOT_SATISFIED while waiting.
                            activeU2fConfirmation = U2fContinuation(
                                message,
                                async { authenticatorContext.confirmWithUser(requestInfo) },
                                cont
                            )
                            rearmU2fRetryTimeout()
                            Log.i(TAG, "User confirmation required; expecting client to retry")
                            StatusWord.CONDITIONS_NOT_SATISFIED.value.toByteArray()
                        }
                    } catch (e: ApduException) {
                        if (payload.contentEquals(U2F_LEGACY_VERSION_COMMAND_APDU)) {
                            U2F_LEGACY_VERSION_RESPONSE
                        } else {
                            val payloadHeader = Hex.bytesToStringUppercase(
                                payload.sliceArray(0 until min(payload.size, 4))
                            )
                            Log.w(
                                TAG,
                                "Transaction failed with status ${e.statusWord}, request header was $payloadHeader"
                            )
                            e.statusWord.value.toByteArray()
                        }
                    }
                    submit(
                        OutMessage.MsgResponse(message.channelId, responsePayload).toRawReports()
                    )
                }
                CtapHidCommand.Cbor -> {
                    activeCborJob = launch {
                        try {
                            val keepaliveJob = launch(Dispatchers.Default) {
                                while (true) {
                                    delay(HID_KEEPALIVE_INTERVAL_MS)
                                    val status = when (authenticatorContext.status) {
                                        AuthenticatorStatus.IDLE,
                                        AuthenticatorStatus.PROCESSING -> CtapHidStatus.PROCESSING
                                        AuthenticatorStatus.WAITING_FOR_UP -> CtapHidStatus.UPNEEDED
                                    }
                                    submit(
                                        OutMessage.KeepaliveResponse(
                                            message.channelId,
                                            status
                                        ).toRawReports()
                                    )
                                }
                            }
                            val responsePayload =
                                Ctap2Authenticator.handle(authenticatorContext, payload)
                            keepaliveJob.cancelAndJoin()
                            submit(
                                OutMessage.CborResponse(
                                    message.channelId,
                                    responsePayload
                                ).toRawReports()
                            )
                        } catch (e: CancellationException) {
                            submit(
                                OutMessage.CborResponse(
                                    message.channelId,
                                    byteArrayOf(CtapError.KeepaliveCancel.value)
                                ).toRawReports()
                            )
                            Log.i(TAG, "Current transaction was cancelled by the client.")
                        } finally {
                            resetTransaction()
                        }
                    }
                    // Return early since we do not want to reset the transaction yet
                    return true
                }
                CtapHidCommand.Init -> throw IllegalStateException("Init message should never make it to handleMessage")
                else -> throw CtapHidException(CtapHidError.InvalidCmd, message.channelId)
            }
            resetTransaction()
            return true
        }
        return false
    }

    @ExperimentalCoroutinesApi
    fun handleReport(bytes: ByteArray, submit: (rawReports: Iterable<ByteArray>) -> Unit) {
        try {
            val packet = Packet.parse(bytes)
            if (packet.channelId == 0.toUInt()) {
                throw CtapHidException(CtapHidError.InvalidCid, packet.channelId)
            }
            when (packet) {
                is Packet.InitPacket -> {
                    when (packet.cmd) {
                        CtapHidCommand.Init -> {
                            if (packet.totalLength != INIT_CMD_NONCE_LENGTH) {
                                throw CtapHidException(CtapHidError.InvalidLen, packet.channelId)
                            }
                            if (packet.channelId == message?.channelId) {
                                // INIT command used to resync on the active channel.
                                resetTransaction()
                            }
                            val newChannelId: UInt
                            if (packet.channelId == BROADCAST_CHANNEL_ID) {
                                newChannelId = freeChannelId
                                freeChannelId++
                                if (freeChannelId == BROADCAST_CHANNEL_ID) {
                                    freeChannelId = 1u
                                }
                            } else {
                                newChannelId = packet.channelId
                            }
                            submit(
                                OutMessage.InitResponse(
                                    packet.channelId,
                                    packet.payload.sliceArray(0 until INIT_CMD_NONCE_LENGTH.toInt()),
                                    newChannelId
                                ).toRawReports()
                            )
                            return
                        }
                        CtapHidCommand.Cancel -> message?.let {
                            if (it.channelId == packet.channelId) {
                                activeCborJob?.cancel()
                                Log.i(TAG, "Cancelling current transaction")
                                activeCborJob = null
                            }
                            // Spurious cancels are silently ignored.
                            return
                        }
                        else -> {
                            if (packet.channelId == BROADCAST_CHANNEL_ID) {
                                // Only INIT messages are allowed on the broadcast channel.
                                throw CtapHidException(CtapHidError.InvalidCid, packet.channelId)
                            }
                            if (message == null) {
                                message = InMessage(packet)
                            } else {
                                // Received a second INIT packet, either on the same or another
                                // channel as the first.
                                if (message!!.channelId == packet.channelId) {
                                    throw CtapHidException(
                                        CtapHidError.InvalidSeq,
                                        packet.channelId
                                    )
                                } else {
                                    throw CtapHidException(
                                        CtapHidError.ChannelBusy,
                                        packet.channelId
                                    )
                                }
                            }
                        }
                    }
                }
                is Packet.ContPacket -> {
                    if (packet.channelId == BROADCAST_CHANNEL_ID) {
                        // Only INIT messages are allowed on the broadcast channel.
                        throw CtapHidException(CtapHidError.InvalidCid, packet.channelId)
                    }
                    if (message?.append(packet) != true) {
                        // Spurious continuation packets are dropped without timeout renewal.
                        return
                    }
                }
            }
            haltTimeout()
            if (!handleMessageIfComplete(submit)) {
                startTimeout(submit)
            }
        } catch (hidException: CtapHidException) {
            return handleError(hidException, submit)
        }
    }
}
