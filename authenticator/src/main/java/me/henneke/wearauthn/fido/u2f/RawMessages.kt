package me.henneke.wearauthn.fido.u2f

import me.henneke.wearauthn.fido.ApduException
import me.henneke.wearauthn.fido.CommandApdu
import me.henneke.wearauthn.fido.StatusWord

@ExperimentalUnsignedTypes
enum class AuthenticateControlByte(val value: UByte) {
    ENFORCE_USER_PRESENCE_AND_SIGN(0x03u),
    CHECK_ONLY(0x07u),
    DONT_ENFORCE_USER_PRESENCE_AND_SIGN(0x08u),
}

@ExperimentalUnsignedTypes
enum class RequestCommand(val value: UByte) {
    REGISTER(0x01u),
    AUTHENTICATE(0x02u),
    VERSION(0x03u),
}


@ExperimentalUnsignedTypes
sealed class Request {
    data class RegistrationRequest(val challenge: ByteArray, val application: ByteArray) : Request()
    data class AuthenticationRequest(
        val controlByte: AuthenticateControlByte,
        val challenge: ByteArray,
        val application: ByteArray,
        val keyHandle: ByteArray
    ) : Request()

    object VersionRequest : Request()

    companion object {
        fun parse(apdu: CommandApdu): Request {
            val command: RequestCommand
            var controlByte: AuthenticateControlByte? = null
            when (apdu.ins) {
                RequestCommand.REGISTER.value -> {
                    // We accept any value for P1 since various real-world applications populate
                    // this (e.g. with 0x80 if enterprise attestation is requested or with a value
                    // mimicking the AuthenticateControlByte).
                    if (apdu.p2 != 0x00.toUByte()) {
                        throw ApduException(StatusWord.INCORRECT_PARAMETERS)
                    }
                    command = RequestCommand.REGISTER
                }
                RequestCommand.AUTHENTICATE.value -> {
                    controlByte = when (apdu.p1) {
                        AuthenticateControlByte.ENFORCE_USER_PRESENCE_AND_SIGN.value -> {
                            AuthenticateControlByte.ENFORCE_USER_PRESENCE_AND_SIGN
                        }
                        AuthenticateControlByte.CHECK_ONLY.value -> {
                            AuthenticateControlByte.CHECK_ONLY
                        }
                        AuthenticateControlByte.DONT_ENFORCE_USER_PRESENCE_AND_SIGN.value -> {
                            AuthenticateControlByte.DONT_ENFORCE_USER_PRESENCE_AND_SIGN
                        }
                        else -> {
                            throw ApduException(StatusWord.INCORRECT_PARAMETERS)
                        }
                    }
                    if (apdu.p2 != 0x00.toUByte()) {
                        throw ApduException(StatusWord.INCORRECT_PARAMETERS)
                    }
                    command = RequestCommand.AUTHENTICATE
                }
                RequestCommand.VERSION.value -> {
                    if (apdu.p1 != 0x00.toUByte()) {
                        throw ApduException(StatusWord.INCORRECT_PARAMETERS)
                    }
                    if (apdu.p2 != 0x00.toUByte()) {
                        throw ApduException(StatusWord.INCORRECT_PARAMETERS)
                    }
                    command = RequestCommand.VERSION
                }
                else -> {
                    throw ApduException(StatusWord.INS_NOT_SUPPORTED)
                }
            }

            if (apdu.cla != 0x00.toUByte()) {
                throw ApduException(StatusWord.CLA_NOT_SUPPORTED)
            }

            when (command) {
                RequestCommand.REGISTER -> {
                    if (apdu.le == 0) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    if (apdu.lc != 32 + 32) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    val challenge = apdu.data.sliceArray(0 until 32).toByteArray()
                    val application = apdu.data.sliceArray(32 until 64).toByteArray()
                    return RegistrationRequest(challenge, application)
                }
                RequestCommand.AUTHENTICATE -> {
                    if (apdu.le == 0) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    if (apdu.lc < 32 + 32 + 1) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    val keyHandleLength = apdu.data[64].toInt()
                    if (apdu.lc != 32 + 32 + 1 + keyHandleLength) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    val challenge = apdu.data.sliceArray(0 until 32).toByteArray()
                    val application = apdu.data.sliceArray(32 until 64).toByteArray()
                    val keyHandle = apdu.data.sliceArray(65 until 65 + keyHandleLength).toByteArray()
                    return AuthenticationRequest(controlByte!!, challenge, application, keyHandle)
                }
                RequestCommand.VERSION -> {
                    if (apdu.lc != 0) {
                        throw ApduException(StatusWord.WRONG_LENGTH)
                    }
                    // In order to pass the FIDO tests, we must not make any assumption on le here
                    return VersionRequest
                }
            }
        }
    }
}


@ExperimentalUnsignedTypes
sealed class Response {
    abstract val data: UByteArray
    val statusWord = StatusWord.NO_ERROR

    data class RegistrationResponse(
        val userPublicKey: ByteArray,
        val keyHandle: ByteArray,
        val attestationCert: ByteArray,
        val signature: ByteArray
    ) : Response() {
        override val data = ubyteArrayOf(0x05u) +
                userPublicKey.toUByteArray() +
                ubyteArrayOf(keyHandle.size.toUByte()) +
                keyHandle.toUByteArray() +
                attestationCert.toUByteArray() +
                signature.toUByteArray()
    }

    data class AuthenticationResponse(
        val assertion: ByteArray
    ) : Response() {
        override val data = assertion.asUByteArray()
    }

    class VersionResponse : Response() {
        override val data = "U2F_V2".toByteArray().toUByteArray()
    }
}