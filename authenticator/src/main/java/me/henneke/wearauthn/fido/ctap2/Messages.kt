package me.henneke.wearauthn.fido.ctap2

import me.henneke.wearauthn.Logging.Companion.i
import me.henneke.wearauthn.Logging.Companion.w
import me.henneke.wearauthn.fido.context.AuthenticatorAction
import me.henneke.wearauthn.fido.context.AuthenticatorAction.AUTHENTICATE
import me.henneke.wearauthn.fido.context.AuthenticatorAction.REGISTER
import me.henneke.wearauthn.fido.context.authenticatorKeyAgreementParams
import me.henneke.wearauthn.fido.ctap2.CtapError.*
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

// This size is chosen such that it can be transmitted via the HID protocol even if the maximal
// report size is 48 bytes.
const val MAX_CBOR_MSG_SIZE = 4096L

enum class RequestCommand(val value: Byte) {
    MakeCredential(0x01),
    GetAssertion(0x02),
    GetNextAssertion(0x08),
    GetInfo(0x04),
    ClientPIN(0x06),
    Reset(0x07),
    Selection(0x0B);

    companion object {
        private val REVERSE_MAP = values().associateBy(RequestCommand::value)
        fun fromByte(value: Byte) = REVERSE_MAP[value]
    }
}

enum class AttestationType(val format: String) {
    SELF("packed"),
    BASIC("packed"),
    ANDROID_KEYSTORE("android-key"),
}

enum class CtapError(val value: Byte) {
    InvalidCommand(0x1),
    InvalidParameter(0x02),
    InvalidLength(0x3),
    CborUnexpectedType(0x11),
    InvalidCbor(0x12),
    MissingParameter(0x14),
    UnsupportedExtension(0x16),
    CredentialExcluded(0x19),
    UnsupportedAlgorithm(0x26),
    OperationDenied(0x27),
    KeyStoreFull(0x28),
    UnsupportedOption(0x2b),
    InvalidOption(0x2c),
    KeepaliveCancel(0x2d),
    NoCredentials(0x2e),
    UserActionTimeout(0x2f),
    NotAllowed(0x30),
    PinAuthInvalid(0x33),
    RequestTooLarge(0x39),
    Other(0x7f),
}

data class CtapErrorException(val error: CtapError) : Throwable()

fun CTAP_ERR(error: CtapError, message: String? = null): Nothing {
    if (error == Other)
        w("CTAP") { "${error.name}: $message" }
    else
        i("CTAP") { "${error.name}: $message" }
    throw CtapErrorException(error)
}

const val MAKE_CREDENTIAL_CLIENT_DATA_HASH = 0x1L
const val MAKE_CREDENTIAL_RP = 0x2L
const val MAKE_CREDENTIAL_USER = 0x3L
const val MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS = 0x4L
const val MAKE_CREDENTIAL_EXCLUDE_LIST = 0x5L
const val MAKE_CREDENTIAL_EXTENSIONS = 0x6L
const val MAKE_CREDENTIAL_OPTIONS = 0x7L
const val MAKE_CREDENTIAL_PIN_AUTH = 0x8L
const val MAKE_CREDENTIAL_PIN_PROTOCOL = 0x9L

const val MAKE_CREDENTIAL_RESPONSE_FMT = 0x1L
const val MAKE_CREDENTIAL_RESPONSE_AUTH_DATA = 0x2L
const val MAKE_CREDENTIAL_RESPONSE_ATT_STMT = 0x3L

const val GET_ASSERTION_RP_ID = 0x1L
const val GET_ASSERTION_CLIENT_DATA_HASH = 0x2L
const val GET_ASSERTION_ALLOW_LIST = 0x3L
const val GET_ASSERTION_EXTENSIONS = 0x4L
const val GET_ASSERTION_OPTIONS = 0x5L
const val GET_ASSERTION_PIN_AUTH = 0x6L
const val GET_ASSERTION_PIN_PROTOCOL = 0x7L

const val GET_ASSERTION_RESPONSE_CREDENTIAL = 0x1L
const val GET_ASSERTION_RESPONSE_AUTH_DATA = 0x2L
const val GET_ASSERTION_RESPONSE_SIGNATURE = 0x3L
const val GET_ASSERTION_RESPONSE_USER = 0x4L
const val GET_ASSERTION_RESPONSE_NUMBER_OF_CREDENTIALS = 0x5L

const val GET_INFO_RESPONSE_VERSIONS = 0x1L
const val GET_INFO_RESPONSE_EXTENSIONS = 0x2L
const val GET_INFO_RESPONSE_AAGUID = 0x3L
const val GET_INFO_RESPONSE_OPTIONS = 0x4L
const val GET_INFO_RESPONSE_MAX_MSG_SIZE = 0x5L
const val GET_INFO_RESPONSE_PIN_PROTOCOLS = 0x6L
// These parts of the GetInfo response are not yet in the public CTAP spec, but have been picked up
// from
// https://chromium.googlesource.com/chromium/src/+/acef6fd7468307321aeab22853f2b6d0d5d6462a
const val GET_INFO_RESPONSE_MAX_CREDENTIAL_COUNT_IN_LIST = 0x7L
const val GET_INFO_RESPONSE_MAX_CREDENTIAL_ID_LENGTH = 0x8L
// These parts of the GetInfo response are also not yet public, but have been picked up from
// https://groups.google.com/a/fidoalliance.org/d/msg/fido-dev/zFbMGu8rfJQ/WE5Wo6tiAgAJ
const val GET_INFO_RESPONSE_TRANSPORTS = 0x9L
const val GET_INFO_RESPONSE_ALGORITHMS = 0xAL

const val CLIENT_PIN_PIN_PROTOCOL = 0x1L
const val CLIENT_PIN_SUB_COMMAND = 0x2L

const val CLIENT_PIN_SUB_COMMAND_GET_KEY_AGREEMENT = 0x2L
const val CLIENT_PIN_GET_KEY_AGREEMENT_RESPONSE_KEY_AGREEMENT = 0x1L

const val COSE_ID_ES256 = -7L
const val COSE_ID_ECDH = -25L
@ExperimentalUnsignedTypes
val COSE_KEY_ES256_TEMPLATE = mapOf(
    1L to CborLong(2), // kty: EC2 key type
    3L to CborLong(COSE_ID_ES256), // alg: ES256 signature algorithm
    -1L to CborLong(1) // crv: P-256 curve
)
@ExperimentalUnsignedTypes
val COSE_KEY_ECDH_TEMPLATE = mapOf(
    1L to CborLong(2), // kty: EC2 key type
    3L to CborLong(COSE_ID_ECDH), // alg: ECDH key agreement algorithm
    -1L to CborLong(1) // crv: P-256 curve
)
const val COSE_KEY_EC256_X = -2L
const val COSE_KEY_EC256_Y = -3L

const val FLAGS_USER_PRESENT = 1.toByte()
const val FLAGS_USER_VERIFIED = (1 shl 2).toByte()
const val FLAGS_AT_INCLUDED = (1 shl 6).toByte()
const val FLAGS_ED_INCLUDED = (1 shl 7).toByte()

val ANDROID_KEYSTORE_ATTESTATION_AAGUID = byteArrayOf(
    0x2b, 0x21, 0x31, 0xa6.toByte(), 0x89.toByte(), 0x01, 0x4d, 0x2d,
    0x8e.toByte(), 0x77, 0xe9.toByte(), 0x90.toByte(), 0xa6.toByte(), 0x2b, 0xfd.toByte(), 0x41
)
val SELF_ATTESTATION_AAGUID = ByteArray(16)
val BASIC_ATTESTATION_AAGUID = byteArrayOf(
    0x1d, 0x6e, 0x98.toByte(), 0x93.toByte(), 0x51, 0x70, 0x7e, 0xdf.toByte(),
    0xfd.toByte(), 0x42, 0xce.toByte(), 0x36, 0x9b.toByte(), 0x6f, 0xaa.toByte(), 0xb4.toByte()
)

const val HMAC_SECRET_KEY_AGREEMENT = 0x1L
const val HMAC_SECRET_SALT_ENC = 0x2L
const val HMAC_SECRET_SALT_AUTH = 0x3L

interface ExtensionInput

object NoInput : ExtensionInput

data class HmacSecretAuthenticateInput(
    val keyAgreement: PublicKey,
    val saltEnc: ByteArray,
    val saltAuth: ByteArray
) : ExtensionInput

data class TxAuthSimpleAuthenticateInput(val prompt: String) : ExtensionInput

enum class Extension(val identifier: String) {
    HmacSecret("hmac-secret"),
    SupportedExtensions("exts"),
    TxAuthSimple("txAuthSimple"),
    UserVerificationMethod("uvm");

    @ExperimentalUnsignedTypes
    fun parseInput(
        input: CborValue,
        action: AuthenticatorAction,
        canUseDisplay: Boolean
    ): ExtensionInput {
        require(action == AUTHENTICATE || action == REGISTER)
        return when (this) {
            HmacSecret -> {
                when (action) {
                    AUTHENTICATE -> {
                        val cosePublicKey = input.getRequired(HMAC_SECRET_KEY_AGREEMENT)
                        if (cosePublicKey !is CborLongMap || cosePublicKey.value.size != 5)
                            CTAP_ERR(InvalidParameter, "Invalid COSE as hmac-secret keyAgreement")
                        for ((key, value) in COSE_KEY_ECDH_TEMPLATE) {
                            if (cosePublicKey.getRequired(key) != value)
                                CTAP_ERR(
                                    InvalidParameter,
                                    "Invalid ECDH COSE as hmac-secret keyAgreement"
                                )
                        }
                        val rawX = cosePublicKey.getRequired(COSE_KEY_EC256_X).unbox<ByteArray>()
                        if (rawX.size != 32)
                            CTAP_ERR(
                                InvalidParameter,
                                "Incorrect length for x in keyAgreement: ${rawX.size}"
                            )
                        val rawY = cosePublicKey.getRequired(COSE_KEY_EC256_Y).unbox<ByteArray>()
                        if (rawY.size != 32)
                            CTAP_ERR(
                                InvalidParameter,
                                "Incorrect length for y in keyAgreement: ${rawY.size}"
                            )
                        val saltEnc = input.getRequired(HMAC_SECRET_SALT_ENC).unbox<ByteArray>()
                        if (saltEnc.size != 32 && saltEnc.size != 64)
                            CTAP_ERR(
                                InvalidParameter,
                                "Incorrect length for saltEnc in keyAgreement: ${saltEnc.size}"
                            )
                        val saltAuth = input.getRequired(HMAC_SECRET_SALT_AUTH).unbox<ByteArray>()
                        if (saltAuth.size != 16)
                            CTAP_ERR(
                                InvalidParameter,
                                "Incorrect length for saltAuth in keyAgreement: ${saltAuth.size}"
                            )

                        val publicPoint = ECPoint(BigInteger(1, rawX), BigInteger(1, rawY))
                        val publicSpec =
                            ECPublicKeySpec(publicPoint, authenticatorKeyAgreementParams)
                        val keyFactory = KeyFactory.getInstance("EC")
                        val publicKey = keyFactory.generatePublic(publicSpec) as ECPublicKey
                        HmacSecretAuthenticateInput(publicKey, saltEnc, saltAuth)
                    }
                    REGISTER -> {
                        if (!input.unbox<Boolean>())
                            CTAP_ERR(
                                InvalidParameter,
                                "Input was not 'true' for hmac-secret in MakeCredential"
                            )
                        NoInput
                    }
                    else -> throw IllegalStateException("action must be AUTHENTICATE or REGISTER")
                }
            }
            SupportedExtensions -> {
                if (action != REGISTER)
                    CTAP_ERR(InvalidParameter, "exts not supported during GetAssertion")
                if (!input.unbox<Boolean>())
                    CTAP_ERR(InvalidParameter, "Input was not 'true' for exts")
                NoInput
            }
            TxAuthSimple -> {
                if (action != AUTHENTICATE)
                    CTAP_ERR(InvalidParameter, "txAuthSimple not supported during MakeCredential")
                // txAuthSimple requires interactive confirmation and therefore requires a transport
                // that can use the display.
                if (!canUseDisplay)
                    CTAP_ERR(UnsupportedExtension)
                val prompt = input.unbox<String>()
                if (prompt.isBlank())
                    CTAP_ERR(InvalidParameter, "Input was only whitespace for txAuthSimple")
                TxAuthSimpleAuthenticateInput(prompt)
            }
            UserVerificationMethod -> {
                if (!input.unbox<Boolean>())
                    CTAP_ERR(InvalidParameter, "Input was not 'true' for uvm")
                NoInput
            }
        }
    }

    companion object {
        val identifiers = values().map { it.identifier }
        val noDisplayIdentifiers = values().filter { it != TxAuthSimple }.map { it.identifier }

        @ExperimentalUnsignedTypes
        val identifiersAsCbor = CborArray(identifiers.map { CborTextString(it) }.toTypedArray())
        @ExperimentalUnsignedTypes
        val noDisplayIdentifiersAsCbor =
            CborArray(noDisplayIdentifiers.map { CborTextString(it) }.toTypedArray())

        fun fromIdentifier(identifier: String) =
            requireNotNull(values().associateBy(Extension::identifier)[identifier])
    }
}

const val USER_VERIFY_PRESENCE = 0x00000001L
const val USER_VERIFY_PASSCODE = 0x00000004L
const val USER_VERIFY_PATTERN = 0x00000080L

const val KEY_PROTECTION_SOFTWARE = 0x0001L
const val KEY_PROTECTION_HARDWARE = 0x0002L
const val KEY_PROTECTION_TEE = 0x0004L

const val MATCHER_PROTECTION_SOFTWARE = 0x0001L
const val MATCHER_PROTECTION_TEE = 0x0002L

@ExperimentalUnsignedTypes
val DUMMY_MAKE_CREDENTIAL_RESPONSE = CborLongMap(
    mapOf(
        MAKE_CREDENTIAL_RESPONSE_AUTH_DATA to CborByteString(ByteArray(37)),
        MAKE_CREDENTIAL_RESPONSE_FMT to CborTextString(AttestationType.SELF.format),
        MAKE_CREDENTIAL_RESPONSE_ATT_STMT to CborTextStringMap(
            mapOf(
                "alg" to CborLong(COSE_ID_ES256),
                "sig" to CborByteString(byteArrayOf())
            )
        )
    )
)

inline fun <reified T : Any> CborValue?.unbox(): T {
    if (this == null)
        CTAP_ERR(MissingParameter, "Failed to unbox ${T::class.java.simpleName} from null")
    if (this is CborBoxedValue<*> && this.value is T) {
        return this.value as T
    } else if (this is CborBoxedValue<*>) {
        val temp = this.value
        if (temp is Any) {
            CTAP_ERR(
                CborUnexpectedType,
                "Failed to unbox ${T::class.java.simpleName}; found ${temp::class.java.simpleName}"
            )
        } else {
            CTAP_ERR(
                CborUnexpectedType,
                "Failed to unbox ${T::class.java.simpleName}; found null"
            )
        }
    } else {
        CTAP_ERR(
            CborUnexpectedType,
            "Failed to unbox ${T::class.java.simpleName} from ${this::class.java.simpleName}"
        )
    }
}

@ExperimentalUnsignedTypes
fun CborValue?.getOptional(index: Long): CborValue? {
    if (this == null)
        CTAP_ERR(InvalidCbor, "Failed to look up '$index'; object could not be parsed")
    if (this !is CborLongMap)
        CTAP_ERR(CborUnexpectedType, "Failed to look up '$index'; object is not a CborLongMap")
    return this.value[index]
}

@ExperimentalUnsignedTypes
fun CborValue?.getRequired(index: Long): CborValue {
    return getOptional(index) ?: CTAP_ERR(MissingParameter, "Required key missing: $index")
}

@ExperimentalUnsignedTypes
fun CborValue?.getOptional(index: String): CborValue? {
    if (this == null)
        CTAP_ERR(InvalidCbor, "Failed to look up '$index'; object could not be parsed")
    if (this !is CborTextStringMap)
        CTAP_ERR(
            CborUnexpectedType,
            "Failed to look up '$index'; object is not a CborTextStringMap"
        )
    return this.value[index]
}

@ExperimentalUnsignedTypes
fun CborValue?.getRequired(index: String): CborValue {
    return getOptional(index) ?: CTAP_ERR(MissingParameter, "Required key missing: $index")
}

fun CborValue?.toCtapSuccessResponse(): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(0)
    this?.writeAsCbor(out)
    return out.toByteArray()
}
