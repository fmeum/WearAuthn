package me.henneke.wearauthn.fido.context

import android.content.Context
import android.security.keystore.*
import android.util.Log
import androidx.core.content.edit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import me.henneke.wearauthn.*
import me.henneke.wearauthn.fido.ctap2.*
import me.henneke.wearauthn.fido.u2f.Response
import me.henneke.wearauthn.ui.defaultSharedPreferences
import java.lang.Integer.max
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.or

private const val TAG = "Keystore"

private const val PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore"
private const val MASTER_SIGNING_KEY_ALIAS = "%MASTER_SIGNING_KEY%"
private const val USER_INFO_ENCRYPTION_KEY_ALIAS = "%USER_INFO_ENCRYPTION_KEY%"
private const val USER_VERIFICATION_FUSE_KEY_ALIAS = "%USER_VERIFICATION_FUSE_KEY%"
private const val HMAC_SECRET_KEY_ALIAS_PREFIX = "%HMAC_SECRET%"

private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
private const val AES_CBC_NO_PADDING = "AES/CBC/NoPadding"

const val USER_VERIFICATION_TIMEOUT_S = 5 * 60 // 5 minutes

fun KeyStore.getSecretKey(keyAlias: String): SecretKey? {
    return (getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
}

fun KeyStore.getPrivateKey(keyAlias: String): PrivateKey? {
    return (getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry)?.privateKey
}

fun KeyStore.getPublicKey(keyAlias: String): PublicKey? {
    return (getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry)?.certificate?.publicKey
}

private fun generateSymmetricKey(
    algorithm: String,
    builder: KeyGenParameterSpec.Builder
): SecretKey? {
    return try {
        val kpg = KeyGenerator.getInstance(
            algorithm,
            PROVIDER_ANDROID_KEYSTORE
        )
        val parameterSpec = builder.build()
        kpg.run {
            init(parameterSpec)
            generateKey()
        }
    } catch (e: Exception) {
        if (e is UserNotAuthenticatedException)
            throw e
        Log.e(TAG, "Failed to generate symmetric key: $e")
        null
    }
}

private fun generateEllipticCurveKey(builder: KeyGenParameterSpec.Builder): KeyPair? {
    return try {
        val kpg =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                PROVIDER_ANDROID_KEYSTORE
            )
        val parameterSpec = builder.build()
        kpg.run {
            initialize(parameterSpec)
            generateKeyPair()
        }
    } catch (e: Exception) {
        if (e is UserNotAuthenticatedException)
            throw e
        Log.e(TAG, "Failed to generate EC key: $e")
        null
    }
}

private val authenticatorKeyAgreementKeyPair: KeyPair by lazy {
    val ecParameterSpec = ECGenParameterSpec("secp256r1")
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(ecParameterSpec)
    kpg.genKeyPair()
}

@ExperimentalUnsignedTypes
val authenticatorKeyAgreementKey
    get() = getCoseRepresentation(authenticatorKeyAgreementKeyPair.public as ECPublicKey, ECAlgorithm.KeyAgreement)

val authenticatorKeyAgreementParams: ECParameterSpec
    get() = (authenticatorKeyAgreementKeyPair.public as ECPublicKey).params

fun agreeOnSharedSecret(platformKey: PublicKey): ByteArray {
    return KeyAgreement.getInstance("ECDH").run {
        init(authenticatorKeyAgreementKeyPair.private)
        doPhase(platformKey, true)
        generateSecret()
    }.sha256()
}

fun decryptSalt(
    sharedSecret: ByteArray,
    saltEnc: ByteArray,
    saltAuth: ByteArray
): ByteArray? {
    val saltAuthComputed = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(sharedSecret, "HmacSHA256"))
        doFinal(saltEnc)
    }.take(16).toByteArray()
    if (!MessageDigest.isEqual(saltAuth, saltAuthComputed))
        return null
    // hmac-secret uses an IV consisting of 0s since the plaintexts are (approximately) random
    val iv = IvParameterSpec(ByteArray(16))
    return Cipher.getInstance(AES_CBC_NO_PADDING).run {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(sharedSecret, AES_CBC_NO_PADDING), iv)
        doFinal(saltEnc)
    }
}

fun encryptHmacOutput(sharedSecret: ByteArray, hmacSecret: ByteArray): ByteArray {
    // hmac-secret uses an IV consisting of 0s since the plaintexts are (approximately) random
    val iv = IvParameterSpec(ByteArray(16))
    return Cipher.getInstance(AES_CBC_NO_PADDING).run {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(sharedSecret, AES_CBC_NO_PADDING), iv)
        doFinal(hmacSecret)
    }
}

fun generateWebAuthnCredential(
    createResidentKey: Boolean = false,
    createHmacSecret: Boolean = false,
    attestationChallenge: ByteArray? = null
): String? {
    val nonce = ByteArray(32)
    SecureRandom.getInstanceStrong().nextBytes(nonce)
    val keyAlias = nonce.base64()
    val purpose = KeyProperties.PURPOSE_SIGN
    val ecParameterSpec = KeyGenParameterSpec.Builder(keyAlias, purpose).apply {
        setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        setDigests(KeyProperties.DIGEST_SHA256)
        setKeySize(256)
        setAttestationChallenge(attestationChallenge)
        if (createResidentKey) {
            setKeyValidityStart(Date.from(Instant.now().minusSeconds(24 * 60 * 60)))
        }
    }
    generateEllipticCurveKey(ecParameterSpec) ?: return null

    if (createHmacSecret) {
        val hmacParameterSpec =
            KeyGenParameterSpec.Builder(
                HMAC_SECRET_KEY_ALIAS_PREFIX + keyAlias,
                KeyProperties.PURPOSE_SIGN
            )
                .apply {
                    setDigests(KeyProperties.DIGEST_SHA256)
                    setKeySize(256)
                }
        if (generateSymmetricKey(
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
                hmacParameterSpec
            ) == null
        ) {
            deleteKey(keyAlias)
            return null
        }
    }

    return keyAlias
}

private fun getOrCreateUserInfoEncryptionKeyIfNecessary(): SecretKey? {
    if (isValidKeyAlias(USER_INFO_ENCRYPTION_KEY_ALIAS))
        return androidKeystore.getSecretKey(USER_INFO_ENCRYPTION_KEY_ALIAS)
    val purposes = KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
    val parameterSpec =
        KeyGenParameterSpec.Builder(USER_INFO_ENCRYPTION_KEY_ALIAS, purposes).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(true)
            setUserAuthenticationValidityDurationSeconds(3 * 24 * 60 * 60)
        }
    return generateSymmetricKey(
        KeyProperties.KEY_ALGORITHM_AES,
        parameterSpec
    ).also {
        if (it == null)
            Log.e(TAG, "Failed to initialize user info encryption key")
    }
}

private fun recreateInvalidatedUserInfoEncryptionKey(): SecretKey? {
    Log.w(TAG, "User info encryption was no longer valid and has been recreated.")
    deleteKey(USER_INFO_ENCRYPTION_KEY_ALIAS)
    return getOrCreateUserInfoEncryptionKeyIfNecessary()
}

fun encryptWithUserInfoEncryptionKey(data: ByteArray): ByteArray? {
    val secretKey = try {
        getOrCreateUserInfoEncryptionKeyIfNecessary()
    } catch (e: UnrecoverableEntryException) {
        recreateInvalidatedUserInfoEncryptionKey()
    } ?: return null
    val cipher = try {
        Cipher.getInstance(AES_GCM_NO_PADDING).apply {
            init(Cipher.ENCRYPT_MODE, secretKey)
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        val newSecretKey = recreateInvalidatedUserInfoEncryptionKey()
            ?: return null
        Cipher.getInstance(AES_GCM_NO_PADDING).apply {
            init(Cipher.ENCRYPT_MODE, newSecretKey)
        }
    }
    val iv = cipher.iv
    check(iv.size < 256)
    val cipherText = cipher.doFinal(data)
    // We assume that the length of the auth tag is 16, which is the default.
    check(cipherText.size == data.size + 16)
    return byteArrayOf(iv.size.toByte()) + iv + cipherText
}

fun decryptWithUserInfoEncryptionKey(data: ByteArray): ByteArray? {
    if (data.isEmpty()) {
        Log.e(TAG, "Failed to decrypt user info: Stored data is empty.")
        return null
    }
    val ivSize = data[0]
    if (data.size < 1 + ivSize) {
        Log.e(TAG, "Failed to decrypt user info: Stored IV size is invalid.")
        return null
    }
    val iv = data.sliceArray(1 until 1 + ivSize)
    val cipherText = data.sliceArray(1 + ivSize until data.size)
    return try {
        val secretKey = androidKeystore.getSecretKey(USER_INFO_ENCRYPTION_KEY_ALIAS) ?: return null
        Cipher.getInstance(AES_GCM_NO_PADDING).run {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            doFinal(cipherText)
        }
    } catch (e: Exception) {
        if (e is UnrecoverableEntryException || e is KeyPermanentlyInvalidatedException) {
            recreateInvalidatedUserInfoEncryptionKey()
        } else if (e is UserNotAuthenticatedException) {
            throw e
        } else {
            Log.e(TAG, "Failed to decrypt user info: $e")
        }
        null
    }
}

fun armUserVerificationFuse(context: Context) {
    if (getUserVerificationState(context) != false)
        return

    context.defaultSharedPreferences.edit {
        putBoolean(FUSE_CREATED_PREFERENCE_KEY, true)
    }
    val parameterSpec =
        KeyGenParameterSpec.Builder(USER_VERIFICATION_FUSE_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .apply {
                setDigests(KeyProperties.DIGEST_SHA256)
                setKeySize(256)
                setUserAuthenticationRequired(true)
                setUserAuthenticationValidityDurationSeconds(USER_VERIFICATION_TIMEOUT_S)
                setUserAuthenticationValidWhileOnBody(true)
            }
    // No need to handle UserNotAuthenticatedException here since the user confirmed their device
    // credential just before this function was called.
    if (generateSymmetricKey(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            parameterSpec
        ) != null
    )
        Log.i(TAG, "Armed user verification fuse")
    else
        Log.e(TAG, "Failed to arm user verification fuse")
}

fun getUserVerificationState(context: Context, obeyTimeout: Boolean = false): Boolean? {
    val fuseCreated = context.defaultSharedPreferences.getBoolean(
        FUSE_CREATED_PREFERENCE_KEY, true
    )
    return try {
        val secretKey = androidKeystore.getSecretKey(USER_VERIFICATION_FUSE_KEY_ALIAS)
            ?: return if (fuseCreated) {
                Log.e(TAG, "Fuse not present but 'fuse_created' preference is set to true")
                null
            } else {
                false
            }
        // Initialize a signature operation to collect a KeyPermanentlyInvalidatedException if the
        // secure lock screen has been disabled since the creation of the fuse.
        Mac.getInstance("HmacSHA256").init(secretKey)
        if (fuseCreated) {
            true
        } else {
            Log.e(TAG, "Fuse present but 'fuse_created' preference is set to false")
            null
        }
    } catch (e: Exception) {
        if (e is UserNotAuthenticatedException) {
            // We do not care about whether the user has recently authenticated, unless we are
            // asked explicitly to check the timeout.
            if (obeyTimeout) {
                throw e
            } else {
                true
            }
        } else {
            if (e !is UnrecoverableEntryException && e !is KeyPermanentlyInvalidatedException)
                Log.e(TAG, "Unexpectedly failed to access fuse: $e")
            null
        }
    }.also { Log.i(TAG, "User verification state is: $it") }
}

private val androidKeystore = KeyStore.getInstance(PROVIDER_ANDROID_KEYSTORE).apply { load(null) }

val isKeystoreEmpty
    get() = androidKeystore.size() == 0

fun isValidKeyAlias(keyAlias: String): Boolean {
    return androidKeystore.containsAlias(keyAlias)
}

fun deleteKey(keyAlias: String) {
    androidKeystore.deleteEntry(keyAlias)
}

fun deleteAllKeys() {
    for (keyAlias in androidKeystore.aliases()) {
        deleteKey(keyAlias)
    }
}

fun getCertificateChain(keyAlias: String): Array<out java.security.cert.Certificate>? {
    return androidKeystore.getCertificateChain(keyAlias)
}

fun initMasterSigningKeyIfNecessary() {
    synchronized(MASTER_SIGNING_KEY_ALIAS) {
        if (!isValidKeyAlias(MASTER_SIGNING_KEY_ALIAS)) {
            val parameterSpec =
                KeyGenParameterSpec.Builder(MASTER_SIGNING_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .apply {
                        setDigests(KeyProperties.DIGEST_SHA256)
                        setKeySize(256)
                    }
            check(
                generateSymmetricKey(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
                    parameterSpec
                ) != null
            ) { "Failed to initialize master signing key" }
        }
    }
}

private fun signWithMasterSigningKey(vararg data: ByteArray): ByteArray {
    val secretKey = androidKeystore.getSecretKey(MASTER_SIGNING_KEY_ALIAS)!!
    return Mac.getInstance("HmacSHA256").run {
        init(secretKey)
        for (datum in data) {
            update(datum)
        }
        doFinal()
    }
}

fun pokeMasterSigningKey() {
    GlobalScope.launch(Dispatchers.IO) {
        signWithMasterSigningKey(byteArrayOf(0))
    }
}

private fun verifyWithMasterSigningKey(signature: ByteArray, vararg data: ByteArray): Boolean {
    return MessageDigest.isEqual(signWithMasterSigningKey(*data), signature)
}

data class Assertion(val authenticatorData: ByteArray, val signature: ByteArray) {
    init {
        require(authenticatorData.size >= 32 + 1 + 4)
    }
}

abstract class Credential {
    abstract val rpIdHash: ByteArray
    protected abstract val keyAlias: String

    private val keyInfo by lazy { getKeyInfo(keyAlias) }
    val isResident: Boolean
        get() = creationDate != null
    val creationDate: Date?
        get() = keyInfo?.keyValidityStart
    val isKeyMaterialInTEE: Boolean
        get() = keyInfo?.isInsideSecureHardware == true

    protected abstract fun toKeyHandle(): ByteArray
    private var _keyHandle: ByteArray? = null
    val keyHandle: ByteArray
        get() = _keyHandle ?: toKeyHandle().also { _keyHandle = it }

    val u2fPublicKeyRepresentation by lazy {
        val publicKey = androidKeystore.getPublicKey(keyAlias) as? ECPublicKey
        if (publicKey != null)
            getUncompressedRepresentation(publicKey)
        else
            null
    }

    @ExperimentalUnsignedTypes
    val ctap2PublicKeyRepresentation by lazy {
        val publicKey = androidKeystore.getPublicKey(keyAlias) as? ECPublicKey
        if (publicKey != null)
            getCoseRepresentation(publicKey, ECAlgorithm.Signature)
        else
            null
    }

    @ExperimentalUnsignedTypes
    fun toCborCredential(): CborTextStringMap {
        return CborTextStringMap(
            mapOf(
                "type" to CborTextString("public-key"),
                "id" to CborByteString(keyHandle)
            )
        )
    }

    fun sign(vararg data: ByteArray): ByteArray {
        val privateKey = androidKeystore.getPrivateKey(keyAlias)!!
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            for (datum in data) {
                update(datum)
            }
            sign()
        }
    }

    @ExperimentalUnsignedTypes
    private fun assert(
        clientDataHash: ByteArray,
        extensionOutputs: CborValue?,
        userPresent: Boolean,
        userVerified: Boolean,
        context: AuthenticatorContext
    ): Assertion {
        val flags = (if (extensionOutputs != null) FLAGS_ED_INCLUDED else 0) or
                (if (userPresent) FLAGS_USER_PRESENT else 0) or
                (if (userVerified) FLAGS_USER_VERIFIED else 0)
        // Either we just created the credential and the counter, or its existence has been checked
        // in fromKeyHandle.
        val counter = context.atomicallyIncrementAndGetCounter(keyAlias)!!
        val authenticatorData =
            rpIdHash + flags.bytes() + counter.bytes() + (extensionOutputs?.toCbor()
                ?: byteArrayOf())
        val signature = sign(authenticatorData, clientDataHash)
        return Assertion(authenticatorData, signature)
    }

    @ExperimentalUnsignedTypes
    fun assertU2f(
        clientDataHash: ByteArray,
        userPresent: Boolean,
        userVerified: Boolean,
        context: AuthenticatorContext
    ): Response.AuthenticationResponse {
        val assertion = assert(clientDataHash, null, userPresent, userVerified, context)
        return Response.AuthenticationResponse(assertion.authenticatorData.sliceArray(32 until 37) + assertion.signature)
    }

    @ExperimentalUnsignedTypes
    fun assertWebAuthn(
        clientDataHash: ByteArray,
        extensionOutputs: CborValue?,
        userPresent: Boolean,
        userVerified: Boolean,
        numberOfCredentials: Int?,
        context: AuthenticatorContext
    ): CborLongMap {
        val assertion = assert(clientDataHash, extensionOutputs, userPresent, userVerified, context)
        val resultMap = mutableMapOf(
            GET_ASSERTION_RESPONSE_CREDENTIAL to toCborCredential(),
            GET_ASSERTION_RESPONSE_AUTH_DATA to CborByteString(assertion.authenticatorData),
            GET_ASSERTION_RESPONSE_SIGNATURE to CborByteString(assertion.signature)
        )
        val usesMultipleResidentKeys = numberOfCredentials != 1
        check(usesMultipleResidentKeys implies isResident)
        if (isResident) {
            // Resident keys are always WebAuthn credentials.
            check(this is WebAuthnCredential)
            // For a resident key, we have to add a "user" field to the result, which contains
            // personal information only if the authenticator does not use the display and there are
            // multiple assertions that need to be returned. At this point, the personal information
            // is not null only if the user has been verified
            val userMap = mutableMapOf<String, CborValue>(
                // userId is ensured to be not null in deserialize
                "id" to CborByteString(userId!!)
            )
            if (!context.isHidTransport && usesMultipleResidentKeys) {
                if (userDisplayName != null || userName != null || userIcon != null)
                    Log.i(TAG, "Revealing personal information to the client")
                userDisplayName?.let { userMap["displayName"] = CborTextString(it) }
                userName?.let { userMap["name"] = CborTextString(it) }
                userIcon?.let { userMap["icon"] = CborTextString(it) }
            }
            resultMap[GET_ASSERTION_RESPONSE_USER] = CborTextStringMap(userMap)
        }
        if (numberOfCredentials != null && numberOfCredentials != 1)
            resultMap[GET_ASSERTION_RESPONSE_NUMBER_OF_CREDENTIALS] =
                CborLong(numberOfCredentials.toLong())

        return CborLongMap(resultMap)
    }

    @ExperimentalUnsignedTypes
    fun delete(context: AuthenticatorContext?) {
        context?.deleteCounter(keyAlias)
        deleteKey(keyAlias)
    }

    companion object {
        @ExperimentalUnsignedTypes
        fun fromKeyHandle(
            keyHandle: ByteArray,
            rpIdHash: ByteArray,
            context: AuthenticatorContext
        ): Credential? {
            require(rpIdHash.size == 32)
            if (keyHandle.size < 64)
                return null
            val keyHandleData = keyHandle.sliceArray(0 until keyHandle.size - 32)
            val keyHandleSignature = keyHandle.sliceArray(keyHandle.size - 32 until keyHandle.size)
            if (!verifyWithMasterSigningKey(
                    keyHandleSignature,
                    rpIdHash,
                    keyHandleData
                )
            )
                return null
            val nonce = keyHandleData.sliceArray(0 until 32)
            val keyAlias = nonce.base64()
            if (!context.isValidWebAuthnCredentialKeyAlias(keyAlias)) {
                Log.e(TAG, "Valid signature, but invalid counter or Keystore entry")
                return null
            }
            return if (keyHandleData.size == 32) {
                // U2F: keyHandleData only consists of the nonce
                U2FCredential(keyAlias, rpIdHash)
            } else {
                // WebAuthn: keyHandleData consists of the nonce, a null byte, and the RP name
                // At this point, keyHandleData has size at least 33
                if (keyHandleData[32] != 0.toByte()) {
                    // This should never happen since we would have had to sign an invalid handle
                    Log.e(TAG, "Encountered invalid signed key handle: missing zero byte")
                    return null
                }
                val rawRpName = keyHandleData.sliceArray(33 until keyHandleData.size)
                val rpName = if (rawRpName.isNotEmpty())
                    rawRpName.decodeToStringOrNull() ?: return null
                else
                    null
                WebAuthnCredential(
                    keyAlias,
                    rpIdHash,
                    rpName
                )
            }.also { it._keyHandle = keyHandle }
        }

        @ExperimentalUnsignedTypes
        fun fromCborCredential(
            credential: CborValue,
            rpIdHash: ByteArray,
            context: AuthenticatorContext
        ): Credential? {
            val map = credential.unbox<Map<String, CborValue>>()
            if (map["type"].unbox<String>() != "public-key")
                return null
            val credentialId = map["id"].unbox<ByteArray>()
            return fromKeyHandle(
                credentialId,
                rpIdHash,
                context
            )
        }
    }

}

data class U2FCredential(override val keyAlias: String, override val rpIdHash: ByteArray) :
    Credential() {

    init {
        require(keyAlias.base64() != null)
        require(rpIdHash.size == 32)
    }

    override fun toKeyHandle(): ByteArray {
        require(rpIdHash.size == 32)
        val nonce = keyAlias.base64()!!
        val keyHandleSignature =
            signWithMasterSigningKey(rpIdHash, nonce)
        return nonce + keyHandleSignature
    }
}

@ExperimentalUnsignedTypes
class WebAuthnCredential(
    override val keyAlias: String,
    override val rpIdHash: ByteArray,
    val rpName: String? = null,
    val userId: ByteArray? = null,
    userDisplayName: String? = null,
    userName: String? = null,
    userIcon: String? = null,
    val encryptedUserMap: ByteArray? = null
) : Credential() {

    init {
        require(keyAlias.base64()?.size == 32)
        require(rpIdHash.size == 32)
        require(rpName == null || rpName.length <= 64)
    }

    var userDisplayName = userDisplayName
        private set
    var userName = userName
        private set
    var userIcon = userIcon
        private set

    override fun toKeyHandle(): ByteArray {
        val nonce = keyAlias.base64()!!
        val keyHandleData = nonce + byteArrayOf(0) + (rpName?.toByteArray() ?: byteArrayOf())
        val keyHandleSignature =
            signWithMasterSigningKey(
                rpIdHash,
                keyHandleData
            )
        return keyHandleData + keyHandleSignature
    }

    fun unlockUserInfoIfNecessary() {
        if (!isResident || encryptedUserMap == null)
            return
        val rawUserMap =
            decryptWithUserInfoEncryptionKey(
                encryptedUserMap
            )
        if (rawUserMap != null) {
            val userMap = fromCborToEnd(rawUserMap)
            userDisplayName = userMap.getOptional("displayName")?.unbox()
            userName = userMap.getOptional("name")?.unbox()
            userIcon = userMap.getOptional("icon")?.unbox()
        }
    }

    fun serialize(userVerified: Boolean): String {
        check(isResident)
        // These fields are always present for resident credentials we just created.
        check(userId != null)
        check(userName != null)
        return CborTextStringMap(mutableMapOf<String, CborValue>(
            "keyAlias" to CborTextString(keyAlias),
            "userId" to CborByteString(userId)
        ).also { map ->
            rpName?.let { map["rpName"] = CborTextString(it) }
            // Personal information is stored only if user verification is enabled, which is allowed
            // by the spec and works around the potential privacy leak of having someone else
            // configure user verification to get access to this information.
            if (userVerified) {
                val userMap = mutableMapOf(
                    "name" to CborTextString(userName!!)
                )
                userDisplayName?.let { userMap["userDisplayName"] = CborTextString(it) }
                userIcon?.let { userMap["icon"] = CborTextString(it) }
                val encryptedUserMap =
                    encryptWithUserInfoEncryptionKey(
                        CborTextStringMap(userMap).toCbor()
                    )
                encryptedUserMap?.let { map["encryptedUser"] = CborByteString(it) }
            }
        }).toCbor().base64()
    }

    @ExperimentalUnsignedTypes
    val androidKeystoreAttestation: CborArray
        get() {
            val certificateChain = getCertificateChain(
                keyAlias
            ) ?: return CborArray(arrayOf())
            return CborArray(certificateChain.map {
                CborByteString(it.encoded)
            }.toTypedArray())
        }

    val hasHmacSecret: Boolean
        get() = androidKeystore.containsAlias(HMAC_SECRET_KEY_ALIAS_PREFIX + keyAlias)

    fun signWithHmacSecret(vararg data: ByteArray): ByteArray? {
        val secretKeyAlias = HMAC_SECRET_KEY_ALIAS_PREFIX + keyAlias
        val secretKey = androidKeystore.getSecretKey(secretKeyAlias) ?: return null
        return Mac.getInstance("HmacSHA256").run {
            init(secretKey)
            for (datum in data) {
                update(datum)
            }
            doFinal()
        }
    }

    companion object {
        fun deserialize(str: String, rpIdHash: ByteArray): WebAuthnCredential? {
            val bytes = str.base64() ?: return null
            val cbor = fromCborToEnd(bytes) as? CborTextStringMap ?: return null
            val map = cbor.value
            val keyAlias = (map["keyAlias"] as? CborTextString)?.value ?: return null
            val rpName = (map["rpName"] as? CborTextString)?.value ?: return null
            val userId = (map["userId"] as? CborByteString)?.value ?: return null
            val encryptedUserMap = (map["encryptedUser"] as? CborByteString)?.value
            val credential = WebAuthnCredential(
                keyAlias = keyAlias,
                rpIdHash = rpIdHash,
                rpName = rpName,
                userId = userId,
                encryptedUserMap = encryptedUserMap
            )
            if (!credential.isResident)
                return null
            return credential
        }
    }
}

private fun getUncompressedRepresentation(publicKey: ECPublicKey): ByteArray {
    val xRaw = publicKey.w.affineX.toByteArray()
    require(xRaw.size <= 32 || (xRaw.size == 33 && xRaw[0] == 0.toByte())) { "Can only handle 256 bit keys." }
    val yRaw = publicKey.w.affineY.toByteArray()
    require(yRaw.size <= 32 || (yRaw.size == 33 && yRaw[0] == 0.toByte())) { "Can only handle 256 bit keys." }
    val uncompressed = ByteBuffer.allocate(65)
    uncompressed.run {
        position(65 - yRaw.size)
        put(yRaw)
        position(65 - 32 - xRaw.size)
        put(xRaw)
        position(0)
        put(0x04)
    }
    return uncompressed.array()
}

enum class ECAlgorithm {
    Signature,
    KeyAgreement
}

@ExperimentalUnsignedTypes
private fun getCoseRepresentation(publicKey: ECPublicKey, algorithm: ECAlgorithm): CborLongMap {
    val xRaw = publicKey.w.affineX.toByteArray()
    require(xRaw.size <= 32 || (xRaw.size == 33 && xRaw[0] == 0.toByte())) { "Can only handle 256 bit keys." }
    val xPadded =
        ByteArray(max(32 - xRaw.size, 0)) + xRaw.slice(max(xRaw.size - 32, 0) until xRaw.size)
    check(xPadded.size == 32)
    val yRaw = publicKey.w.affineY.toByteArray()
    require(yRaw.size <= 32 || (yRaw.size == 33 && yRaw[0] == 0.toByte())) { "Can only handle 256 bit keys." }
    val yPadded =
        ByteArray(max(32 - yRaw.size, 0)) + yRaw.slice(max(yRaw.size - 32, 0) until yRaw.size)
    check(yPadded.size == 32)
    val template = when (algorithm) {
        ECAlgorithm.Signature -> COSE_KEY_ES256_TEMPLATE
        ECAlgorithm.KeyAgreement -> COSE_KEY_ECDH_TEMPLATE
    }
    return CborLongMap(
        template + mapOf(
            COSE_KEY_EC256_X to CborByteString(xPadded),
            COSE_KEY_EC256_Y to CborByteString(yPadded)
        )
    )
}

private fun getKeyInfo(keyAlias: String): KeyInfo? {
    return try {
        when (val key = androidKeystore.getKey(keyAlias, null)) {
            is SecretKey -> {
                val factory =
                    SecretKeyFactory.getInstance(
                        key.getAlgorithm(),
                        PROVIDER_ANDROID_KEYSTORE
                    )
                try {
                    factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                } catch (e: Exception) {
                    null
                }
            }
            is PrivateKey -> {
                val factory = KeyFactory.getInstance(
                    key.getAlgorithm(),
                    PROVIDER_ANDROID_KEYSTORE
                )
                try {
                    factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                } catch (e: java.lang.Exception) {
                    null
                }
            }
            else -> null
        }
    } catch (e: Exception) {
        null
    }
}

fun checkAllKeysInHardware(): Boolean {
    for (alias in androidKeystore.aliases()) {
        val keyInfo = getKeyInfo(alias) ?: return false
        if (!keyInfo.isInsideSecureHardware || keyInfo.origin != KeyProperties.ORIGIN_GENERATED) {
            return false
        }
    }
    return true
}

