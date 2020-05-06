package me.henneke.wearauthn.fido.context

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import android.security.keystore.UserNotAuthenticatedException
import android.text.Html
import android.text.Spanned
import androidx.annotation.WorkerThread
import androidx.core.content.edit
import kotlinx.coroutines.*
import me.henneke.wearauthn.*
import me.henneke.wearauthn.Logging.Companion.i
import me.henneke.wearauthn.fido.context.AuthenticatorAction.*
import me.henneke.wearauthn.fido.ctap2.AttestationType
import me.henneke.wearauthn.fido.ctap2.CTAP_ERR
import me.henneke.wearauthn.fido.ctap2.CborValue
import me.henneke.wearauthn.fido.ctap2.CtapError.OperationDenied
import me.henneke.wearauthn.fido.ctap2.CtapError.Other
import me.henneke.wearauthn.fido.u2f.resolveAppIdHash
import me.henneke.wearauthn.ui.*
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

private const val COUNTERS_PREFERENCE_FILE = "counters"
private val COUNTERS_WRITE_LOCK = Object()

private const val CACHED_CREDENTIAL_ALIAS_PREFERENCE_KEY = "cached_credential_key_alias"
private val CACHED_CREDENTIAL_ALIAS_WRITE_LOCK = Object()

const val FUSE_CREATED_PREFERENCE_KEY = "fuse_created"
private const val USE_ANDROID_ATTESTATION_PREFERENCE_KEY = "use_android_attestation"

private const val RESIDENT_KEY_PREFERENCE_FILE_PREFIX = "rp_id_hash_"
private const val RESIDENT_KEY_RP_ID_HASHES_FILE = "rp_id_hashes"

enum class AuthenticatorAction {
    AUTHENTICATE,
    AUTHENTICATE_NO_CREDENTIALS,
    REGISTER,
    REGISTER_CREDENTIAL_EXCLUDED,
    PLATFORM_GET_TOUCH
}

sealed class RequestInfo(private val context: Context, private val action: AuthenticatorAction) {
    protected abstract val formattedRp: String?
    protected abstract val shortRp: String?
    protected abstract val formattedUser: String?
    protected abstract val formattedAdditionalInfo: String
    protected abstract val shortAdditionalInfo: String

    private val formattedRpPart by lazy {
        if (formattedRp != null) context.getString(
            R.string.generic_part_to,
            formattedRp
        ) else ""
    }
    private val shortRpPart by lazy {
        if (shortRp != null) context.getString(
            R.string.generic_part_to,
            shortRp
        ) else ""
    }
    private val formattedUserPart by lazy {
        if (formattedUser != null) context.getString(
            R.string.generic_part_as,
            formattedUser
        ) else ""
    }

    val confirmationPrompt: Spanned
        get() = Html.fromHtml(
            when (action) {
                AUTHENTICATE -> context.getString(
                    R.string.prompt_authenticate,
                    formattedRpPart,
                    formattedUserPart,
                    formattedAdditionalInfo
                )
                AUTHENTICATE_NO_CREDENTIALS -> context.getString(R.string.prompt_authenticate_no_credentials)
                REGISTER -> context.getString(
                    R.string.prompt_register,
                    formattedRpPart,
                    formattedUserPart,
                    formattedAdditionalInfo
                )
                REGISTER_CREDENTIAL_EXCLUDED -> context.getString(
                    R.string.prompt_register_credential_excluded,
                    formattedRpPart
                )
                PLATFORM_GET_TOUCH -> context.getString(R.string.prompt_platform_get_touch)
            }, Html.FROM_HTML_MODE_LEGACY
        )

    val successMessage: String
        get() = when (action) {
            AUTHENTICATE -> context.getString(
                R.string.message_authenticate,
                shortRpPart,
                shortAdditionalInfo
            )
            AUTHENTICATE_NO_CREDENTIALS -> context.getString(R.string.message_authenticate_no_credentials)
            REGISTER -> context.getString(
                R.string.message_register,
                shortRpPart,
                shortAdditionalInfo
            )
            REGISTER_CREDENTIAL_EXCLUDED -> context.getString(
                R.string.message_register_credential_excluded,
                shortRpPart
            )
            PLATFORM_GET_TOUCH -> context.getString(R.string.message_platform_get_touch)
        }
}

class U2fRequestInfo(
    context: Context,
    action: AuthenticatorAction,
    private val appIdHash: ByteArray
) :
    RequestInfo(context, action) {
    override val formattedRp = resolveAppIdHash(appIdHash)?.let { "<br/><b>$it</b><br/>" }
    override val shortRp = resolveAppIdHash(appIdHash)
    override val formattedUser: String? = null
    override val formattedAdditionalInfo = ""
    override val shortAdditionalInfo = ""
}

class Ctap2RequestInfo(
    context: Context,
    action: AuthenticatorAction,
    rpId: String,
    rpName: String? = null,
    userName: String? = null,
    userDisplayName: String? = null,
    requiresUserVerification: Boolean = false,
    addResidentKeyHint: Boolean = false
) :
    RequestInfo(context, action) {

    override val formattedRp = if (!rpName.isNullOrBlank())
        "<br/><b>${rpId.escapeHtml()}</b><br/>(“${rpName.escapeHtml()}”)<br/>"
    else
        "<br/><b>${rpId.escapeHtml()}</b><br/>"

    override val shortRp = rpId

    override val formattedUser = if (!userName.isNullOrBlank())
        userName.escapeHtml()
    else if (!userDisplayName.isNullOrBlank())
        userDisplayName.escapeHtml()
    else null

    override val formattedAdditionalInfo = if (requiresUserVerification || addResidentKeyHint) {
        "<br/>"
    } else {
        ""
    } + if (requiresUserVerification) {
        when (action) {
            AUTHENTICATE -> context.getString(R.string.prompt_authenticate_user_verification)
            REGISTER -> context.getString(R.string.prompt_register_user_verification)
            else -> ""
        }
    } else {
        ""
    } + if (addResidentKeyHint) {
        when (action) {
            AUTHENTICATE -> context.getString(R.string.prompt_authenticate_resident_key)
            REGISTER -> context.getString(R.string.prompt_register_resident_key)
            else -> ""
        }
    } else {
        ""
    }

    override val shortAdditionalInfo = if (requiresUserVerification && action == REGISTER) {
        context.getString(R.string.message_register_user_verification)
    } else {
        ""
    }
}

enum class AuthenticatorStatus {
    IDLE,
    PROCESSING,
    WAITING_FOR_UP
}

enum class AuthenticatorSpecialStatus {
    RESET,
    USER_NOT_AUTHENTICATED
}

@ExperimentalUnsignedTypes
abstract class AuthenticatorContext(private val context: Context, val isHidTransport: Boolean) {
    abstract fun notifyUser(info: RequestInfo)
    abstract fun handleSpecialStatus(specialStatus: AuthenticatorSpecialStatus)
    abstract suspend fun confirmRequestWithUser(info: RequestInfo): Boolean?
    abstract suspend fun confirmTransactionWithUser(rpId: String, prompt: String): String?

    // We use cached credentials only over NFC, where low latency responses are very important
    private val useCachedCredential = !isHidTransport
    var status: AuthenticatorStatus = AuthenticatorStatus.IDLE
        set(value) {
            d { "Authenticator status changed: $value" }
            field = value
        }
    var getNextAssertionBuffer: Iterator<CborValue>? = null
    var getNextAssertionRequestInfo: RequestInfo? = null

    private val counterPrefs by lazy { context.sharedPreferences(COUNTERS_PREFERENCE_FILE) }

    init {
        initAuthenticator(context)
    }

    fun getUserVerificationState(obeyTimeout: Boolean = false): Boolean? {
        return getUserVerificationState(
            context,
            obeyTimeout
        )
    }

    fun getOrCreateFreshWebAuthnCredential(
        createResidentKey: Boolean = false,
        createHmacSecret: Boolean = false,
        attestationChallenge: ByteArray? = null
    ): Pair<String, AttestationType>? {
        val useAndroidAttestation =
            context.defaultSharedPreferences.getBoolean(
                USE_ANDROID_ATTESTATION_PREFERENCE_KEY, true
            )
        val actualAttestationChallenge = if (useAndroidAttestation) attestationChallenge else null

        if (useCachedCredential && !createResidentKey && !createHmacSecret) {
            synchronized(CACHED_CREDENTIAL_ALIAS_WRITE_LOCK) {
                val keyAlias =
                    getCachedCredentialKeyAlias(context)
                if (keyAlias != null) {
                    setCachedCredentialKeyAlias(
                        context,
                        null
                    )
                    // attestationChallenge is ignored when using a cached key
                    return Pair(keyAlias, AttestationType.BASIC)
                }
            }
        }

        val keyAlias = generateWebAuthnCredential(
            createResidentKey = createResidentKey,
            createHmacSecret = createHmacSecret,
            attestationChallenge = actualAttestationChallenge
        )
        if (keyAlias == null) {
            if (actualAttestationChallenge == null) {
                w { "Key generation failed without attestation; giving up" }
                return null
            }
            // We failed to generate a Keystore key, which may be due to attestation failing on this
            // device. Since attestation is not essential, we fall back to self attestation for all
            // future key generations.
            w { "Key generation failed; falling back to self attestation in the future" }
            context.defaultSharedPreferences.edit {
                putBoolean(USE_ANDROID_ATTESTATION_PREFERENCE_KEY, false)
            }
            // Directly retry without attestation; explicitly set attestation challenge to null to
            // prevent an infinite loop in case shared preferences are flaky.
            return getOrCreateFreshWebAuthnCredential(
                createResidentKey = createResidentKey,
                createHmacSecret = createHmacSecret,
                attestationChallenge = null
            )
        }
        // For the foreseeable future, we use Basic attestation even if we managed to generate a
        // credential with Android KeyStore attestation since most RPs that rely on attestation are
        // not compatible with this type.
        return Pair(keyAlias, AttestationType.BASIC)
    }

    fun refreshCachedWebAuthnCredentialIfNecessary() {
        refreshCachedWebAuthnCredentialIfNecessary(context)
    }

    fun initCounter(keyAlias: String) {
        synchronized(COUNTERS_WRITE_LOCK) {
            setCounter(keyAlias, 0u)
        }
    }

    fun atomicallyIncrementAndGetCounter(keyAlias: String): UInt? {
        synchronized(COUNTERS_WRITE_LOCK) {
            val current = getCounter(keyAlias) ?: return null
            val new = current + 1u
            setCounter(keyAlias, new)
            return new
        }
    }

    fun isValidWebAuthnCredentialKeyAlias(keyAlias: String): Boolean {
        return getCounter(keyAlias) != null && isValidKeyAlias(keyAlias)
    }

    suspend fun <T> authenticateUserFor(block: () -> T): T? {
        // Confirm device credential and retry if block throws a UserNotAuthenticatedException.
        return try {
            block()
        } catch (e1: UserNotAuthenticatedException) {
            confirmDeviceCredentialInternal(updateAuthenticatorStatus = true)
            try {
                block()
            } catch (e2: UserNotAuthenticatedException) {
                null
            }
        }
    }

    suspend fun verifyUser(): Boolean {
        val keyguardManager = context.keyguardManager ?: return false
        if (keyguardManager.isDeviceLocked)
            return false
        return try {
            // Check whether user verification is configured; throws an exception if the user has
            // not authenticated during the timeout duration.
            getUserVerificationState(obeyTimeout = true) == true
        } catch (e: UserNotAuthenticatedException) {
            if (!isHidTransport) {
                handleSpecialStatus(AuthenticatorSpecialStatus.USER_NOT_AUTHENTICATED)
                false
            } else {
                confirmDeviceCredentialInternal(updateAuthenticatorStatus = true)
                try {
                    getUserVerificationState(obeyTimeout = true) == true
                } catch (e: UserNotAuthenticatedException) {
                    false
                }
            }
        }
    }

    suspend fun confirmDeviceCredential() {
        confirmDeviceCredentialInternal(updateAuthenticatorStatus = false)
    }

    private suspend fun confirmDeviceCredentialInternal(updateAuthenticatorStatus: Boolean) {
        if (updateAuthenticatorStatus)
            status = AuthenticatorStatus.WAITING_FOR_UP
        withContext(Dispatchers.Main) {
            val confirmCredentialJob = launch {
                suspendCoroutine<Nothing?> { continuation ->
                    val intent =
                        Intent(context, ConfirmDeviceCredentialActivity::class.java).apply {
                            putExtra(
                                EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER,
                                object : ResultReceiver(Handler()) {
                                    override fun onReceiveResult(
                                        resultCode: Int,
                                        resultData: Bundle?
                                    ) {
                                        continuation.resume(null)
                                    }
                                })
                            // Starting with Android P (due to a bug, Oreo is excepted),
                            // FLAG_ACTIVITY_NEW_TASK needs to be set when launching an activity
                            // from a non-activity context.
                            // https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-wear-9.0.0_r14/core/java/android/app/ContextImpl.java#907
                            if (context !is Activity)
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                    context.startActivity(intent)
                }
            }
            delay(1_000)
            wink(context)
            confirmCredentialJob.join()
        }
        if (updateAuthenticatorStatus)
            status = AuthenticatorStatus.PROCESSING
    }

    suspend fun chooseCredential(credentials: List<Credential>): Credential? {
        check(isHidTransport)
        require(credentials.isNotEmpty())
        if (credentials.size == 1)
            return credentials.first()
        // If there is more than one credential to choose from, all of them must be resident.
        require(credentials.all { it is WebAuthnCredential && it.isResident })
        val credentialsArray = credentials.map { it as WebAuthnCredential }.toTypedArray()
        status = AuthenticatorStatus.WAITING_FOR_UP
        val credential = withContext(Dispatchers.Main) {
            suspendCancellableCoroutine<WebAuthnCredential?> { continuation ->
                val dialog = CredentialChooserDialog(credentialsArray, context) {
                    continuation.resume(it)
                }
                dialog.show()
                continuation.invokeOnCancellation {
                    dialog.dismiss()
                }
            }
        }
        status = AuthenticatorStatus.PROCESSING
        return credential
    }

    suspend fun setResidentCredential(
        rpId: String,
        userId: ByteArray,
        credential: WebAuthnCredential,
        userVerified: Boolean
    ) {
        require(userId.size <= 64)
        val rpIdHash = rpId.sha256()
        val encodedUserId = userId.base64()
        val encodedKeyHandle = credential.keyHandle.base64()
        val serializedCredential = try {
            authenticateUserFor {
                credential.serialize(userVerified)
            } ?: CTAP_ERR(OperationDenied)
        } catch (e: Exception) {
            e { "Failed to serialize user data: $e" }
            CTAP_ERR(Other)
        }
        v { "Storing resident credential information: {'rpId': '${rpId}', 'uid+$encodedUserId': '$serializedCredential', 'kh+$encodedKeyHandle': '$encodedUserId'}" }
        getResidentKeyPrefsForRpId(rpIdHash).edit {
            putString("rpId", rpId)
            putString("uid+$encodedUserId", serializedCredential)
            putString("kh+$encodedKeyHandle", encodedUserId)
        }
        i { "Resident credential stored" }
    }

    fun lookupAndReplaceWithResidentCredential(credential: Credential): Credential {
        val encodedKeyHandle = credential.keyHandle.base64()
        val encodedUserId =
            getResidentKeyPrefsForRpId(credential.rpIdHash).getString("kh+$encodedKeyHandle", null)
                ?: return credential
        return (getResidentCredential(credential.rpIdHash, encodedUserId) ?: credential).also {
            if (it != credential)
                i { "Replaced allow list credential with resident credential" }
        }
    }

    fun getResidentCredential(
        rpIdHash: ByteArray,
        encodedUserId: String
    ): WebAuthnCredential? {
        require(rpIdHash.size == 32)
        val serialized =
            getResidentKeyPrefsForRpId(rpIdHash).getString("uid+$encodedUserId", null)
                ?: return null
        return WebAuthnCredential.deserialize(serialized, rpIdHash)
    }

    fun deleteResidentCredential(credential: WebAuthnCredential) =
        Companion.deleteResidentCredential(context, credential)

    fun getResidentKeyUserIdsForRpId(rpIdHash: ByteArray): List<String> {
        require(rpIdHash.size == 32)
        val prefs = getResidentKeyPrefsForRpId(rpIdHash)
        return prefs.all.keys.filter { it.startsWith("uid+") }
            .map { it.substring(4) }.toList()
    }

    fun makeU2fRequestInfo(action: AuthenticatorAction, appIdHash: ByteArray) =
        U2fRequestInfo(context.applicationContext, action = action, appIdHash = appIdHash)

    fun makeCtap2RequestInfo(
        action: AuthenticatorAction,
        rpId: String,
        rpName: String? = null,
        userName: String? = null,
        userDisplayName: String? = null,
        requiresUserVerification: Boolean = false,
        addResidentKeyHint: Boolean = false
    ) = Ctap2RequestInfo(
        context.applicationContext,
        action = action,
        rpId = rpId,
        rpName = rpName,
        userName = userName,
        userDisplayName = userDisplayName,
        requiresUserVerification = requiresUserVerification,
        addResidentKeyHint = addResidentKeyHint
    )

    private fun getResidentKeyPrefsForRpId(rpIdHash: ByteArray) =
        Companion.getResidentKeyPrefsForRpId(context, rpIdHash)

    suspend fun requestReset(): Boolean {
        return try {
            status = AuthenticatorStatus.WAITING_FOR_UP
            withContext(Dispatchers.Main) {
                suspendCoroutine<Boolean> { continuation ->
                    val intent =
                        Intent(context, ManageSpaceActivity::class.java).apply {
                            putExtra(
                                EXTRA_MANAGE_SPACE_RECEIVER,
                                object : ResultReceiver(Handler()) {
                                    override fun onReceiveResult(
                                        resultCode: Int,
                                        resultData: Bundle?
                                    ) {
                                        continuation.resume(resultCode == Activity.RESULT_OK)
                                    }
                                })
                        }
                    context.startActivity(intent)
                }
            }
        } finally {
            status = AuthenticatorStatus.PROCESSING
        }
    }

    private fun getCounter(keyAlias: String): UInt? {
        val counter = counterPrefs.getLong(keyAlias, -1)
        return if (counter >= 0) counter.toUInt() else null
    }

    private fun setCounter(keyAlias: String, counter: UInt) {
        counterPrefs.edit {
            putLong(keyAlias, counter.toLong())
        }
    }

    internal fun deleteCounter(keyAlias: String) {
        counterPrefs.edit {
            remove(keyAlias)
        }
    }

    companion object : Logging {
        override val TAG = "AuthenticatorContext"

        fun initAuthenticator(context: Context) {
            if (isKeystoreEmpty) {
                context.defaultSharedPreferences.edit {
                    putBoolean(FUSE_CREATED_PREFERENCE_KEY, false)
                }
                i { "Set 'fuse_created' preference to false" }
            }
            initMasterSigningKeyIfNecessary()
            // We create a dummy signature with the master signing key to get it cached.
            pokeMasterSigningKey()
        }

        fun refreshCachedWebAuthnCredentialIfNecessary(context: Context) {
            synchronized(CACHED_CREDENTIAL_ALIAS_WRITE_LOCK) {
                val keyAlias = getCachedCredentialKeyAlias(context)
                if (keyAlias == null) {
                    val newKeyAlias = generateWebAuthnCredential()
                    if (newKeyAlias == null) {
                        e { "Failed to refresh WebAuthn credential cache" }
                    } else {
                        setCachedCredentialKeyAlias(
                            context,
                            newKeyAlias
                        )
                        i { "Refreshed the credential cache" }
                    }
                }
            }
        }

        private fun getCachedCredentialKeyAlias(context: Context): String? {
            return context.defaultSharedPreferences.getString(
                CACHED_CREDENTIAL_ALIAS_PREFERENCE_KEY, null
            )
        }

        private fun setCachedCredentialKeyAlias(context: Context, keyAlias: String?) {
            context.defaultSharedPreferences.edit {
                putString(CACHED_CREDENTIAL_ALIAS_PREFERENCE_KEY, keyAlias)
            }
        }


        @WorkerThread
        suspend fun deleteAllData(context: Context) {
            withContext(Dispatchers.IO) {
                context.defaultSharedPreferences.edit(commit = true) {
                    remove(CACHED_CREDENTIAL_ALIAS_PREFERENCE_KEY)
                    remove(FUSE_CREATED_PREFERENCE_KEY)
                }
                context.sharedPreferences(COUNTERS_PREFERENCE_FILE).edit(commit = true) {
                    clear()
                }
                for (rpIdHashString in context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE).all.keys) {
                    context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE + rpIdHashString)
                        .edit(commit = true) {
                            clear()
                        }
                }
                context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE).edit(commit = true) {
                    clear()
                }
                deleteAllKeys()

                initAuthenticator(context)
            }
        }

        fun deleteResidentCredential(context: Context, credential: WebAuthnCredential) {
            check(credential.userId != null)
            val rpIdHashString = credential.rpIdHash.base64()
            val encodedUserId = credential.userId.base64()
            val encodedKeyHandle = credential.keyHandle.base64()
            val rpPrefs = getResidentKeyPrefsForRpId(context, credential.rpIdHash)
            rpPrefs.edit {
                remove("uid+$encodedUserId")
                remove("kh+$encodedKeyHandle")
            }
            if (rpPrefs.all.none { it.key.startsWith("uid+") || it.key.startsWith("kh+") }) {
                // This was the last resident credential for this RP, delete its record.
                context.deleteSharedPreferences(RESIDENT_KEY_PREFERENCE_FILE_PREFIX + rpIdHashString)
                context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE).edit {
                    remove(rpIdHashString)
                }
            }
        }


        private fun getResidentKeyPrefsForRpId(
            context: Context,
            rpIdHash: ByteArray
        ): SharedPreferences {
            val rpIdHashString = rpIdHash.base64()
            v { "Writing RP ID hash entry for $rpIdHashString" }
            context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE).edit {
                putBoolean(rpIdHashString, true)
            }
            return context.sharedPreferences(RESIDENT_KEY_PREFERENCE_FILE_PREFIX + rpIdHashString)
        }

        fun getAllResidentCredentials(context: Context): Map<String, List<WebAuthnCredential>> {
            var unknownSiteCounter = 1
            i { "Looking up all resident credentials" }
            return context.sharedPreferences(RESIDENT_KEY_RP_ID_HASHES_FILE).all.keys
                .sorted() // Guarantee deterministic assignment of indices to RPs without stored rpId
                .also {
                    d { "Found ${it.size} entries in RP ID hash file" }
                }
                .mapNotNull {
                    it.base64()
                }.also {
                    d { "Successfully decoded ${it.size} encoded RP ID hashes" }
                }
                .map { rpIdHash ->
                    val rpPrefs =
                        context.sharedPreferences(RESIDENT_KEY_PREFERENCE_FILE_PREFIX + rpIdHash.base64())
                    val rpId = rpPrefs.getString("rpId", null)
                        ?: context.getString(
                            R.string.title_prefix_unknown_site_with_number,
                            unknownSiteCounter
                        ).also { unknownSiteCounter++ }
                    val credentials = rpPrefs.all.keys
                        .filter { it.startsWith("uid+") }
                        .also {
                            v { "Found ${it.size} user IDs for '$rpId'" }
                        }
                        .mapNotNull {
                            WebAuthnCredential.deserialize(
                                rpPrefs.getString(it, null) ?: return@mapNotNull null,
                                rpIdHash
                            )
                        }.sortedByDescending { it.creationDate }
                    Pair(rpId, credentials).also {
                        v { "Deserialized ${it.second.size} credentials for '$rpId'" }
                    }
                }.toMap().also {
                    d { "Found resident credentials for ${it.size} RPs with ${unknownSiteCounter - 1} unknown sites" }
                }
        }

        fun isScreenLockEnabled(context: Context) = context.keyguardManager?.isDeviceSecure == true
    }
}
