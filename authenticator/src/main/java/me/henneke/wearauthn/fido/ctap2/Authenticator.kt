package me.henneke.wearauthn.fido.ctap2

import android.util.Log
import me.henneke.wearauthn.*
import me.henneke.wearauthn.fido.context.*
import me.henneke.wearauthn.fido.context.AuthenticatorAction.*
import kotlin.experimental.or


@ExperimentalUnsignedTypes
object Authenticator {
    private const val TAG = "Ctap2Authenticator"

    suspend fun handle(context: AuthenticatorContext, rawRequest: ByteArray): ByteArray {
        context.status = AuthenticatorStatus.PROCESSING
        return try {
            if (rawRequest.isEmpty())
                throw CtapErrorException(CtapError.InvalidLength)
            if (rawRequest.size > 1 + MAX_CBOR_MSG_SIZE)
                throw CtapErrorException(CtapError.RequestTooLarge)
            val rawRequestIterator = rawRequest.iterator()
            val command = RequestCommand.fromByte(rawRequestIterator.next())
                ?: throw CtapErrorException(CtapError.InvalidCommand)
            when (command) {
                RequestCommand.MakeCredential -> {
                    Log.i(TAG, "MakeCredential called")
                    val params = fromCborToEnd(
                        rawRequestIterator
                    )
                        ?: throw CtapErrorException(CtapError.InvalidCbor)
                    handleMakeCredential(context, params)
                }
                RequestCommand.GetAssertion -> {
                    Log.i(TAG, "GetAssertion called")
                    val params = fromCborToEnd(
                        rawRequestIterator
                    )
                        ?: throw CtapErrorException(CtapError.InvalidCbor)
                    handleGetAssertion(context, params)
                }
                RequestCommand.GetNextAssertion -> {
                    Log.i(TAG, "GetNextAssertion called")
                    if (rawRequest.size != 1)
                        throw CtapErrorException(CtapError.InvalidLength)
                    handleGetNextAssertion(context)
                }
                RequestCommand.GetInfo -> {
                    Log.i(TAG, "GetInfo called")
                    if (rawRequest.size != 1)
                        throw CtapErrorException(CtapError.InvalidLength)
                    handleGetInfo(context)
                }
                RequestCommand.Reset -> {
                    Log.i(TAG, "Reset called")
                    if (rawRequest.size != 1)
                        throw CtapErrorException(CtapError.InvalidLength)
                    handleReset(context)
                }
            }.toCtapSuccessResponse()
        } catch (e: CtapErrorException) {
            Log.w(TAG, "CTAP2 operation failed: ${e.error}")
            byteArrayOf(e.error.value)
        } finally {
            context.status = AuthenticatorStatus.IDLE
        }
    }

    private suspend fun handleMakeCredential(
        context: AuthenticatorContext,
        params: CborValue
    ): CborValue {
        val clientDataHash =
            params.getRequired(MAKE_CREDENTIAL_CLIENT_DATA_HASH).unbox<ByteArray>()

        val rp = params.getRequired(MAKE_CREDENTIAL_RP)
        val rpId: String = rp.getRequired("id").unbox()
        val rpIdHash = rpId.sha256()
        val rpName = rp.getOptional("name")?.unbox<String>()?.truncate(64)
        // Ensure that the RP icon is a string, even though we do not use it.
        rp.getOptional("icon")?.unbox<String>()

        val user = params.getRequired(MAKE_CREDENTIAL_USER)
        val userId = user.getRequired("id").unbox<ByteArray>()
        if (userId.size > 64)
            throw CtapErrorException(CtapError.InvalidLength)
        val userName = user.getRequired("name").unbox<String>().truncate(64)
        val userDisplayName = user.getOptional("displayName")?.unbox<String>()?.truncate(64)
        val userIcon = user.getOptional("icon")?.unbox<String>()

        val pubKeyCredParams =
            params.getRequired(MAKE_CREDENTIAL_PUB_KEY_CRED_PARAMS).unbox<Array<CborValue>>()
        val excludeList =
            params.getOptional(MAKE_CREDENTIAL_EXCLUDE_LIST)?.unbox<Array<CborValue>>()
        val extensions =
            params.getOptional(MAKE_CREDENTIAL_EXTENSIONS)?.unbox<Map<String, CborValue>>()
        val options = params.getOptional(MAKE_CREDENTIAL_OPTIONS)

        // Chrome will send dummy MakeCredential requests to collect a touch after all credentials
        // in the allowList of a GetAssertion request have been silently probed and were not
        // recognized by the authenticator or if user verification/resident key is requested and the
        // authenticator does not support it.
        // We detect these requests and show an appropriate confirmation prompt to the user, after
        // which we will either return a dummy response or an OperationDenied error. Chrome will
        // show an error message afterwards, although sometimes only if we didn't deny.
        // https://cs.chromium.org/chromium/src/device/fido/make_credential_task.cc?l=66&rcl=eb40dba9a062951578292de39424d7479f723463
        if (rpId == ".dummy" && userName == "dummy" && clientDataHash.contentEquals("".sha256())) {
            Log.i(
                TAG,
                "Received a Chrome GetTouchRequest, replying with dummy response after confirmation"
            )
            val requestInfo = Ctap2RequestInfo(REQUIREMENTS_NOT_MET_CHROME, rpId)
            val showErrorInBrowser = context.confirmWithUser(requestInfo)
            if (showErrorInBrowser)
                return DUMMY_MAKE_CREDENTIAL_RESPONSE
            else
                throw CtapErrorException(CtapError.OperationDenied)
        }

        // Step 1
        if (excludeList != null) {
            for (cborCredential in excludeList) {
                if (LocalCredential.fromCborCredential(cborCredential, rpIdHash, context) == null)
                    continue
                val requestInfo =
                    Ctap2RequestInfo(
                        action = REGISTER_CREDENTIAL_EXCLUDED,
                        rpId = rpId,
                        rpName = rpName
                    )
                val revealRegistration = context.confirmWithUser(requestInfo)
                if (revealRegistration)
                    throw CtapErrorException(CtapError.CredentialExcluded)
                else
                    throw CtapErrorException(CtapError.OperationDenied)
            }
        }

        // Step 2
        var foundCompatibleAlgorithm = false
        for (pubKeyCredParam in pubKeyCredParams) {
            if (pubKeyCredParam.getRequired("type").unbox<String>() == "public-key" &&
                pubKeyCredParam.getRequired("alg").unbox<Long>() == COSE_ID_ES256
            )
                foundCompatibleAlgorithm = true
        }
        if (!foundCompatibleAlgorithm)
            throw CtapErrorException(CtapError.UnsupportedAlgorithm)

        // Step 3
        var requireResidentKey = false
        var requireUserVerification = false
        if (options != null) {
            if (options.getOptional("rk")?.unbox<Boolean>() == true)
                requireResidentKey = true
            if (options.getOptional("up") != null)
                throw CtapErrorException(CtapError.InvalidOption)
            if (options.getOptional("uv")?.unbox<Boolean>() == true) {
                if (context.getUserVerificationState() != true)
                    throw CtapErrorException(CtapError.UnsupportedOption)
                requireUserVerification = true
            }
        }

        // Step 4
        // We only validate the extension inputs here, the actual processing is done later.
        val supportedExtensions =
            validateExtensionInputs(extensions, REGISTER)

        // Step 7
        // We do not support any PIN protocols
        if (params.getOptional(MAKE_CREDENTIAL_PIN_AUTH) != null)
            throw CtapErrorException(CtapError.PinAuthInvalid)

        // Step 8
        val requestInfo = Ctap2RequestInfo(
            action = REGISTER,
            rpId = rpId,
            rpName = rpName,
            userName = userName,
            userDisplayName = userDisplayName,
            usesResidentKey = requireResidentKey,
            requiresUserVerification = requireUserVerification
        )

        if (!context.confirmWithUser(requestInfo))
            throw CtapErrorException(CtapError.OperationDenied)

        if (requireUserVerification && !context.verifyUser())
            throw CtapErrorException(CtapError.OperationDenied)

        // At this point, user verification has been performed if requested.

        // Step 9
        val (keyAlias, attestationType) =
            context.getOrCreateFreshWebAuthnCredential(
                residentKey = requireResidentKey,
                attestationChallenge = clientDataHash
            ) ?: throw CtapErrorException(CtapError.KeyStoreFull)

        val credential = WebAuthnLocalCredential(
            keyAlias = keyAlias,
            rpIdHash = rpIdHash,
            rpName = rpName,
            userId = userId,
            userDisplayName = userDisplayName,
            userName = userName,
            userIcon = userIcon
        )

        // Step 10
        if (requireResidentKey)
            context.setResidentCredential(
                rpIdHash = rpIdHash,
                userId = userId,
                credential = credential,
                userVerified = requireUserVerification
            )

        // Step 4
        val extensionOutputs = processExtensions(
            supportedExtensions,
            credential,
            true,
            requireUserVerification
        )

        // Step 11
        val credentialPublicKey = credential.ctap2PublicKeyRepresentation
        if (credentialPublicKey == null) {
            credential.delete(context)
            Log.e(TAG, "Failed to get raw public key")
            throw CtapErrorException(CtapError.Other)
        }
        val attestedCredentialData =
            WEARAUTHN_AAGUID + credential.keyHandle.size.toUShort().bytes() + credential.keyHandle + credentialPublicKey.toCbor()

        // At this point, if we have not returned CtapError.OperationDenied, the user has been
        // verified successfully if UV had been requested.
        val flags = FLAGS_AT_INCLUDED or
                (if (extensionOutputs != null) FLAGS_ED_INCLUDED else 0) or
                FLAGS_USER_PRESENT or
                (if (requireUserVerification) FLAGS_USER_VERIFIED else 0)

        val authenticatorData =
            rpIdHash + flags.bytes() + 0.toUInt().bytes() + attestedCredentialData +
                    (extensionOutputs?.toCbor() ?: byteArrayOf())

        val signature = credential.sign(authenticatorData, clientDataHash)

        context.initCounter(keyAlias)

        val attestationStatement = CborTextStringMap(
            when (attestationType) {
                AttestationType.SELF -> mapOf(
                    "alg" to CborLong(COSE_ID_ES256),
                    "sig" to CborByteString(signature)
                )
                AttestationType.ANDROID_KEYSTORE -> mapOf(
                    "alg" to CborLong(COSE_ID_ES256),
                    "sig" to CborByteString(signature),
                    "x5c" to credential.androidKeystoreAttestation
                )
            }
        )

        context.notifyUser(requestInfo)

        return CborLongMap(
            mapOf(
                MAKE_CREDENTIAL_RESPONSE_AUTH_DATA to CborByteString(authenticatorData),
                MAKE_CREDENTIAL_RESPONSE_FMT to CborTextString(attestationType.format),
                MAKE_CREDENTIAL_RESPONSE_ATT_STMT to attestationStatement
            )
        )
    }

    private suspend fun handleGetAssertion(
        context: AuthenticatorContext,
        params: CborValue
    ): CborValue {
        val clientDataHash = params.getRequired(GET_ASSERTION_CLIENT_DATA_HASH).unbox<ByteArray>()

        val rpId = params.getRequired(GET_ASSERTION_RP_ID).unbox<String>()
        val rpIdHash = rpId.sha256()

        val allowList = params.getOptional(GET_ASSERTION_ALLOW_LIST)?.unbox<Array<CborValue>>()
        val extensions =
            params.getOptional(GET_ASSERTION_EXTENSIONS)?.unbox<Map<String, CborValue>>()
        val options = params.getOptional(GET_ASSERTION_OPTIONS)

        // Step 1 is handled further down since it requires input from earlier steps

        // Step 3
        // We do not support any PIN protocols
        if (params.getOptional(GET_ASSERTION_PIN_AUTH) != null)
            throw CtapErrorException(CtapError.PinAuthInvalid)

        // Step 5
        var requireUserPresence = true
        var requireUserVerification = false
        if (options != null) {
            if (options.getOptional("rk") != null)
                throw CtapErrorException(CtapError.InvalidOption)
            if (options.getOptional("up")?.unbox<Boolean>() == false)
                requireUserPresence = false
            if (options.getOptional("uv")?.unbox<Boolean>() == true) {
                if (context.getUserVerificationState() != true)
                    throw CtapErrorException(CtapError.UnsupportedOption)
                requireUserVerification = true
            }
        }

        // Step 6
        // We only validate the extension inputs here, the actual processing is done later.
        val supportedExtensions = validateExtensionInputs(
            extensions,
            AUTHENTICATE
        )

        // Step 1
        val useResidentKey = allowList == null
        val applicableCredentials = if (!useResidentKey) {
            check(allowList != null)
            if (allowList.isEmpty()) {
                // Step 1 of the spec does not list this case, hence we treat it as if there were
                // no credentials found
                emptySequence()
            } else {
                allowList.asSequence().mapNotNull { cborCredential ->
                    LocalCredential.fromCborCredential(cborCredential, rpIdHash, context)
                }.map { credential -> context.lookupAndReplaceWithResidentCredential(credential) }
            }
        } else {
            // Locate all rk credentials bound to the provided rpId
            Log.i(TAG, "Locating resident credentials for $rpId")
            context.getResidentKeyUserIdsForRpId(rpIdHash).asSequence()
                .mapNotNull { userId -> context.getResidentCredential(rpIdHash, userId.base64()) }
                .sortedByDescending { it.creationDate }
        }.toList()

        // Step 9
        val credentialsToUse = if (useResidentKey) {
            applicableCredentials.toList()
        } else {
            val credential = applicableCredentials.firstOrNull()
            if (credential != null) listOf(credential) else listOf()
        }
        val numberOfCredentials = credentialsToUse.size

        // Step 7

        // Since requests requiring user verification may ask the user to confirm their device
        // credentials, we upgrade them to also require user presence.
        if (requireUserVerification)
            requireUserPresence = true

        val requestInfo = if (numberOfCredentials > 0) {
            val firstCredential = credentialsToUse.first() as? WebAuthnLocalCredential
            val singleCredential = numberOfCredentials == 1
            check(!singleCredential implies useResidentKey)
            Ctap2RequestInfo(
                action = AUTHENTICATE,
                rpId = rpId,
                rpName = firstCredential?.rpName,
                userName = if (singleCredential) firstCredential?.userName else null,
                userDisplayName = if (singleCredential) firstCredential?.userDisplayName else null,
                requiresUserVerification = requireUserVerification,
                usesResidentKey = !singleCredential
            )
        } else {
            // We have not found any credentials, ask the user for permission to reveal this fact.
            Ctap2RequestInfo(
                AUTHENTICATE_NO_CREDENTIALS,
                rpId
            )
        }
        if (requireUserPresence && !context.confirmWithUser(requestInfo))
            throw CtapErrorException(CtapError.OperationDenied)
        if (!requireUserPresence)
            Log.i(TAG, "Processing silent GetAssertion request")

        // Step 8
        // It is very important that this step happens after the user presence check of step 7.
        if (numberOfCredentials == 0) {
            context.notifyUser(requestInfo)
            throw CtapErrorException(CtapError.NoCredentials)
        }

        // Step 7 (user verification)
        if (requireUserVerification && !context.verifyUser())
            throw CtapErrorException(CtapError.OperationDenied)

        // At this point, user presence and verification have been performed if requested.

        if (requireUserVerification) {
            for (credential in credentialsToUse) {
                if (credential is WebAuthnLocalCredential) {
                    context.authenticateUserFor {
                        credential.unlockUserInfoIfNecessary()
                    }
                }
            }
        }

        return if (!context.isHidTransport) {
            // Step 10
            val assertionOperationsIterator = credentialsToUse
                .mapIndexed { credentialCounter, nextCredential ->
                    // Step 6
                    // Process extensions.
                    val extensionOutputs = processExtensions(
                        extensions = supportedExtensions,
                        credential = nextCredential,
                        requireUserPresence = requireUserPresence,
                        requireUserVerification = requireUserVerification
                    )
                    nextCredential.assertWebAuthn(
                        clientDataHash = clientDataHash,
                        extensionOutputs = extensionOutputs,
                        userPresent = requireUserPresence,
                        userVerified = requireUserVerification,
                        numberOfCredentials = if (credentialCounter == 0) numberOfCredentials else null,
                        context = context
                    )
                }.iterator()
            // Step 12
            assertionOperationsIterator.next().also {
                if (numberOfCredentials > 1) {
                    context.getNextAssertionBuffer = assertionOperationsIterator
                    context.getNextAssertionRequestInfo = requestInfo
                }
            }
        } else {
            // Step 11
            val credential = context.chooseCredential(credentialsToUse)
                ?: throw CtapErrorException(CtapError.OperationDenied)
            // Step 6
            // Process extensions.
            val extensionOutputs = processExtensions(
                extensions = supportedExtensions,
                credential = credential,
                requireUserPresence = requireUserPresence,
                requireUserVerification = requireUserVerification
            )
            // Step 12
            credential.assertWebAuthn(
                clientDataHash = clientDataHash,
                extensionOutputs = extensionOutputs,
                userPresent = requireUserPresence,
                userVerified = requireUserVerification,
                numberOfCredentials = 1,
                context = context
            )
        }
    }

    private fun handleGetNextAssertion(context: AuthenticatorContext): CborValue {
        if (context.getNextAssertionBuffer?.hasNext() != true || context.getNextAssertionRequestInfo == null)
            throw CtapErrorException(CtapError.NotAllowed)
        val nextAssertion = context.getNextAssertionBuffer!!.next()
        if (context.getNextAssertionBuffer?.hasNext() != true) {
            context.getNextAssertionRequestInfo?.let { context.notifyUser(it) }
            context.getNextAssertionBuffer = null
            context.getNextAssertionRequestInfo = null
        }
        return nextAssertion
    }

    private fun handleGetInfo(context: AuthenticatorContext): CborValue {
        val optionsMap = mutableMapOf(
            "plat" to CborBoolean(false),
            "rk" to CborBoolean(true),
            "up" to CborBoolean(true)
        )
        context.getUserVerificationState()?.let { optionsMap["uv"] = CborBoolean(it) }
        return CborLongMap(
            mapOf(
                GET_INFO_RESPONSE_VERSIONS to CborArray(
                    arrayOf(
                        CborTextString("FIDO_2_0"),
                        CborTextString("U2F_V2")
                    )
                ),
                GET_INFO_RESPONSE_EXTENSIONS to Extension.identifiersAsCbor,
                GET_INFO_RESPONSE_AAGUID to CborByteString(WEARAUTHN_AAGUID),
                GET_INFO_RESPONSE_OPTIONS to CborTextStringMap(optionsMap),
                GET_INFO_RESPONSE_MAX_MSG_SIZE to CborLong(MAX_CBOR_MSG_SIZE),
                // This value is chosen such that most credential lists will fit into a single
                // request while still staying well below the maximal message size when taking
                // the maximal credential ID length into account.
                GET_INFO_RESPONSE_MAX_CREDENTIAL_COUNT_IN_LIST to CborLong(5),
                // Our credential IDs consist of
                // * a signature (32 bytes)
                // * a nonce (32 bytes)
                // * a null byte (WebAuthn only)
                // * the rpName truncated to 64 UTF-16 code units (every UTF-16 code unit can be
                //   coded on at most three UTF-8 bytes)
                GET_INFO_RESPONSE_MAX_CREDENTIAL_ID_LENGTH to CborLong(32 + 32 + 1 + 3 * 64)
                // TODO: Uncomment once understood by at least one client
//                ,
//                GET_INFO_RESPONSE_TRANSPORTS to CborArray(
//                    arrayOf(
//                        CborTextString("nfc"),
//                        CborTextString("usb")
//                    )
//                ),
//                GET_INFO_RESPONSE_ALGORITHMS to CborArray(
//                    arrayOf(
//                        CborTextStringMap(
//                            mapOf(
//                                "alg" to CborLong(-7),
//                                "type" to CborTextString("public-key")
//                            )
//                        )
//                    )
//                )
            )
        )
    }

    private suspend fun handleReset(context: AuthenticatorContext): Nothing? {
        // The FIDO conformance tests demand reset capabilities over any protocol. In order to test
        // the authenticator behavior with UV configured, the UV status also needs to be reenabled
        // after a reset. In order to pass the conformance tests, it is thus required to use the
        // following code variant:
        //
        // context.deleteAllData()
        // context.armUserVerificationFuse()
        // return null

        // Deny reset requests over NFC since there is now way to confirm them with the user.
        if (!context.isHidTransport)
            throw CtapErrorException(CtapError.OperationDenied)
        if (context.requestReset()) {
            return null
        } else {
            context.handleSpecialStatus(AuthenticatorSpecialStatus.RESET)
            throw CtapErrorException(CtapError.OperationDenied)
        }
    }

    private fun validateExtensionInputs(
        extensions: Map<String, CborValue>?,
        action: AuthenticatorAction
    ): Map<Extension, CborValue> {
        if (extensions == null)
            return mapOf()
        val extensionInputs = extensions.filterKeys { identifier ->
            identifier in Extension.identifiers
        }.mapKeys {
            Extension.fromIdentifier(it.key)
        }
        // validateInput throws an appropriate exception if the input is not of the correct form.
        for ((extension, input) in extensionInputs.entries)
            extension.validateInput(input, action)
        return extensionInputs
    }

    private fun processExtensions(
        extensions: Map<Extension, CborValue>,
        credential: LocalCredential,
        requireUserPresence: Boolean,
        requireUserVerification: Boolean
    ): CborValue? {
        val extensionOutputs = extensions.mapValues {
            val extension = it.key
            processExtension(
                extension,
                credential,
                requireUserPresence,
                requireUserVerification
            )
        }
        return if (extensionOutputs.isEmpty())
            null
        else
            CborTextStringMap(extensionOutputs.mapKeys { it.key.identifier })
    }

    private fun processExtension(
        extension: Extension,
        credential: LocalCredential,
        userPresent: Boolean,
        userVerified: Boolean
    ): CborValue {
        return when (extension) {
            Extension.SupportedExtensions -> Extension.identifiersAsCbor
            Extension.UserVerificationMethod -> {
                val keyProtectionType =
                    if (credential.isKeyMaterialInTEE) KEY_PROTECTION_HARDWARE or KEY_PROTECTION_TEE else KEY_PROTECTION_SOFTWARE
                val methods = mutableListOf<CborArray>()
                if (userPresent) {
                    methods.add(
                        CborArray(
                            arrayOf(
                                CborLong(USER_VERIFY_PRESENCE),
                                CborLong(keyProtectionType),
                                CborLong(MATCHER_PROTECTION_SOFTWARE)
                            )
                        )
                    )
                }
                if (userVerified) {
                    methods.add(
                        CborArray(
                            arrayOf(
                                CborLong(USER_VERIFY_PATTERN),
                                CborLong(keyProtectionType),
                                CborLong(MATCHER_PROTECTION_SOFTWARE)
                            )
                        )
                    )
                }
                CborArray(methods.toTypedArray())
            }
        }
    }
}
