package me.henneke.wearauthn.fido.ctap2

import android.util.Log
import kotlinx.coroutines.delay
import me.henneke.wearauthn.*
import me.henneke.wearauthn.fido.context.*
import me.henneke.wearauthn.fido.context.AuthenticatorAction.*
import me.henneke.wearauthn.fido.ctap2.CtapError.*
import kotlin.experimental.or


@ExperimentalUnsignedTypes
object Authenticator {
    private const val TAG = "Ctap2Authenticator"

    suspend fun handle(context: AuthenticatorContext, rawRequest: ByteArray): ByteArray {
        context.status = AuthenticatorStatus.PROCESSING
        return try {
            if (rawRequest.isEmpty())
                CTAP_ERR(InvalidLength, "Empty CBOR request")
            if (rawRequest.size > 1 + MAX_CBOR_MSG_SIZE)
                CTAP_ERR(RequestTooLarge, "CBOR request exceeds maximal size: ${rawRequest.size}")
            val rawRequestIterator = rawRequest.iterator()
            val rawCommand = rawRequestIterator.next()
            val command = RequestCommand.fromByte(rawCommand)
                ?: CTAP_ERR(InvalidCommand, "Unsupported command: $rawCommand")
            when (command) {
                RequestCommand.MakeCredential -> {
                    Log.i(TAG, "MakeCredential called")
                    val params = fromCborToEnd(rawRequestIterator)
                        ?: CTAP_ERR(InvalidCbor, "Invalid CBOR in MakeCredential request")
                    handleMakeCredential(context, params)
                }
                RequestCommand.GetAssertion -> {
                    Log.i(TAG, "GetAssertion called")
                    val params = fromCborToEnd(rawRequestIterator)
                        ?: CTAP_ERR(InvalidCbor, "Invalid CBOR in GetAssertion request")
                    handleGetAssertion(context, params)
                }
                RequestCommand.GetNextAssertion -> {
                    Log.i(TAG, "GetNextAssertion called")
                    if (rawRequest.size != 1)
                        CTAP_ERR(InvalidLength, "Non-empty params for GetNextAssertion")
                    handleGetNextAssertion(context)
                }
                RequestCommand.GetInfo -> {
                    Log.i(TAG, "GetInfo called")
                    if (rawRequest.size != 1)
                        CTAP_ERR(InvalidLength, "Non-empty params for GetInfo")
                    handleGetInfo(context)
                }
                RequestCommand.ClientPIN -> {
                    Log.i(TAG, "ClientPIN called")
                    val params = fromCborToEnd(rawRequestIterator)
                        ?: CTAP_ERR(InvalidCbor, "Invalid CBOR in ClientPIN request")
                    handleClientPIN(params)
                }
                RequestCommand.Reset -> {
                    Log.i(TAG, "Reset called")
                    if (rawRequest.size != 1)
                        CTAP_ERR(InvalidLength, "Non-empty params for Reset")
                    handleReset(context)
                }
            }.toCtapSuccessResponse()
        } catch (e: CtapErrorException) {
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
            CTAP_ERR(InvalidLength, "userId too long: ${userId.size}")
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

        // Chrome and Windows Hello use special dummy requests to request a touch from an
        // authenticator in various situations, such as to confirm a reset request is sent to the
        // correct device or to prevent websites from verifying the availability of a given
        // credential without user interaction.
        // https://cs.chromium.org/chromium/src/device/fido/make_credential_task.cc?l=66&rcl=eb40dba9a062951578292de39424d7479f723463
        if ((rpId == ".dummy" && userName == "dummy") /* Chrome */ ||
                (rpId == "SelectDevice" && userName == "SelectDevice") /* Windows Hello */) {
            val requestInfo = Ctap2RequestInfo(PLATFORM_GET_TOUCH, rpId)
            val followUpInClient = context.confirmRequestWithUser(requestInfo)
            if (followUpInClient)
                return DUMMY_MAKE_CREDENTIAL_RESPONSE
            else
                CTAP_ERR(OperationDenied)
        }

        // Step 1
        if (excludeList != null) {
            for (cborCredential in excludeList) {
                if (Credential.fromCborCredential(cborCredential, rpIdHash, context) == null)
                    continue
                val requestInfo =
                    Ctap2RequestInfo(
                        action = REGISTER_CREDENTIAL_EXCLUDED,
                        rpId = rpId,
                        rpName = rpName
                    )
                val revealRegistration = context.confirmRequestWithUser(requestInfo)
                if (revealRegistration)
                    CTAP_ERR(CredentialExcluded)
                else
                    CTAP_ERR(OperationDenied)
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
            CTAP_ERR(UnsupportedAlgorithm)

        // Step 3
        var requireResidentKey = false
        var requireUserVerification = false
        if (options != null) {
            if (options.getOptional("rk")?.unbox<Boolean>() == true)
                requireResidentKey = true
            if (options.getOptional("up") != null)
                CTAP_ERR(InvalidOption, "Option 'up' specified for MakeCredential")
            if (options.getOptional("uv")?.unbox<Boolean>() == true) {
                if (context.getUserVerificationState() != true)
                    CTAP_ERR(UnsupportedOption)
                requireUserVerification = true
            }
        }

        // Step 4
        // We only validate the extension inputs here, the actual processing is done later.
        val activeExtensions = parseExtensionInputs(
            extensions = extensions,
            action = REGISTER,
            canUseDisplay = context.isHidTransport
        )

        // Step 7
        // We do not support any PIN protocols
        if (params.getOptional(MAKE_CREDENTIAL_PIN_AUTH) != null)
            CTAP_ERR(PinAuthInvalid, "pinAuth sent with MakeCredential")

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

        if (!context.confirmRequestWithUser(requestInfo))
            CTAP_ERR(OperationDenied)

        if (requireUserVerification && !context.verifyUser())
            CTAP_ERR(OperationDenied)

        // At this point, user verification has been performed if requested.

        // Step 9
        val (keyAlias, attestationType) =
            context.getOrCreateFreshWebAuthnCredential(
                createResidentKey = requireResidentKey,
                createHmacSecret = activeExtensions.containsKey(Extension.HmacSecret),
                attestationChallenge = clientDataHash
            ) ?: CTAP_ERR(KeyStoreFull, "Failed to create WebAuthnCredential")

        val credential = WebAuthnCredential(
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
                rpId = rpId,
                userId = userId,
                credential = credential,
                userVerified = requireUserVerification
            )

        // Step 4
        val extensionOutputs = processExtensions(
            extensions = activeExtensions,
            credential = credential,
            requireUserPresence = true,
            requireUserVerification = requireUserVerification,
            action = REGISTER
        )

        // Step 11
        val credentialPublicKey = credential.ctap2PublicKeyRepresentation
        if (credentialPublicKey == null) {
            credential.delete(context)
            Log.e(TAG, "Failed to get raw public key")
            CTAP_ERR(Other)
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
            CTAP_ERR(PinAuthInvalid, "pinAuth sent with GetAssertion")

        // Step 5
        var requireUserPresence = true
        var requireUserVerification = false
        if (options != null) {
            if (options.getOptional("rk") != null)
                CTAP_ERR(InvalidOption, "Option 'rk' specified for GetAssertion")
            if (options.getOptional("up")?.unbox<Boolean>() == false)
                requireUserPresence = false
            if (options.getOptional("uv")?.unbox<Boolean>() == true) {
                if (context.getUserVerificationState() != true)
                    CTAP_ERR(UnsupportedOption)
                requireUserVerification = true
            }
        }

        // Step 6
        // We only validate the extension inputs here, the actual processing is done later.
        val activeExtensions = parseExtensionInputs(
            extensions = extensions,
            action = AUTHENTICATE,
            canUseDisplay = context.isHidTransport
        ).toMutableMap()

        // hmac-secret requires user presence, but the spec is not clear on whether this has to be
        // obtained separately
        if (activeExtensions.containsKey(Extension.HmacSecret))
            requireUserPresence = true
        if (activeExtensions.containsKey(Extension.TxAuthSimple)) {
            if (!requireUserPresence && !requireUserVerification)
                requireUserPresence = true
        }

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
                    Credential.fromCborCredential(cborCredential, rpIdHash, context)
                }.map { credential -> context.lookupAndReplaceWithResidentCredential(credential) }
            }
        } else {
            // Locate all rk credentials bound to the provided rpId
            context.getResidentKeyUserIdsForRpId(rpIdHash).asSequence()
                .mapNotNull { userId -> context.getResidentCredential(rpIdHash, userId.base64()) }
                .sortedByDescending { it.creationDate }
        }.filter {
            // If the hmac-secret extension is requested, we must only offer credentials that were
            // created with hmac-secret enabled.
            if (activeExtensions.containsKey(Extension.HmacSecret))
                (it as? WebAuthnCredential)?.hasHmacSecret == true
            else
                true
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

        // txAuthSimple leads to a prompt that the user has to confirm. This prompt has to be shown
        // before the usual user presence check as per spec, but we omit it if there are no
        // applicable credentials.
        if (activeExtensions.containsKey(Extension.TxAuthSimple) && numberOfCredentials > 0) {
            val txAuthSimpleInput =
                activeExtensions[Extension.TxAuthSimple] as TxAuthSimpleAuthenticateInput
            // The actual prompt confirmed by the user differs from the requested prompt only by
            // potentially containing additional newlines. We simply replace the extension input
            // with the prompt that was actually shown to keep extension handling simple.
            val actualPrompt = context.confirmTransactionWithUser(rpId, txAuthSimpleInput.prompt)
                ?: CTAP_ERR(OperationDenied)
            activeExtensions[Extension.TxAuthSimple] = TxAuthSimpleAuthenticateInput(actualPrompt)
            // Introduce a small delay between the transaction confirmation and the usual
            // GetAssertion confirmation, otherwise the user may inadvertently confirm both with one
            // tap.
            delay(500)
        }

        // Since requests requiring user verification may ask the user to confirm their device
        // credentials, we upgrade them to also require user presence.
        if (requireUserVerification)
            requireUserPresence = true

        val requestInfo = if (numberOfCredentials > 0) {
            val firstCredential = credentialsToUse.first() as? WebAuthnCredential
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
            Ctap2RequestInfo(AUTHENTICATE_NO_CREDENTIALS, rpId)
        }
        if (requireUserPresence && !context.confirmRequestWithUser(requestInfo))
            CTAP_ERR(OperationDenied)
        if (!requireUserPresence)
            Log.i(TAG, "Processing silent GetAssertion request")

        // Step 8
        // It is very important that this step happens after the user presence check of step 7.
        if (numberOfCredentials == 0) {
            context.notifyUser(requestInfo)
            CTAP_ERR(NoCredentials)
        }

        // Step 7 (user verification)
        if (requireUserVerification && !context.verifyUser())
            CTAP_ERR(OperationDenied)

        // At this point, user presence and verification have been performed if requested.

        if (requireUserVerification) {
            for (credential in credentialsToUse) {
                if (credential is WebAuthnCredential) {
                    context.authenticateUserFor {
                        credential.unlockUserInfoIfNecessary()
                    }
                }
            }
        }

        // If the transport does not allow for interactive credential selection or if silent
        // authentication is requested, return a list of assertions for all applicable credentials.
        // Otherwise, let the user select one to return an assertion for.
        return if (!context.isHidTransport || !requireUserPresence) {
            // Step 10
            val assertionOperationsIterator = credentialsToUse
                .mapIndexed { credentialCounter, nextCredential ->
                    // Step 6
                    // Process extensions.
                    val extensionOutputs = processExtensions(
                        extensions = activeExtensions,
                        credential = nextCredential,
                        requireUserPresence = requireUserPresence,
                        requireUserVerification = requireUserVerification,
                        action = AUTHENTICATE
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
                    // Cache remaining assertions for subsequent GetNextAssertion requests
                    context.getNextAssertionBuffer = assertionOperationsIterator
                    context.getNextAssertionRequestInfo = requestInfo
                } else {
                    // We return the only assertion and thus indicate success to the user
                    context.notifyUser(requestInfo)
                }
            }
        } else {
            // Step 11
            val credential = context.chooseCredential(credentialsToUse)
                ?: CTAP_ERR(OperationDenied)
            // Step 6
            // Process extensions.
            val extensionOutputs = processExtensions(
                extensions = activeExtensions,
                credential = credential,
                requireUserPresence = requireUserPresence,
                requireUserVerification = requireUserVerification,
                action = AUTHENTICATE
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
            CTAP_ERR(NotAllowed)
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
                GET_INFO_RESPONSE_EXTENSIONS to
                        if (context.isHidTransport)
                            Extension.identifiersAsCbor
                        else
                            Extension.noDisplayIdentifiersAsCbor,
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

    private fun handleClientPIN(params: CborValue): CborValue {
        val pinProtocol = params.getRequired(CLIENT_PIN_PIN_PROTOCOL).unbox<Long>()
        if (pinProtocol != 1L)
            CTAP_ERR(InvalidParameter, "Unsupported pinProtocol: $pinProtocol")

        val subCommand = params.getRequired(CLIENT_PIN_SUB_COMMAND).unbox<Long>()
        if (subCommand != CLIENT_PIN_SUB_COMMAND_GET_KEY_AGREEMENT)
            CTAP_ERR(InvalidCommand, "Unsupported ClientPIN subcommand: $subCommand")

        return CborLongMap(
            mapOf(
                CLIENT_PIN_GET_KEY_AGREEMENT_RESPONSE_KEY_AGREEMENT to authenticatorKeyAgreementKey
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
            CTAP_ERR(OperationDenied)
        if (context.requestReset()) {
            return null
        } else {
            context.handleSpecialStatus(AuthenticatorSpecialStatus.RESET)
            CTAP_ERR(OperationDenied)
        }
    }

    private fun parseExtensionInputs(
        extensions: Map<String, CborValue>?,
        action: AuthenticatorAction,
        canUseDisplay: Boolean
    ): Map<Extension, ExtensionInput> {
        if (extensions == null)
            return mapOf()
        return extensions.filterKeys { identifier ->
            identifier in Extension.identifiers
        }.map {
            val extension = Extension.fromIdentifier(it.key)
            // parseInput throws an appropriate exception if the input is not of the correct form.
            Pair(extension, extension.parseInput(it.value, action, canUseDisplay))
        }.toMap()
    }

    private fun processExtensions(
        extensions: Map<Extension, ExtensionInput>,
        credential: Credential,
        requireUserPresence: Boolean,
        requireUserVerification: Boolean,
        action: AuthenticatorAction
    ): CborValue? {
        val extensionOutputs = extensions.mapValues {
            val extension = it.key
            processExtension(
                extension,
                it.value,
                credential,
                requireUserPresence,
                requireUserVerification,
                action
            )
        }
        return if (extensionOutputs.isEmpty())
            null
        else
            CborTextStringMap(extensionOutputs.mapKeys { it.key.identifier })
    }

    private fun processExtension(
        extension: Extension,
        input: ExtensionInput,
        credential: Credential,
        userPresent: Boolean,
        userVerified: Boolean,
        action: AuthenticatorAction
    ): CborValue {
        require(action == REGISTER || action == AUTHENTICATE)
        return when (extension) {
            Extension.HmacSecret -> {
                if (action == REGISTER) {
                    require(input is NoInput)
                    // hmac-secret has already been handled during credential creation
                    CborBoolean(true)
                } else {
                    require(input is HmacSecretAuthenticateInput)
                    require(credential is WebAuthnCredential)
                    val sharedSecret = agreeOnSharedSecret(input.keyAgreement)
                    val salt = decryptSalt(sharedSecret, input.saltEnc, input.saltAuth)
                        ?: CTAP_ERR(InvalidParameter, "Invalid saltAuth")
                    require(salt.size == 32 || salt.size == 64)
                    val output = if (salt.size == 32) {
                        val hmacOutput = credential.signWithHmacSecret(salt)
                            ?: CTAP_ERR(NoCredentials, "HMAC secret is missing")
                        encryptHmacOutput(sharedSecret, hmacOutput).also {
                            check(it.size == 32)
                        }
                    } else {
                        val salt1 = salt.sliceArray(0 until 32)
                        val hmacOutput1 = credential.signWithHmacSecret(salt1)
                            ?: CTAP_ERR(NoCredentials, "HMAC secret is missing")
                        val salt2 = salt.sliceArray(32 until 64)
                        val hmacOutput2 = credential.signWithHmacSecret(salt2)
                            ?: CTAP_ERR(NoCredentials, "HMAC secret is missing")
                        encryptHmacOutput(sharedSecret, hmacOutput1 + hmacOutput2).also {
                            check(it.size == 64)
                        }
                    }
                    CborByteString(output)
                }
            }
            Extension.SupportedExtensions -> {
                require(action == REGISTER)
                require(input is NoInput)
                Extension.identifiersAsCbor
            }
            Extension.TxAuthSimple -> {
                require(action == AUTHENTICATE)
                require(input is TxAuthSimpleAuthenticateInput)
                // At this point, either we have returned an OperationDenied error or the user has
                // confirmed the prompt (with added line breaks).
                CborTextString(input.prompt)
            }
            Extension.UserVerificationMethod -> {
                require(input is NoInput)
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
