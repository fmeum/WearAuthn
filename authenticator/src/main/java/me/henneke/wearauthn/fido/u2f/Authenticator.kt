package me.henneke.wearauthn.fido.u2f

import me.henneke.wearauthn.*
import me.henneke.wearauthn.fido.ApduException
import me.henneke.wearauthn.fido.StatusWord
import me.henneke.wearauthn.fido.context.*
import me.henneke.wearauthn.fido.u2f.Request.*

@ExperimentalUnsignedTypes
object Authenticator : Logging {
    override val TAG = "U2fAuthenticator"

    fun handle(context: AuthenticatorContext, req: Request): Pair<RequestInfo?, () -> Response> {
        v { "<- $req" }
        return when (req) {
            is RegistrationRequest -> {
                i { "Register request received" }
                handleRegisterRequest(context, req)
            }
            is AuthenticationRequest -> {
                i { "Authenticate request received" }
                handleAuthenticateRequest(context, req)
            }
            is VersionRequest -> {
                i { "Version request received" }
                handleVersionRequest()
            }
        }
    }

    private fun handleRegisterRequest(
        context: AuthenticatorContext,
        req: RegistrationRequest
    ): Pair<RequestInfo, () -> Response.RegistrationResponse> {
        val action = if (isDummyRequest(req.application, req.challenge)) {
            i { "Dummy request received" }
            AuthenticatorAction.AUTHENTICATE_NO_CREDENTIALS
        } else {
            AuthenticatorAction.REGISTER
        }
        val requestInfo =
            context.makeU2fRequestInfo(action, req.application)
        return Pair(requestInfo) {
            val (keyAlias, _) = context.getOrCreateFreshWebAuthnCredential()
                ?: throw ApduException(StatusWord.MEMORY_FAILURE)
            val credential =
                U2FCredential(
                    keyAlias,
                    req.application
                )
            val rawPublicKey = credential.u2fPublicKeyRepresentation
            if (rawPublicKey == null) {
                credential.delete(context)
                w { "Failed to get raw public key" }
                throw ApduException(StatusWord.MEMORY_FAILURE)
            }
            context.initCounter(keyAlias)
            // Alternatively, self attestation can be used as follows:
            // val attestationCert = createU2fSelfAttestationCert(credential)
            // val signature = credential.sign(
            val attestationCert = U2F_RAW_BATCH_ATTESTATION_CERT
            val signature = signWithU2fBatchAttestationKey(
                byteArrayOf(0x00),
                req.application,
                req.challenge,
                credential.keyHandle,
                rawPublicKey
            )
            // Delete key material created for dummy requests
            if (action != AuthenticatorAction.REGISTER)
                credential.delete(context)

            Response.RegistrationResponse(
                rawPublicKey,
                credential.keyHandle,
                attestationCert,
                signature
            ).also { v { "-> $it" } }
        }
    }

    private fun handleAuthenticateRequest(
        context: AuthenticatorContext,
        req: AuthenticationRequest
    ): Pair<RequestInfo?, () -> Response.AuthenticationResponse> {
        val credential = Credential.fromKeyHandle(req.keyHandle, req.application, context)
            ?: throw ApduException(StatusWord.WRONG_DATA)
        // CTAP2 credentials are allowed to be used via CTAP1, which greatly improves NFC usability
        if (credential !is U2FCredential)
            i { "Using a CTAP2 credential via CTAP1" }
        val action =
            if (isDummyRequest(req.application, req.challenge))
                AuthenticatorAction.REGISTER_CREDENTIAL_EXCLUDED
            else
                AuthenticatorAction.AUTHENTICATE
        return when (req.controlByte) {
            AuthenticateControlByte.CHECK_ONLY -> {
                throw ApduException(StatusWord.CONDITIONS_NOT_SATISFIED)
            }
            AuthenticateControlByte.ENFORCE_USER_PRESENCE_AND_SIGN -> {
                val requestInfo =
                    context.makeU2fRequestInfo(action, req.application)
                Pair(requestInfo) {
                    credential.assertU2f(
                        clientDataHash = req.challenge,
                        userPresent = true,
                        userVerified = false,
                        context = context
                    )
                }
            }
            AuthenticateControlByte.DONT_ENFORCE_USER_PRESENCE_AND_SIGN -> {
                i { "Processing silent Authenticate request" }
                Pair(null) {
                    credential.assertU2f(
                        clientDataHash = req.challenge,
                        userPresent = false,
                        userVerified = false,
                        context = context
                    )
                }
            }
        }
    }

    private fun handleVersionRequest(): Pair<Nothing?, () -> Response.VersionResponse> {
        return Pair(null) { Response.VersionResponse() }
    }
}
