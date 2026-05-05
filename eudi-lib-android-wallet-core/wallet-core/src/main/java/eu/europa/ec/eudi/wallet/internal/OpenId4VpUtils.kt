/*
 * Copyright (c) 2023-2025 European Commission
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.internal

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.iso18013.transfer.SessionTranscriptBytes
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.device.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.device.ProcessedDeviceRequest
import eu.europa.ec.eudi.openid4vp.CoseAlgorithm
import eu.europa.ec.eudi.openid4vp.JarConfiguration
import eu.europa.ec.eudi.openid4vp.JwkSetSource.ByReference
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.PreregisteredClient
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.VPConfiguration
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifierId
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.present
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serializeWithKeyBinding
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.credential.CredentialIssuedData
import eu.europa.ec.eudi.wallet.document.credential.CustomKeyInfo
import eu.europa.ec.eudi.wallet.document.credential.getIssuedData
import eu.europa.ec.eudi.wallet.issue.openid4vci.DilithiumJWK
import eu.europa.ec.eudi.wallet.issue.openid4vci.toJoseEncoded
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ClientIdScheme
import eu.europa.ec.eudi.wallet.transfer.openId4vp.EncryptionAlgorithm
import eu.europa.ec.eudi.wallet.transfer.openId4vp.EncryptionMethod
import eu.europa.ec.eudi.wallet.transfer.openId4vp.Format
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpConfig
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpReaderTrust
import eu.europa.ec.eudi.wallet.transfer.openId4vp.SdJwtVcItem
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.UnlockReason
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Date

private const val SHA_256_ALGORITHM = "SHA-256"

/**
 *  Utility to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = null,
 *  EReaderKeyBytes = null
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = bstr
 *  responseUriHash = bstr
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = tstr
 *  clientId = tstr
 *  responseUri = tstr
 *  nonce = tstr
 *
 */
internal fun generateSessionTranscript(
    clientId: String,
    nonce: String,
    jwkThumbprint: ByteArray?,
    responseOrRedirectUri: String
): SessionTranscriptBytes {

    val openID4VPHandover =
        generateOpenId4VpHandover(clientId, nonce, jwkThumbprint, responseOrRedirectUri)

    val sessionTranscriptBytes =
        CBORObject.NewArray().apply {
            Add(CBORObject.Null)
            Add(CBORObject.Null)
            Add(openID4VPHandover)
        }.EncodeToBytes()

    return sessionTranscriptBytes
}

internal fun generateJarmNonce(): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(16)
    secureRandom.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

internal fun makeOpenId4VPConfig(
    config: OpenId4VpConfig,
    trust: OpenId4VpReaderTrust,
): OpenId4VPConfig {
    val supportedClientIdPrefixes = config.clientIdSchemes.map { clientIdScheme ->
        when (clientIdScheme) {
            is ClientIdScheme.Preregistered -> SupportedClientIdPrefix.Preregistered(
                clientIdScheme.preregisteredVerifiers.associate { verifier ->
                    verifier.clientId to PreregisteredClient(
                        clientId = verifier.clientId,
                        legalName = verifier.legalName,
                        jarConfig = JWSAlgorithm.parse(verifier.jwsAlgorithm.joseAlgorithmIdentifier) to ByReference(
                            verifier.jwkSetSource
                        )

                    )
                }
            )

            ClientIdScheme.RedirectUri -> SupportedClientIdPrefix.RedirectUri
            ClientIdScheme.X509SanDns -> SupportedClientIdPrefix.X509SanDns(trust = trust)
            ClientIdScheme.X509Hash -> SupportedClientIdPrefix.X509Hash(trust = trust)
        }
    }
    return OpenId4VPConfig(
        issuer = OpenId4VPConfig.SelfIssued,
        jarConfiguration = JarConfiguration.Default,
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
            supportedAlgorithms = config.encryptionAlgorithms.map { it.nimbus },
            supportedMethods = config.encryptionMethods.map { it.nimbus }
        ),
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = config.formats.toVpFormats()
        ),
        supportedClientIdPrefixes = supportedClientIdPrefixes
    )
}

internal fun generateOpenId4VpHandover(
    clientId: String,
    nonce: String,
    jwkThumbprint: ByteArray?,
    responseOrRedirectUri: String,
): CBORObject {

    val openID4VPHandoverInfoBytes = CBORObject.NewArray().apply {
        Add(clientId)
        Add(nonce)
        Add(jwkThumbprint ?: CBORObject.Null)
        Add(responseOrRedirectUri)
    }.EncodeToBytes()

    val openID4VPHandoverInfoHash = MessageDigest.getInstance(SHA_256_ALGORITHM)
        .digest(openID4VPHandoverInfoBytes)

    val openID4VPHandover = CBORObject.NewArray().apply {
        Add("OpenID4VPHandover")
        Add(openID4VPHandoverInfoHash)
    }

    return openID4VPHandover
}

internal fun generateMdocGeneratedNonce(): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(16)
    secureRandom.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

internal fun ResolvedRequestObject.getSessionTranscriptBytes(): SessionTranscriptBytes {
    val clientId = client.id.clientId
    val nonce = nonce
    val jwkThumbprint = responseEncryptionSpecification?.recipientKey?.computeThumbprint()?.decode()
    val responseOrRedirectUri = when (val mode = this.responseMode) {
        is ResponseMode.DirectPostJwt -> mode.responseURI.toString()
        is ResponseMode.DirectPost -> mode.responseURI.toString()
        is ResponseMode.Fragment -> mode.redirectUri.toString()
        is ResponseMode.FragmentJwt -> mode.redirectUri.toString()
        is ResponseMode.Query -> mode.redirectUri.toString()
        is ResponseMode.QueryJwt -> mode.redirectUri.toString()
    }
    val sessionTranscriptBytes = generateSessionTranscript(
        clientId = clientId,
        nonce = nonce,
        jwkThumbprint = jwkThumbprint,
        responseOrRedirectUri = responseOrRedirectUri
    )
    return sessionTranscriptBytes
}

internal fun List<Format>.toVpFormats(): VpFormatsSupported {

    val msoMdocVpFormat = filterIsInstance<Format.MsoMdoc>()
        .firstOrNull()
        ?.let { spec ->
            VpFormatsSupported.MsoMdoc(
                issuerAuthAlgorithms = spec.issuerAuthAlgorithms.map { CoseAlgorithm(it.coseAlgorithmIdentifier!!) },
                deviceAuthAlgorithms = spec.deviceAuthAlgorithms.map { CoseAlgorithm(it.coseAlgorithmIdentifier!!) }
            )
        }


    val pqcVpFormat = filterIsInstance<Format.PqcJwtVc>()
        .firstOrNull()
        ?.let {
            VpFormatsSupported.SdJwtVc(
                sdJwtAlgorithms = it.sdJwtAlgorithms.map { JWSAlgorithm.ML_DSA_44 },
                kbJwtAlgorithms = it.kbJwtAlgorithms.map { JWSAlgorithm.ML_DSA_44 }
            )
        }

    return VpFormatsSupported(
        sdJwtVc = pqcVpFormat,
        msoMdoc = msoMdocVpFormat
    )
}

/**
 * Constructs a verifiable presentation for an SD-JWT VC credential.
 *
 * @param resolvedRequestObject The resolved OpenID4VP authorization request.
 * @param document The issued document containing the credential.
 * @param disclosedDocument The document with disclosed claims.
 * @param signatureAlgorithm The algorithm to use for signing.
 * @return The constructed [VerifiablePresentation.Generic].
 * @throws IllegalArgumentException if no claims are disclosed or presentation creation fails.
 */
internal suspend fun verifiablePresentationForSdJwtVc(
    resolvedRequestObject: ResolvedRequestObject,
    document: IssuedDocument,
    disclosedDocument: DisclosedDocument,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    return document.consumingCredential {
        val credentialIssuedData =
            getIssuedData<CredentialIssuedData.SdJwtVc>()
        val issuedSdJwt = credentialIssuedData.getOrThrow().issuedSdJwt

        val query = disclosedDocument.disclosedItems
            .filterIsInstance<SdJwtVcItem>()
            .map { item ->
                val elements = item.path.map { ClaimPathElement.Claim(it) }

                ClaimPath(elements.first(), *elements.drop(1).toTypedArray())
            }.toSet()

        // Check that at least one claim is disclosed, otherwise throw an error
        require(!(query.isEmpty())) { "No claims to disclose" }

        val presentation = issuedSdJwt.present(query)
            ?: throw IllegalArgumentException("Failed to create SD JWT VC presentation")

        val containsCnf = issuedSdJwt.jwt.second["cnf"] != null

        // If the SD-JWT contains a 'cnf' claim, serialize with key binding
        val serialized = if (containsCnf) {
            presentation.serializeWithKeyBinding(
                credential = this, //credential
                keyUnlockData = disclosedDocument.keyUnlockData,
                clientId = resolvedRequestObject.client.id,
                nonce = resolvedRequestObject.nonce,
                signatureAlgorithm = signatureAlgorithm,
                issueDate = Date()
            )
        } else {
            presentation.serialize()
        }

        VerifiablePresentation.Generic(serialized)
    }.getOrThrow()
}

internal suspend fun SdJwt<JwtAndClaims>.serializeWithKeyBinding(
    credential: SecureAreaBoundCredential,
    keyUnlockData: KeyUnlockData?,
    clientId: VerifierId,
    nonce: String,
    signatureAlgorithm: Algorithm,
    issueDate: Date,
): String {
    var algorithm = JWSAlgorithm.parse((signatureAlgorithm).joseAlgorithmIdentifier)
    val publicKey = credential.secureArea.getKeyInfo(credential.alias).publicKey
    val provider = keyUnlockData.asProvider()
    var pemPublicKey: JWK;
    if (publicKey is CustomKeyInfo) {
        algorithm = JWSAlgorithm.ML_DSA_44
        val publicKeyBytes = publicKey.dilithiumPublicKey
        val pem = dilithiumPublicKeyToPem(publicKeyBytes)
        print("test");
        pemPublicKey = DilithiumJWK(publicKeyBytes).toOfficialJWK()
    } else {
        pemPublicKey = JWK.parseFromPEMEncodedObjects(publicKey.toPem())
    }
    val buildKbJwt = NimbusSdJwtOps.kbJwtIssuer(
        signer = object : JWSSigner {
            override fun getJCAContext(): JCAContext = JCAContext()
            override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
            override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                val signature = runBlocking {
                    withContext(provider) {
                        credential.secureArea.sign(
                            alias = credential.alias,
                            dataToSign = signingInput,
                            unlockReason = UnlockReason.Unspecified
                        )
                    }
                }
                if (algorithm == JWSAlgorithm.Dilithium3 || algorithm == JWSAlgorithm.ML_DSA_44) {
                    return Base64URL.encode(signature.r)
                }
                return Base64URL.encode(signature.toJoseEncoded(algorithm))
            }
        },
        signAlgorithm = algorithm,
        publicKey = JWK.parseFromPEMEncodedObjects(publicKey.toPem()) as AsymmetricJWK
    ) {
        audience(clientId.clientId)
        claim("nonce", nonce)
        issueTime(issueDate)
    }
    return serializeWithKeyBinding(buildKbJwt).getOrThrow()
}

fun dilithiumPublicKeyToPem(publicKeyBytes: ByteArray): String {
    val base64 = Base64.getEncoder().encodeToString(publicKeyBytes)
    val formatted = base64.chunked(64).joinToString("\n")
    return """
        -----BEGIN PUBLIC KEY-----
        $formatted
        -----END PUBLIC KEY-----
    """.trimIndent()
}

/**
 * Constructs a verifiable presentation for an MSO mdoc credential.
 *
 * This function creates a verifiable presentation according to the ISO 18013-5 standard by:
 * 1. Filtering the requested documents to include only the specified document
 * 2. Generating a device response with the session transcript for cryptographic binding
 * 3. Converting the binary CBOR-encoded device response to a base64url-encoded string
 *
 * The session transcript is critical as it binds the presentation to the specific request session.
 *
 * @param documentManager The document manager for retrieving the full document content and credentials
 * @param disclosedDocument The document with specific claims that the user has consented to disclose
 * @param requestedDocuments The complete set of documents requested by the verifier
 * @param sessionTranscript The session transcript bytes that cryptographically bind the response to the request
 * @param signatureAlgorithm The algorithm to use for digitally signing the presentation
 * @return The constructed [VerifiablePresentation.Generic] containing the base64url-encoded device response
 * @throws RuntimeException if the response generation fails
 */
internal fun verifiablePresentationForMsoMdoc(
    documentManager: DocumentManager,
    disclosedDocument: DisclosedDocument,
    requestedDocuments: RequestedDocuments,
    sessionTranscript: ByteArray,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    // Create a new RequestedDocuments instance containing only the document that was selected for disclosure
    // This filters out any other documents that might have been in the original request
    val deviceResponse = ProcessedDeviceRequest(
        documentManager = documentManager,
        sessionTranscript = sessionTranscript,  // Bind the presentation to this specific session
        requestedDocuments = RequestedDocuments(requestedDocuments.filter { it.documentId == disclosedDocument.documentId })
    ).generateResponse(
        // Create a response containing only the selected document with its disclosed claims
        disclosedDocuments = DisclosedDocuments(disclosedDocument),
        signatureAlgorithm = signatureAlgorithm  // Use the specified algorithm to sign the response
    ).getOrThrow() as DeviceResponse  // Unwrap the Result and cast to DeviceResponse type

    // Convert the binary CBOR-encoded device response to a base64url-encoded string format
    // suitable for transmission in JWT or JSON payload without padding characters
    return VerifiablePresentation.Generic(
        value = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(deviceResponse.deviceResponseBytes)
    )
}

internal fun Algorithm.toJwsAlgorithm(default: JWSAlgorithm): JWSAlgorithm = try {
    JWSAlgorithm.parse(this.joseAlgorithmIdentifier)
} catch (_: Throwable) {
    default
}

internal val EncryptionAlgorithm.nimbus: JWEAlgorithm
    get() = when (this) {
        EncryptionAlgorithm.ECDH_ES -> JWEAlgorithm.ECDH_ES
        EncryptionAlgorithm.ECDH_ES_A128KW -> JWEAlgorithm.ECDH_ES_A128KW
        EncryptionAlgorithm.ECDH_ES_A192KW -> JWEAlgorithm.ECDH_ES_A192KW
        EncryptionAlgorithm.ECDH_ES_A256KW -> JWEAlgorithm.ECDH_ES_A256KW
        EncryptionAlgorithm.DILITHIUM -> JWEAlgorithm.DILITHIUM
        EncryptionAlgorithm.ML_DSA_44 -> JWEAlgorithm.ML_DSA_44
    }

internal val EncryptionMethod.nimbus: com.nimbusds.jose.EncryptionMethod
    get() = when (this) {
        EncryptionMethod.A128CBC_HS256 -> com.nimbusds.jose.EncryptionMethod.A128CBC_HS256
        EncryptionMethod.A192CBC_HS384 -> com.nimbusds.jose.EncryptionMethod.A192CBC_HS384
        EncryptionMethod.A256CBC_HS512 -> com.nimbusds.jose.EncryptionMethod.A256CBC_HS512
        EncryptionMethod.A128GCM -> com.nimbusds.jose.EncryptionMethod.A128GCM
        EncryptionMethod.A192GCM -> com.nimbusds.jose.EncryptionMethod.A192GCM
        EncryptionMethod.A256GCM -> com.nimbusds.jose.EncryptionMethod.A256GCM
        EncryptionMethod.A128CBC_HS256_DEPRECATED -> com.nimbusds.jose.EncryptionMethod.A128CBC_HS256_DEPRECATED
        EncryptionMethod.A256CBC_HS512_DEPRECATED -> com.nimbusds.jose.EncryptionMethod.A256CBC_HS512_DEPRECATED
        EncryptionMethod.XC20P -> com.nimbusds.jose.EncryptionMethod.XC20P
    }