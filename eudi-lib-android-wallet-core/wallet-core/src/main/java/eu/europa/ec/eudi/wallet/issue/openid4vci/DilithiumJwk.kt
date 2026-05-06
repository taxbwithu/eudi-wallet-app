/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.eudi.wallet.issue.openid4vci

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.Requirement
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.util.Base64URL
import java.net.URI
import java.security.KeyStore
import java.util.LinkedHashMap

class DilithiumJWK(
    val publicKey: ByteArray,
    val kid: String? = null,
    val ks: KeyStore? = null
) : JWK(
    KeyType("AKP", Requirement.REQUIRED),  // Custom key type
    null,                  // KeyUse
    null,                  // KeyOperations
    Algorithm("Dilithium3"),                  // Algorithm
    kid,                   // Key ID
    null,                  // x5u
    null,                  // x5t
    null,                  // x5t#S256
    null,                   // x5c
    ks,
) {
    override fun getRequiredParams(): LinkedHashMap<String, *> {
        val params = LinkedHashMap<String, Any>()
        params["kty"] = "AKP"
        params["alg"] = "Dilithium3"
        params["pub"] = Base64URL.encode(publicKey)
        if (kid != null) params["kid"] = kid
        return params
    }

    override fun isPrivate(): Boolean = false

    override fun toPublicJWK(): JWK = this

    fun toOfficialJWK(): JWK {
        return MLDSAKey.Builder(
            Algorithm("Dilithium3"), // Or your custom curve name
            Base64URL.encode(this.publicKey) // `x` = public key bytes
        ).build()
    }
    override fun toRevokedJWK(keyRevocation: KeyRevocation?): JWK {
        // Simply returning a new object with the same data
        return DilithiumJWK(publicKey, kid)
    }

    override fun size(): Int {
        // Approximate size of the key in bits (e.g., Dilithium3 ~ 256 bytes = 2048 bits)
        return publicKey.size * 8
    }

    override fun toJSONObject(): MutableMap<String, Any> {
        val obj = super.toJSONObject()
        // TODO MM
        obj["kty"] = "AKP"
        obj["alg"] = "Dilithium3"
        obj["pub"] = Base64URL.encode(publicKey).toString()
        if (kid != null) obj["kid"] = kid
        return obj
    }
}