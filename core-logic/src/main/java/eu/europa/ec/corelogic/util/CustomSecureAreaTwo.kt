package eu.europa.ec.corelogic.util

import android.util.Log
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.PassphraseConstraints
import com.android.identity.securearea.fromDataItem
import com.android.identity.securearea.keyPurposeSet
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPrivateKey
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumPublicKey
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import java.security.KeyPairGenerator
import java.security.PrivateKey
import kotlin.random.Random
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.wallet.document.credential.CustomKeyInfo
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cose.CoseKey
import java.security.PublicKey
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcSignature
import org.multipaz.crypto.X509KeyUsage
import org.multipaz.crypto.X509KeyUsage.Companion.encodeSet
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyAttestation
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.storage.StorageEngine
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class CustomSecureAreaTwo(private val storageEngine: StorageEngine) : SecureArea {
    override val identifier get() = "AndroidKeystoreSecureArea"
    override val supportedAlgorithms: List<Algorithm>
        get() = listOf(Algorithm.UNSET)

    override suspend fun createKey(
        alias: String?,
        createKeySettings: CreateKeySettings
    ): KeyInfo {
        val actualAlias = alias ?: "DefaultKey"

        val settings = if (createKeySettings is SoftwareCreateKeySettings) {
            createKeySettings
        } else {
            SoftwareCreateKeySettings.Builder().build()
        }

        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA-44", "BC")
            keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_44)
            val keyPair = keyPairGenerator.generateKeyPair()
            val publicKey = keyPair.public
            val privateKey = keyPair.private

            val result = testSignature(publicKey.encoded, privateKey.encoded)

            val mapBuilder = CborMap.builder().apply {
                put("algorithm", "ML-DSA-44")
                put("keyPurposes", encodeSet(setOf(X509KeyUsage.KEY_ENCIPHERMENT)).value)
                put("passphraseRequired", settings.passphraseRequired)
            }

            if (!settings.passphraseRequired) {
                mapBuilder.put(
                    "privateKey",
                    privateKey.toCoseKey()
                ) // You'll need to define this extension for Dilithium
            } else {
                val encodedPublicKey = Cbor.encode(publicKey.toCoseKey())
                val secretKey =
                    derivePrivateKeyEncryptionKey(encodedPublicKey, settings.passphrase!!)
                val cleartextPrivateKey = Cbor.encode(privateKey.toCoseKey())
                val iv = Random.Default.nextBytes(12)
                val encryptedPrivateKey = Crypto.encrypt(
                    Algorithm.A128GCM,
                    secretKey,
                    iv,
                    cleartextPrivateKey
                )
                mapBuilder.put("encodedPublicKey", encodedPublicKey)
                mapBuilder.put("encryptedPrivateKey", encryptedPrivateKey)
                mapBuilder.put("encryptedPrivateKeyIv", iv)
            }

            mapBuilder.put("publicKey", publicKey.toCoseKey())
            mapBuilder.put("dilithiumPublicKey", Bstr(publicKey.encoded))
            mapBuilder.put("dilithiumPrivateKey", Bstr(privateKey.encoded))


            storageEngine.put(PREFIX + actualAlias, Cbor.encode(mapBuilder.end().build()))
            val ecKey = publicKey.toEcPublicKey();
            return CustomKeyInfo(
                publicKey = ecKey,
                attestation = KeyAttestation(ecKey, null),
                alias = actualAlias,
                algorithm = Algorithm.UNSET,
                dilithiumPublicKey = publicKey.encoded
            )

        } catch (e: Exception) {
            throw IllegalStateException("Failed to create Dilithium key", e)
        }
    }

    override suspend fun deleteKey(alias: String) {
        return;
    }

    override suspend fun getKeyInfo(alias: String): KeyInfo {
        val data = storageEngine[PREFIX + alias]
            ?: throw IllegalArgumentException("No key with given alias")
        val map = Cbor.decode(data)
        val publicKey = map["publicKey"].asCoseKey
        val dilithiumPublicKey = (map["dilithiumPublicKey"] as Bstr).value
        val ecKey = publicKey.toEcPublicKeyCose();
        return CustomKeyInfo(
            publicKey = ecKey,
            attestation = KeyAttestation(ecKey, null),
            alias = alias,
            algorithm = Algorithm.ES256,// should be unset
            dilithiumPublicKey = dilithiumPublicKey
        )
    }

    override suspend fun getKeyInvalidated(alias: String): Boolean {
        // Software keys are never invalidated.
        return false
    }

    override suspend fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        keyUnlockData: KeyUnlockData?
    ): ByteArray {
        TODO("Not yet implemented")
    }

    override suspend fun sign(
        alias: String,
        dataToSign: ByteArray,
        keyUnlockData: KeyUnlockData?
    ): EcSignature {
        val keyData = storageEngine["$PREFIX$alias"]
            ?: throw IllegalArgumentException("No key found for alias: $alias")
        val keyFactory = KeyFactory.getInstance("ML-DSA-44", "BC")

        val map = Cbor.decode(keyData)
        val privateKeyBytes = (map["dilithiumPrivateKey"] as Bstr).value
        //val publicKey = (map["publicKey"][-2] as Bstr).value + (map["publicKey"][-3] as Bstr).value
        val publicKey = (map["dilithiumPublicKey"] as Bstr).value
        val privKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = keyFactory.generatePrivate(privKeySpec)
        // Use your signing library here
        val signer = Signature.getInstance("ML-DSA-44", "BC")
        signer.initSign(privateKey)
        signer.update(dataToSign)
        val signature = signer.sign()

        val isTrueSignature = verifySignature(publicKey, dataToSign, signature)

        return EcSignature(
            signature,
            ByteArray(0)
        )
    }

    fun testSignature(pubKey: ByteArray, privateKeyBytes: ByteArray): Boolean {
        val keyFactory = KeyFactory.getInstance("ML-DSA-44", "BC")
        // Public Key
        val pubKeySpec = X509EncodedKeySpec(pubKey)
        val publicKey = keyFactory.generatePublic(pubKeySpec)

// Private Key
        val privKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = keyFactory.generatePrivate(privKeySpec)
        val data = "test message that will be encoded".toByteArray()
        // Sign
        val signer = Signature.getInstance("ML-DSA-44", "BC")
        signer.initSign(privateKey)
        signer.update(data)
        val signature = signer.sign()

        // Verify
        val verifier = Signature.getInstance("ML-DSA-44", "BC")
        verifier.initVerify(publicKey)
        verifier.update(data)
        val ok = verifier.verify(signature)   // should be true
        println("Verification: $ok")
        return ok
    }

    fun verifySignature(pubKey: ByteArray, msg: ByteArray, signature: ByteArray): Boolean {
        val keyFactory = KeyFactory.getInstance("ML-DSA-44", "BC")
        // Public Key
        val pubKeySpec = X509EncodedKeySpec(pubKey)
        val publicKey = keyFactory.generatePublic(pubKeySpec)
        val verifier = Signature.getInstance("ML-DSA-44", "BC")
        verifier.initVerify(publicKey)
        verifier.update(msg)
        return verifier.verify(signature)   // should be true
    }

    override val displayName get() = "Software Secure Area"

    // Custom toCoseKey for a public key
    fun PublicKey.toCoseKey(): DataItem {
        val (x, y) = this.encoded.fakeAsEcKey()
        return CborMap.builder()
            .put(1, 2)
            .put(3, -999)
            .put(-1, 1) // crv = custom curve
            .put(-2, x) // public key bytes
            .put(-3, y)
            .end()
            .build()
    }

    // Custom toCoseKey for a private key
    fun PrivateKey.toCoseKey(): DataItem {
        return CborMap.builder()
            .put(1, 1)  // kty = 100 (custom value for Dilithium)
            .put(3, -999) // alg = custom alg ID
            .put(-1, 6) // crv = custom curve
            .put(-4, this.encoded) // private key bytes
            .end()
            .build()
    }

    fun ByteArray.fakeAsEcKey(): Pair<ByteArray, ByteArray> {
        val x = this.copyOfRange(0, minOf(32, this.size))
        val y = ByteArray(32) { 1 } // Dummy Y value
        return Pair(x, y)
    }


    private fun derivePrivateKeyEncryptionKey(
        encodedPublicKey: ByteArray,
        passphrase: String
    ): ByteArray {
        val info = "ICPrivateKeyEncryption1".encodeToByteArray()
        return Crypto.hkdf(
            Algorithm.HMAC_SHA256,
            passphrase.encodeToByteArray(),
            encodedPublicKey,
            info,
            32
        )
    }


    fun PublicKey.toEcPublicKey(): EcPublicKey {
        val key = this.toCoseKey()
        return EcPublicKey.fromDataItem(key)
    }

    fun CoseKey.toEcPublicKeyCose(): EcPublicKey {
        val key = this.toDataItem()
        return EcPublicKey.fromDataItem(key)
    }

    companion object {
        private const val TAG = "SoftwareSecureArea"

        // Prefix for storage items.
        private const val PREFIX = "IC_SoftwareSecureArea_key_"
    }
}


//class MockECPublicKeyy(
//    private val encodedBytes: ByteArray = ByteArray(0)
//) : ECPublicKey {
//
//    override fun getAlgorithm(): String = "EC" // Still say it's EC
//    override fun getFormat(): String = "X.509" // Standard format
//
//    // Dummy encoded bytes (e.g. your Dilithium key if necessary)
//    override fun getEncoded(): ByteArray = encodedBytes
//
//    // Dummy curve point
//    override fun getW(): ECPoint = ECPoint(BigInteger.ZERO, BigInteger.ZERO)
//
//    // Dummy EC parameters (use known curve)
//    override fun getParams(): ECParameterSpec {
//        // Use a real EC curve, like secp256r1, to avoid nulls
//        val kf = java.security.KeyFactory.getInstance("EC")
//        val kpg = java.security.KeyPairGenerator.getInstance("EC")
//        kpg.initialize(256)
//        val kp = kpg.generateKeyPair()
//        val realEcPublicKey = kp.public as ECPublicKey
//        return realEcPublicKey.params
//    }
//}