package com.nimbusds.jose.crypto.utils;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;

import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class MLDSAUtils {

    public static PublicKey base64toPublicKey(Base64URL base64, Algorithm alg) {
        byte[] pubBytes = base64.decode();

        PublicKey pubKey;
        if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
            MLDSAPublicKeyParameters bcPub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, pubBytes);
            pubKey = new BCMLDSAPublicKey(bcPub);
        } else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
            MLDSAPublicKeyParameters bcPub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pubBytes);
            pubKey = new BCMLDSAPublicKey(bcPub);
        } else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
            MLDSAPublicKeyParameters bcPub = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, pubBytes);
            pubKey = new BCMLDSAPublicKey(bcPub);
        } else if (alg.equals(JWSAlgorithm.Dilithium2)) {
            DilithiumPublicKeyParameters bcPub = new DilithiumPublicKeyParameters(DilithiumParameters.dilithium2, pubBytes);
            pubKey = new BCDilithiumPublicKey(bcPub);
        } else if (alg.equals(JWSAlgorithm.Dilithium3)) {
            DilithiumPublicKeyParameters bcPub = new DilithiumPublicKeyParameters(DilithiumParameters.dilithium3, pubBytes);
            pubKey = new BCDilithiumPublicKey(bcPub);
        } else if (alg.equals(JWSAlgorithm.Dilithium5)) {
            DilithiumPublicKeyParameters bcPub = new DilithiumPublicKeyParameters(DilithiumParameters.dilithium5, pubBytes);
            pubKey = new BCDilithiumPublicKey(bcPub);
        } else {
            throw new IllegalArgumentException("Unknown / unsupported alg: " + alg);
        }

        if (!pubKey.getAlgorithm().equalsIgnoreCase(alg.getName())) {
            throw new IllegalArgumentException("Not an ML-DSA public key");
        }

        return pubKey;
    }


    public static Base64URL publicKeyToBase64(PublicKey pub) {
        byte[] encoded = pub.getEncoded();
        ASN1Sequence seq;
        try {
            seq = (ASN1Sequence) ASN1Primitive.fromByteArray(encoded);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        DERBitString db = (DERBitString) seq.getObjectAt(1);
        byte[] b = db.getBytes();
        return Base64URL.encode(b);
    }


    public static PrivateKey seedToPrivateKey(Base64URL seed, Algorithm alg) throws JOSEException {


        if (alg.equals(JWSAlgorithm.ML_DSA_44) || alg.equals(JWSAlgorithm.ML_DSA_65) || alg.equals(JWSAlgorithm.ML_DSA_87)) {
            MLDSAParameters params;

            if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
                params = MLDSAParameters.ml_dsa_44;
            } else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
                params = MLDSAParameters.ml_dsa_65;
            } else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
                params = MLDSAParameters.ml_dsa_87;
            } else {
                throw new JOSEException("Unsupported algorithm: " + alg);
            }
            byte[] s = seed.decode();
            FixedSecureRandom random = new FixedSecureRandom(s);

            MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(random, params);
            ;

            MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
            kpGen.init(genParams);

//        KeyPair kp = generator.generateKeyPair();
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
            MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

            BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
            BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

            KeyPair skp = new KeyPair(pubKey, privKey);

            return skp.getPrivate();
        } else if (alg.equals(JWSAlgorithm.Dilithium2) || alg.equals(JWSAlgorithm.Dilithium3) || alg.equals(JWSAlgorithm.Dilithium5)) {
            DilithiumParameters params;

            if (alg.equals(JWSAlgorithm.Dilithium2)) {
                params = DilithiumParameters.dilithium2;
            }
            else if (alg.equals(JWSAlgorithm.Dilithium3)) {
                params = DilithiumParameters.dilithium3;
            }
            else if (alg.equals(JWSAlgorithm.Dilithium5)) {
                params = DilithiumParameters.dilithium5;
            }
            else {
                throw new JOSEException("Unsupported algorithm: " + alg);
            }
            byte[] s = seed.decode();
            FixedSecureRandom random = new FixedSecureRandom(s);

            DilithiumKeyGenerationParameters genParams = new DilithiumKeyGenerationParameters(random, params);;

            DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
            kpGen.init(genParams);

//        KeyPair kp = generator.generateKeyPair();
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
            DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();

            BCDilithiumPublicKey pubKey = new BCDilithiumPublicKey(pub);
            BCDilithiumPrivateKey privKey = new BCDilithiumPrivateKey(priv);

            KeyPair skp = new KeyPair(pubKey, privKey);

            return skp.getPrivate();
        } else {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }
    }


    public static Base64URL privateKeyToBase64URL(PrivateKey privKey) {
        byte[] encoded = privKey.getEncoded();
        ASN1Sequence pkcs8 = null;
        try {
            pkcs8 = (ASN1Sequence) ASN1Primitive.fromByteArray(encoded);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        DEROctetString d = (DEROctetString) pkcs8.getObjectAt(2);
        byte[] a = d.getOctets();
        byte[] withoutHeader = Arrays.copyOfRange(a, 4, a.length);
        return Base64URL.encode(withoutHeader);
    }


    public static PrivateKey base64toPrivateKey(Base64URL base64, Algorithm alg) throws JOSEException {
        byte[] privBytes = base64.decode();

        PrivateKey privKey;
        if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
            MLDSAPrivateKeyParameters bcPriv = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, privBytes, null);
            privKey = new BCMLDSAPrivateKey(bcPriv);
        } else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
            MLDSAPrivateKeyParameters bcPriv = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, privBytes, null);
            privKey = new BCMLDSAPrivateKey(bcPriv);
        } else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
            MLDSAPrivateKeyParameters bcPriv = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, privBytes, null);
            privKey = new BCMLDSAPrivateKey(bcPriv);
        } else if (alg.equals(JWSAlgorithm.Dilithium2)) {
            DilithiumPrivateKeyParameters bcPriv = new DilithiumPrivateKeyParameters(DilithiumParameters.dilithium2, privBytes, null);
            privKey = new BCDilithiumPrivateKey(bcPriv);
        } else if (alg.equals(JWSAlgorithm.Dilithium3)) {
            DilithiumPrivateKeyParameters bcPriv = new DilithiumPrivateKeyParameters(DilithiumParameters.dilithium3, privBytes, null);
            privKey = new BCDilithiumPrivateKey(bcPriv);
        } else if (alg.equals(JWSAlgorithm.Dilithium5)) {
            DilithiumPrivateKeyParameters bcPriv = new DilithiumPrivateKeyParameters(DilithiumParameters.dilithium5, privBytes, null);
            privKey = new BCDilithiumPrivateKey(bcPriv);
        } else {
            throw new IllegalArgumentException("Unknown / unsupported alg: " + alg);
        }

        if (!privKey.getAlgorithm().equalsIgnoreCase(alg.getName())) {
            throw new IllegalArgumentException("Not an ML-DSA public key");
        }

        return privKey;
    }
}
