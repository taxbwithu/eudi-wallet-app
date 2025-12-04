/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import java.security.*;
//import java.security.spec.NamedParameterSpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.nimbusds.jose.crypto.impl.MLDSA;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECParameterTable;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.StandardCharset;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;


/**
 * Tests the static ECDSA utilities.
 *
 * @version 2024-05-08
 */
public class MLDSATest extends TestCase {


    public void testResolveAlgFromAlg()
            throws JOSEException {

        assertEquals(JWSAlgorithm.ML_DSA_44, MLDSA.resolveAlgorithm(JWSAlgorithm.ML_DSA_44));
        assertEquals(JWSAlgorithm.ML_DSA_65, MLDSA.resolveAlgorithm(JWSAlgorithm.ML_DSA_65));
        assertEquals(JWSAlgorithm.ML_DSA_87, MLDSA.resolveAlgorithm(JWSAlgorithm.ML_DSA_87));

        try {
            MLDSA.resolveAlgorithm((JWSAlgorithm)null);

        } catch (JOSEException e) {
            assertEquals("Unsupported algorithm, must be ML-DSA-44, ML-DSA-65 or ML-DSA-87", e.getMessage());
        }
    }


    public void testResolveAlgFromKey_ML_DSA_44()
            throws Exception {

        MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(),
                MLDSAParameters.ml_dsa_44);
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
        BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ml-dsa", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_44);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_44);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.ML_DSA_44, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.ML_DSA_44, MLDSA.resolveAlgorithm(privateKey));
    }


    public void testResolveAlgFromKey_ML_DSA_65()
            throws Exception {
        MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(),
                MLDSAParameters.ml_dsa_65);
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
        BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("MLDSA", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_65);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_65);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.ML_DSA_65, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.ML_DSA_65, MLDSA.resolveAlgorithm(privateKey));
    }


    public void testResolveAlgFromKey_ML_DSA_87()
            throws Exception {

        MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(),
                MLDSAParameters.ml_dsa_87);
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
        BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("MLDSA", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_87);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_87);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.ML_DSA_87, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.ML_DSA_87, MLDSA.resolveAlgorithm(privateKey));
    }


    public void testResolveAlgFromKey_Dilithium2()
            throws Exception {

        DilithiumKeyGenerationParameters genParams = new DilithiumKeyGenerationParameters(new SecureRandom(),
                DilithiumParameters.dilithium2);
        DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();

        BCDilithiumPublicKey pubKey = new BCDilithiumPublicKey(pub);
        BCDilithiumPrivateKey privKey = new BCDilithiumPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ml-dsa", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_44);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_44);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.Dilithium2, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.Dilithium2, MLDSA.resolveAlgorithm(privateKey));
    }

    public void testResolveAlgFromKey_Dilithium3()
            throws Exception {

        DilithiumKeyGenerationParameters genParams = new DilithiumKeyGenerationParameters(new SecureRandom(),
                DilithiumParameters.dilithium3);
        DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();

        BCDilithiumPublicKey pubKey = new BCDilithiumPublicKey(pub);
        BCDilithiumPrivateKey privKey = new BCDilithiumPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ml-dsa", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_44);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_44);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.Dilithium3, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.Dilithium3, MLDSA.resolveAlgorithm(privateKey));
    }

    public void testResolveAlgFromKey_Dilithium5()
            throws Exception {

        DilithiumKeyGenerationParameters genParams = new DilithiumKeyGenerationParameters(new SecureRandom(),
                DilithiumParameters.dilithium5);
        DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();

        BCDilithiumPublicKey pubKey = new BCDilithiumPublicKey(pub);
        BCDilithiumPrivateKey privKey = new BCDilithiumPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);

//        Security.addProvider(new BouncyCastlePQCProvider());
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ml-dsa", "BCPQC");
//        generator.initialize(MLDSAParameterSpec.ml_dsa_44);

//        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA");
//        generator.initialize(NamedParameterSpec.ML_DSA_44);
//        KeyPair kp = generator.generateKeyPair();

        PublicKey publicKey = standardKeyPair.getPublic();
        PrivateKey privateKey = standardKeyPair.getPrivate();

        assertEquals(JWSAlgorithm.Dilithium5, MLDSA.resolveAlgorithm(publicKey));
        assertEquals(JWSAlgorithm.Dilithium5, MLDSA.resolveAlgorithm(privateKey));
    }


    public void test_default_JCE_for_CVE_2022_21449__zeroSignature() throws Exception {
        MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(),
                MLDSAParameters.ml_dsa_44);
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(genParams);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
        BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);
//        KeyPair keyPair = KeyPairGenerator.getInstance("ML-DSA-44").generateKeyPair();

        byte[] blankSignature = new byte[2420];


        org.bouncycastle.pqc.crypto.mldsa.MLDSASigner signer = new org.bouncycastle.pqc.crypto.mldsa.MLDSASigner();
        signer.init(false, kp.getPublic());
        byte[] message = "Hello, World".getBytes();
        signer.update(message, 0, message.length);
        boolean verify = signer.verifySignature(blankSignature);

//        Signature signature = Signature.getInstance("ML-DSA-44");
//
//        signature.initVerify(standardKeyPair.getPublic());
//        signature.update("Hello, World".getBytes());
//        boolean verify = signature.verify(blankSignature);
        assertFalse("Your Java runtime is vulnerable to CVE-2022-21449 - Upgrade to a patched Java version!!!", verify);
    }


    public void test_CVE_2022_21449__zeroSignature() throws ParseException, JOSEException {

        for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87)) {

            JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlg), new Payload("Hello, world"));

            String jwsString = new String(jwsObject.getSigningInput(), StandardCharset.UTF_8) +
                    "." +
                    Base64URL.encode(new byte[MLDSA.getSignatureByteArrayLength(jwsAlg)]);

            assertFalse(JWSObject.parse(jwsString).verify(new MLDSAVerifier(new MLDSAKeyGenerator(jwsAlg).generate().toPublicJWK())));
        }
    }


    public void testIsLegalSignature_zeroFilled() throws JOSEException {

        int nMaxArraySize = MLDSA.getSignatureByteArrayLength(JWSAlgorithm.ML_DSA_44);

        for (int sigSize=1; sigSize <= nMaxArraySize; sigSize++) {

            byte[] sigArray = new byte[sigSize];

            for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87)) {

                try {
                    MLDSA.ensureLegalSignature(sigArray, jwsAlg);
                    fail();
                } catch (JOSEException e) {
                    assertEquals("Blank signature", e.getMessage());
                }
            }
        }
    }


    public void testIsLegalSignature_unsupportedJWSAlg() {

        List<JWSAlgorithm> jwsAlgorithmList = new LinkedList<>();
        jwsAlgorithmList.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgorithmList.add(JWSAlgorithm.EdDSA);

        for (JWSAlgorithm jwsAlg: jwsAlgorithmList) {

            byte[] sigArray = new byte[32]; // some 1s filled array
            Arrays.fill(sigArray, (byte)1);

            try {
                MLDSA.ensureLegalSignature(sigArray, jwsAlg);
                fail();
            } catch (JOSEException e) {
                assertEquals("Unsupported JWS algorithm: " + jwsAlg, e.getMessage());
            }
        }
    }


    public void testIsLegalSignature_illegalSignatureLength() throws JOSEException {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65).generate();
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ML_DSA_65), new Payload("Hello, world!"));
        jwsObject.sign(new MLDSASigner(mldsaJWK));

        try {
            MLDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ML_DSA_44);
            fail();
        } catch (JOSEException e) {
            assertEquals("Illegal signature length", e.getMessage());
        }

        try {
            MLDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ML_DSA_87);
            fail();
        } catch (JOSEException e) {
            assertEquals("Illegal signature length", e.getMessage());
        }
    }

}
