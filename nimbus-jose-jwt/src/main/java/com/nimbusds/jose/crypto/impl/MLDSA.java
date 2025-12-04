/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.impl;


import java.security.*;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.ByteUtils;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;


/**
 * Module-Lattice-Based Digital Signature Algorithm (ML-DSA) functions and utilities.
 */
public class MLDSA {


    /**
     * Resolves the matching ML-DSA algorithm for the specified ML-DSA key
     * (public or private).
     *
     * @param key The ML-DSA key. Must not be {@code null}.
     *
     * @return The matching ML-DSA algorithm.
     *
     * @throws JOSEException If the algorithm of key is not supported.
     */
    public static JWSAlgorithm resolveAlgorithm(final Key key)
            throws JOSEException {

        String algorithm = key.getAlgorithm();

        if ("ML-DSA-44".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.ML_DSA_44;
        } else if ("ML-DSA-65".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.ML_DSA_65;
        } else if ("ML-DSA-87".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.ML_DSA_87;
        } else if ("Dilithium2".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.Dilithium2;
        } else if ("Dilithium3".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.Dilithium3;
        } else if ("Dilithium5".equalsIgnoreCase(algorithm)) {
            return JWSAlgorithm.Dilithium5;
        } else {
            throw new JOSEException("Unsupported algorithm: " + algorithm);
        }

//        if ("ML-DSA".equalsIgnoreCase(algorithm)) {
//            ASN1Sequence algId;
//            try {
//                if (key instanceof PrivateKey) {
//                    byte[] encoded = key.getEncoded();
//                    ASN1Sequence pkcs8 = (ASN1Sequence) ASN1Primitive.fromByteArray(encoded);
//                    algId = (ASN1Sequence) pkcs8.getObjectAt(1);
//                } else if (key instanceof PublicKey) {
//                    byte[] encoded = key.getEncoded();
//                    ASN1Sequence pkcs8 = null;
//                    pkcs8 = (ASN1Sequence) ASN1Primitive.fromByteArray(encoded);
//                    algId = (ASN1Sequence) pkcs8.getObjectAt(0);
//                } else {
//                    throw new JOSEException("Unsupported key type: " + algorithm);
//                }
//            } catch (IOException e) {
//                throw new JOSEException("Error parsing ML-DSA public key", e);
//            }
//            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algId.getObjectAt(0);
//            if (oid.equals(ASN1ObjectIdentifier.tryFromID("2.16.840.1.101.3.4.3.17"))) {
//                return JWSAlgorithm.ML_DSA_44;
//            } else if (oid.equals(ASN1ObjectIdentifier.tryFromID("2.16.840.1.101.3.4.3.18"))) {
//                return JWSAlgorithm.ML_DSA_65;
//            } else if (oid.equals(ASN1ObjectIdentifier.tryFromID("2.16.840.1.101.3.4.3.19"))) {
//                return JWSAlgorithm.ML_DSA_87;
//            } else {
//                throw new JOSEException("Unknown algorithm " + algorithm);
//            }
//        } else {
//            throw new JOSEException("Unsupported algorithm: " + algorithm);
//        }
    }


    public static JWSAlgorithm resolveAlgorithm(final Algorithm alg)
            throws JOSEException {
        if (alg == null) {
            throw new JOSEException("Unsupported algorithm, must be ML-DSA-44, ML-DSA-65 or ML-DSA-87");
        }
        else if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
            return JWSAlgorithm.ML_DSA_44;
        } else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
            return JWSAlgorithm.ML_DSA_65;
        } else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
            return JWSAlgorithm.ML_DSA_87;
        } else if (alg.equals(JWSAlgorithm.Dilithium2)) {
            return JWSAlgorithm.Dilithium2;
        } else if (alg.equals(JWSAlgorithm.Dilithium3)) {
            return JWSAlgorithm.Dilithium3;
        } else if (alg.equals(JWSAlgorithm.Dilithium5)) {
            return JWSAlgorithm.Dilithium5;
        } else {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }

    }


    /**
     * Creates a new JCA signer / verifier for ML-DSA.
     *
     * @param alg         The ML-DSA JWS algorithm. Must not be
     *                    {@code null}.
     * @param jcaProvider The JCA provider, {@code null} if not specified.
     *
     * @return The JCA signer / verifier instance.
     *
     * @throws JOSEException If a JCA signer / verifier couldn't be
     *                       created.
     */
    public static MLDSASigner getSignerAndVerifier(final JWSAlgorithm alg,
                                                   final Provider jcaProvider)
            throws JOSEException {
        return new MLDSASigner();
    }


    /**
     * Returns the expected signature byte array length for
     * the specified ML-DSA algorithm.
     *
     * @param alg The ML-DSA algorithm. Must be supported and not
     *            {@code null}.
     *
     * @return The expected byte array length for the signature.
     *
     * @throws JOSEException If the algorithm is not supported.
     */
    public static int getSignatureByteArrayLength(final JWSAlgorithm alg)
            throws JOSEException {

        if (alg.equals(JWSAlgorithm.ML_DSA_44)) {

            return 2420;

        } else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {

            return 3309;

        } else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {

            return 4627;

        } else if (alg.equals(JWSAlgorithm.Dilithium2)) {

            return 2420;

        } else if (alg.equals(JWSAlgorithm.Dilithium3)) {

            return 3309;

        } else if (alg.equals(JWSAlgorithm.Dilithium5)) {

            return 4627;
        } else {

            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
                    alg,
                    MLDSAProvider.SUPPORTED_ALGORITHMS));
        }
    }


    /**
     * Ensures the specified ECDSA signature is legal. Intended to prevent
     * attacks on JCA implementations vulnerable to CVE-2022-21449 and
     * similar bugs.
     *
     * @param jwsSignature The JWS signature. Must not be {@code null}.
     * @param jwsAlg       The ECDSA JWS algorithm. Must not be
     *                     {@code null}.
     *
     * @throws JOSEException If the signature is found to be illegal, or
     *                       the JWS algorithm or curve are not supported.
     */
    public static void ensureLegalSignature(final byte[] jwsSignature,
                                            final JWSAlgorithm jwsAlg)
            throws JOSEException {

        if (ByteUtils.isZeroFilled(jwsSignature)) {
            throw new JOSEException("Blank signature");
        }

        if (!(jwsAlg.equals(JWSAlgorithm.ML_DSA_44) || jwsAlg.equals(JWSAlgorithm.ML_DSA_65) ||
                jwsAlg.equals(JWSAlgorithm.ML_DSA_87) || jwsAlg.equals(JWSAlgorithm.Dilithium2) ||
                jwsAlg.equals(JWSAlgorithm.Dilithium3) || jwsAlg.equals(JWSAlgorithm.Dilithium5))) {
            throw new JOSEException("Unsupported JWS algorithm: " + jwsAlg);
        }

        if (MLDSA.getSignatureByteArrayLength(jwsAlg) != jwsSignature.length) {
            throw new JOSEException("Illegal signature length");
        }

    }


    /**
     * Prevents public instantiation.
     */
    private MLDSA() {}
}
