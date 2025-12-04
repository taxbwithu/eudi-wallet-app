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


import java.io.IOException;
import java.security.*;
import java.util.Set;

import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.jwk.MLDSAKey;
import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;


/**
 * Module-Lattice-Based Digital Signature Algorithm (ML-DSA) verifier of
 * {@link com.nimbusds.jose.JWSObject JWS objects}. Expects a public ML-DSA key
 * (ML-DSA-44, ML-DSA-65 or ML-DSA-87).
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_44}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_65}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_87}
 * </ul>
 */
@ThreadSafe
public class MLDSAVerifier extends MLDSAProvider implements JWSVerifier, CriticalHeaderParamsAware {


    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * The public ML-DSA key.
     */
    private final PublicKey publicKey;


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * verifier.
     *
     * @param publicKey The public ML-DSA key. Must not be {@code null}.
     *
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public MLDSAVerifier(final PublicKey publicKey)
            throws JOSEException {

        this(publicKey, null);
    }


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * verifier.
     *
     * @param mldsaKey The public ML-DSA key. Must not be {@code null}.
     *
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public MLDSAVerifier(final MLDSAKey mldsaKey)
            throws JOSEException {

        this(mldsaKey.toPublicKey());
    }


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * verifier.
     *
     * @param publicKey      The public ML-DSA key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     *
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public MLDSAVerifier(final PublicKey publicKey, final Set<String> defCritHeaders)
            throws JOSEException {

        super(MLDSA.resolveAlgorithm(publicKey));

        this.publicKey = publicKey;

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }


    /**
     * Returns the public ML-DSA key.
     *
     * @return The public ML-DSA key.
     */
    public PublicKey getPublicKey() {

        return publicKey;
    }


    @Override
    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public boolean verify(final JWSHeader header,
                          final byte[] signedContent,
                          final Base64URL signature)
            throws JOSEException {

        final JWSAlgorithm alg = header.getAlgorithm();

        if (! supportedJWSAlgorithms().contains(alg)) {
            System.out.println("TUTAJ: " + alg.getName());
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }

        if (! critPolicy.headerPasses(header)) {
            return false;
        }

        final byte[] jwsSignature = signature.decode();

        // Prevent CVE-2022-21449 and similar attacks
        try {
            MLDSA.ensureLegalSignature(jwsSignature, alg);
        } catch (JOSEException e) {
            return false;
        }

        if (alg.equals(JWSAlgorithm.ML_DSA_44) || alg.equals(JWSAlgorithm.ML_DSA_65) || alg.equals(JWSAlgorithm.ML_DSA_87)) {
            MLDSASigner sig = MLDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
            AsymmetricKeyParameter bcKey;
            try {
                bcKey = PublicKeyFactory.createKey(publicKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            sig.init(false, bcKey);
            sig.update(signedContent, 0, signedContent.length);
            return sig.verifySignature(jwsSignature);
        } else {
            DilithiumSigner sig = new DilithiumSigner();
            AsymmetricKeyParameter bcKey;
            try {
                bcKey = PublicKeyFactory.createKey(publicKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            sig.init(false, bcKey);
            return sig.verifySignature(signedContent, jwsSignature);
        }

    }
}
