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
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.jwk.MLDSAKey;
import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.opts.OptionUtils;
import com.nimbusds.jose.crypto.opts.UserAuthenticationRequired;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.JWSAlgorithm;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;


/**
 * Module-Lattice-Based Digital Signature Algorithm (ML-DSA) signer of
 * {@link com.nimbusds.jose.JWSObject JWS objects}. Expects a private ML-DSA key
 * (ML-DSA-44, ML-DSA-65 or ML-DSA-87).
 *
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
 *
 * <p>Supports the following {@link JWSSignerOption options}:
 *
 * <ul>
 *     <li>{@link UserAuthenticationRequired} -- to prompt the user to
 *         authenticate in order to complete the signing operation. Android
 *         applications can use this option to trigger a biometric prompt that
 *         is required to unlock a private key created with
 *         {@code setUserAuthenticationRequired(true)}.
 * </ul>
 */
@ThreadSafe
public class MLDSASigner extends MLDSAProvider implements JWSSigner {


    /**
     * The private ML-DSA key. Represented by generic private key interface to
     * support key stores that prevent exposure of the private key
     * parameters via the {@link java.security.PrivateKey}
     * API.
     */
    private final PrivateKey privateKey;


    /**
     * The configured options, empty set if none.
     */
    private final Set<JWSSignerOption> opts;


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * signer.
     *
     * @param privateKey The private ML-DSA key. Must not be {@code null}.
     *
     * @throws JOSEException If the elliptic curve of key is not supported.
     */
    public MLDSASigner(final PrivateKey privateKey)
            throws JOSEException, IOException {

        this(privateKey, (Set<JWSSignerOption>) null);
    }


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * signer.
     *
     * @param privateKey The private ML-DSA key. Must not be {@code null}.
     * @param opts       The signing options, empty or {@code null} if
     *                   none.
     *
     * @throws JOSEException If the alg of key is not supported.
     */
    public MLDSASigner(final PrivateKey privateKey, final Set<JWSSignerOption> opts)
            throws JOSEException, IOException {

        super(MLDSA.resolveAlgorithm(privateKey));

        this.privateKey = privateKey;
        this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
    }


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * signer.
     *
     * @param mldsaJWK The ML-DSA JSON Web Key (JWK). Must contain a private part.
     *              Must not be {@code null}.
     *
     * @throws JOSEException If the EC JWK doesn't contain a private part,
     *                       its extraction failed, or the elliptic curve
     *                       is not supported.
     */
    public MLDSASigner(final MLDSAKey mldsaJWK)
            throws JOSEException {
        this(mldsaJWK, null);
    }


    /**
     * Creates a new Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
     * signer.
     *
     * @param mldsaJWK The ML-DSA JSON Web Key (JWK). Must contain a private part.
     *              Must not be {@code null}.
     * @param opts  The signing options, empty or {@code null} if
     *              none.
     *
     * @throws JOSEException If the EC JWK doesn't contain a private part,
     *                       its extraction failed, or the elliptic curve
     *                       is not supported.
     */
    public MLDSASigner(final MLDSAKey mldsaJWK, final Set<JWSSignerOption> opts)
            throws JOSEException {

        super(MLDSA.resolveAlgorithm(mldsaJWK.getAlgorithm()));

        if (! mldsaJWK.isPrivate()) {
            throw new JOSEException("The ML-DSA JWK doesn't contain a private part");
        }

        privateKey = mldsaJWK.toPrivateKey();
        this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
    }


    /**
     * Gets the private ML-DSA key.
     *
     * @return The private ML-DSA key. Casting to
     *         {@link java.security.PrivateKey} may not be
     *         possible if the key is located in a PKCS#11 store that
     *         doesn't expose the private key parameters.
     */
    public PrivateKey getPrivateKey() {

        return privateKey;
    }


    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput)
            throws JOSEException {

        final JWSAlgorithm alg = header.getAlgorithm();

        if (! supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
        }

        final byte[] jcaSignature;

        if ("ML-DSA-44".equals(alg.getName()) || "ML-DSA-65".equals(alg.getName()) || "ML-DSA-87".equals(alg.getName())) {
            final org.bouncycastle.pqc.crypto.mldsa.MLDSASigner signature = MLDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());

            AsymmetricKeyParameter bcPrivateKey;
            try {
                bcPrivateKey = PrivateKeyFactory.createKey(privateKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            signature.init(true, bcPrivateKey);

            if (OptionUtils.optionIsPresent(opts, UserAuthenticationRequired.class)) {

                throw new ActionRequiredForJWSCompletionException(
                        "Authenticate user to complete signing",
                        UserAuthenticationRequired.getInstance(),
                        new CompletableJWSObjectSigning() {
                            @Override
                            public Signature getInitializedSignature() {
                                return null;
                            }

                            @Override
                            public Base64URL complete() throws JOSEException {
                                signature.update(signingInput, 0, signingInput.length);
                                final byte[] jcaSignature;
                                try {
                                    jcaSignature = signature.generateSignature();
                                } catch (CryptoException e) {
                                    throw new JOSEException("Error: " + e.getMessage());
                                }
                                final int rsByteArrayLength = MLDSA.getSignatureByteArrayLength(header.getAlgorithm());
                                if (jcaSignature.length != rsByteArrayLength) {
                                    throw new JOSEException("Unexpected ML-DSA signature length");
                                }

                                return Base64URL.encode(jcaSignature);
                            }
                        }
                );
            }
            signature.update(signingInput, 0, signingInput.length);
            try {
                jcaSignature = signature.generateSignature();
            } catch (CryptoException e) {
                throw new JOSEException("Error: " + e.getMessage());
            }
        } else if ("Dilithium2".equals(alg.getName()) || "Dilithium3".equals(alg.getName()) || "Dilithium5".equals(alg.getName())) {
            final DilithiumSigner signature = new DilithiumSigner();

            AsymmetricKeyParameter bcPrivateKey;
            try {
                bcPrivateKey = PrivateKeyFactory.createKey(privateKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            signature.init(true, bcPrivateKey);

            if (OptionUtils.optionIsPresent(opts, UserAuthenticationRequired.class)) {

                throw new ActionRequiredForJWSCompletionException(
                        "Authenticate user to complete signing",
                        UserAuthenticationRequired.getInstance(),
                        new CompletableJWSObjectSigning() {
                            @Override
                            public Signature getInitializedSignature() {
                                return null;
                            }

                            @Override
                            public Base64URL complete() throws JOSEException {

                                final byte[] jcaSignature = signature.generateSignature(signingInput);

                                final int rsByteArrayLength = MLDSA.getSignatureByteArrayLength(header.getAlgorithm());
                                if (jcaSignature.length != rsByteArrayLength) {
                                    throw new JOSEException("Unexpected Dilithium signature length");
                                }

                                return Base64URL.encode(jcaSignature);
                            }
                        }
                );
            }

            jcaSignature = signature.generateSignature(signingInput);

        } else {
            throw new JOSEException("Unexpected algorithm: " + alg);
        }

        final int rsByteArrayLength = MLDSA.getSignatureByteArrayLength(header.getAlgorithm());
        if (jcaSignature.length != rsByteArrayLength) {
            System.out.println("HEADER ALG: " + header.getAlgorithm());
            System.out.println(jcaSignature.length + " != " + rsByteArrayLength);
            throw new JOSEException("Unexpected ML-DSA signature length");
        }

        return Base64URL.encode(jcaSignature);
    }
}
