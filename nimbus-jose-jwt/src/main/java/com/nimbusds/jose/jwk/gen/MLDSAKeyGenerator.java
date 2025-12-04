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

package com.nimbusds.jose.jwk.gen;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.MLDSAKey;

import java.security.*;
import java.util.Objects;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;


/**
 * Elliptic Curve (EC) JSON Web Key (JWK) generator.
 *
 * <p>Supported curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256 P-256}
 *     <li>{@link Curve#SECP256K1 secp256k1}
 *     <li>{@link Curve#P_384 P-384}
 *     <li>{@link Curve#P_521 P-512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Cranford
 * @version 2024-12-15
 */
public class MLDSAKeyGenerator extends JWKGenerator<MLDSAKey> {


    /**
     * The algorithm.
     */
    private final Algorithm alg;


    /**
     * Creates a new ML-DSA JWK generator.
     *
     * @param alg The algorithm. Must not be {@code null}.
     */
    public MLDSAKeyGenerator(final Algorithm alg) {
        this.alg = Objects.requireNonNull(alg);
    }


    @Override
    public MLDSAKey generate()
            throws JOSEException  {

        if (alg.equals(JWSAlgorithm.ML_DSA_44) ||  alg.equals(JWSAlgorithm.ML_DSA_65) || alg.equals(JWSAlgorithm.ML_DSA_87)) {
            MLDSAParameters params;
            if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
                params = MLDSAParameters.ml_dsa_44;
            }
            else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
                params = MLDSAParameters.ml_dsa_65;
            }
            else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
                params = MLDSAParameters.ml_dsa_87;
            }
            else {
                throw new JOSEException("Unsupported algorithm: " + alg);
            }

            KeyPair kp = getMLDSAKeyPair(params);


            MLDSAKey.Builder builder = new MLDSAKey.Builder(alg, kp.getPublic())
                    .privateKey(kp.getPrivate())
                    .keyUse(use)
                    .keyOperations(ops)
                    .algorithm(alg)
                    .expirationTime(exp)
                    .notBeforeTime(nbf)
                    .issueTime(iat)
                    .keyStore(keyStore);

            if (tprKid) {
                builder.keyIDFromThumbprint();
            } else {
                builder.keyID(kid);
            }

            return builder.build();
        } else if (alg.equals(JWSAlgorithm.Dilithium2) ||  alg.equals(JWSAlgorithm.Dilithium3) || alg.equals(JWSAlgorithm.Dilithium5)) {

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

            KeyPair kp = getDilithiumKeyPair(params);


            MLDSAKey.Builder builder = new MLDSAKey.Builder(alg, kp.getPublic())
                    .privateKey(kp.getPrivate())
                    .keyUse(use)
                    .keyOperations(ops)
                    .algorithm(alg)
                    .expirationTime(exp)
                    .notBeforeTime(nbf)
                    .issueTime(iat)
                    .keyStore(keyStore);

            if (tprKid) {
                builder.keyIDFromThumbprint();
            } else {
                builder.keyID(kid);
            }

            return builder.build();
        } else {
            throw new JOSEException("Unsupported algorithm: " + alg);
        }
    }

    private KeyPair getMLDSAKeyPair(MLDSAParameters params) {
        MLDSAKeyGenerationParameters genParams;

        if (secureRandom != null) {
            genParams = new MLDSAKeyGenerationParameters(secureRandom, params);
        } else {
            genParams = new MLDSAKeyGenerationParameters(new SecureRandom(),
                    params);
        }

        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(genParams);

//        KeyPair kp = generator.generateKeyPair();
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        BCMLDSAPublicKey pubKey = new BCMLDSAPublicKey(pub);
        BCMLDSAPrivateKey privKey = new BCMLDSAPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);
        return standardKeyPair;
    }

    private KeyPair getDilithiumKeyPair(DilithiumParameters params) {
        DilithiumKeyGenerationParameters genParams;

        if (secureRandom != null) {
            genParams = new DilithiumKeyGenerationParameters(secureRandom, params);
        } else {
            genParams = new DilithiumKeyGenerationParameters(new SecureRandom(),
                    params);
        }

        DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
        kpGen.init(genParams);

//        KeyPair kp = generator.generateKeyPair();
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) kp.getPublic();
        DilithiumPrivateKeyParameters priv = (DilithiumPrivateKeyParameters) kp.getPrivate();

        BCDilithiumPublicKey pubKey = new BCDilithiumPublicKey(pub);
        BCDilithiumPrivateKey privKey = new BCDilithiumPrivateKey(priv);

        KeyPair standardKeyPair = new KeyPair(pubKey, privKey);
        return standardKeyPair;
    }


}
