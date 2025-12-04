/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2024, Connect2id Ltd.
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

package com.nimbusds.jose.jwk;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.utils.MLDSAUtils;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.math.BigInteger;
import java.net.URI;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;


/**
 * Public and private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK).
 * This class is immutable.
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
 * <p>Provides EC JWK import from / export to the following standard Java
 * interfaces and classes:
 *
 * <ul>
 *     <li>{@link java.security.interfaces.ECPublicKey}
 *     <li>{@link java.security.interfaces.ECPrivateKey}
 *     <li>{@link java.security.PrivateKey} for an EC key in a PKCS#11 store
 *     <li>{@link java.security.KeyPair}
 * </ul>
 *
 * <p>Example JSON object representation of a public AKP JWK:
 *
 * <pre>
 * {
 *   "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
 *   "kty" : "AKP",
 *   "alg" : "ML-DSA-44",
 *   "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l
 *   0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsL
 *   e8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7z
 *   Tuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yY
 *   JEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29
 *   n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6
 *   F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwd
 *   OY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIy
 *   blAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c
 *   9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD
 *   7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnma
 *   etjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjV
 *   jYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8Y
 *   VBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeI
 *   Hj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4
 *   F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a private AKP JWK:
 *
 * <pre>
 * {
 *     "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
 *     "kty": "AKP",
 *     "alg": "ML-DSA-44",
 *     "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk
 *     8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLo
 *     aWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHP
 *     IX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCX
 *     Y4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV4
 *     4qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJM
 *     RxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeri
 *     q1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNg
 *     GWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9
 *     eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21
 *     fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLB
 *     DbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11E
 *     vuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ
 *     5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8p
 *     mkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDW
 *     X-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ",
 *     "seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
 * }
 * </pre>
 *
 * <p>Use the builder to create a new EC JWK:
 *
 * <pre>
 * ECKey key = new ECKey.Builder(Curve.P_256, x, y)
 * 	.keyUse(KeyUse.SIGNATURE)
 * 	.keyID("1")
 * 	.build();
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2024-10-31
 */
@Immutable
public final class MLDSAKey extends JWK implements AsymmetricJWK {


    private static final long serialVersionUID = 1L;


    /**
     * Supported EC curves.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87,
                    JWSAlgorithm.Dilithium2, JWSAlgorithm.Dilithium3, JWSAlgorithm.Dilithium5))
    );


    /**
     * Builder for constructing ML-DSA JWKs.
     *
     * <p>Example usage:
     *
     * <pre>
     * MLDSAKey key = new MLDSAKey.Builder(JWSAlgorithm.ML_DSA_44, pub)
     *     .privateKey(priv)
     *     .keyID("1")
     *     .build();
     * </pre>
     */
    public static class Builder {


        /**
         * The intended JOSE algorithm for the key, optional.
         */
        private Algorithm alg;


        /**
         * The public ML-DSA key, as PKCS#11 handle, optional.
         */
        private final PublicKey pub;


        /**
         * The private ML-DSA key, as PKCS#11 handle, optional.
         */
        private PrivateKey priv;


        /**
         * The seed.
         */
        private Base64URL seed;


        /**
         * The key use, optional.
         */
        private KeyUse use;


        /**
         * The key operations, optional.
         */
        private Set<KeyOperation> ops;


        /**
         * The key ID, optional.
         */
        private String kid;


        /**
         * X.509 certificate URL, optional.
         */
        private URI x5u;


        /**
         * X.509 certificate SHA-1 thumbprint, optional.
         */
        @Deprecated
        private Base64URL x5t;


        /**
         * X.509 certificate SHA-256 thumbprint, optional.
         */
        private Base64URL x5t256;


        /**
         * The X.509 certificate chain, optional.
         */
        private List<Base64> x5c;


        /**
         * The key expiration time, optional.
         */
        private Date exp;


        /**
         * The key not-before time, optional.
         */
        private Date nbf;


        /**
         * The key issued-at time, optional.
         */
        private Date iat;


        /**
         * The key revocation, optional.
         */
        private KeyRevocation revocation;


        /**
         * Reference to the underlying key store, {@code null} if none.
         */
        private KeyStore ks;


        /**
         * Creates a new ML-DSA JWK builder.
         *
         * @param alg The intended JOSE algorithm for the key. Must not be
         *            {@code null}.
         * @param pub The public ML-DSA key. Must not be {@code null}.
         */
        public Builder(final Algorithm alg, final PublicKey pub) {

            if (pub != null && !(
                    "ML-DSA-44".equalsIgnoreCase(pub.getAlgorithm()) ||
                            "ML-DSA-65".equalsIgnoreCase(pub.getAlgorithm()) ||
                            "ML-DSA-87".equalsIgnoreCase(pub.getAlgorithm()) ||
                            "Dilithium2".equalsIgnoreCase(pub.getAlgorithm()) ||
                            "Dilithium3".equalsIgnoreCase(pub.getAlgorithm()) ||
                            "Dilithium5".equalsIgnoreCase(pub.getAlgorithm())
            )) {
                throw new IllegalArgumentException("The public key algorithm must be ML-DSA-44, ML-DSA-65, ML-DSA-87, Dilithium2, Dilithium3 or Dilithium5");
            }

            this.alg = Objects.requireNonNull(alg, "The algorithm must not be null");
            this.pub = Objects.requireNonNull(pub, "The public key must not be null");
        }


        /**
         * Creates a new ML-DSA JWK builder.
         *
         * @param alg The intended JOSE algorithm for the key. Must not be
         *            {@code null}.
         * @param pub The public ML-DSA key. Must not be {@code null}.
         */
        public Builder(final Algorithm alg, final Base64URL pub) {

            PublicKey pubKey = MLDSAUtils.base64toPublicKey(pub, alg);

            this.alg = Objects.requireNonNull(alg, "The algorithm must not be null");
            this.pub = Objects.requireNonNull(pubKey, "The public key must not be null");
        }


        /**
         * Creates a new ML-DSA JWK builder.
         *
         * @param mldsaJWK The ML-DSA JWK to start with. Must not be
         *              {@code null}.
         */
        public Builder(final MLDSAKey mldsaJWK) {

            alg = mldsaJWK.alg;
            pub = mldsaJWK.pub;
            priv = mldsaJWK.priv;
            seed = mldsaJWK.seed;
            use = mldsaJWK.getKeyUse();
            ops = mldsaJWK.getKeyOperations();
            kid = mldsaJWK.getKeyID();
            x5u = mldsaJWK.getX509CertURL();
            x5t = mldsaJWK.getX509CertThumbprint();
            x5t256 = mldsaJWK.getX509CertSHA256Thumbprint();
            x5c = mldsaJWK.getX509CertChain();
            exp = mldsaJWK.getExpirationTime();
            nbf = mldsaJWK.getNotBeforeTime();
            iat = mldsaJWK.getIssueTime();
            revocation = mldsaJWK.getKeyRevocation();
            ks = mldsaJWK.getKeyStore();
        }


        /**
         * Sets the private ML-DSA key.
         *
         * @param priv The private ML-DSA key.
         *
         * @return This builder.
         */
        public Builder privateKey(final PrivateKey priv) {

            if (priv != null && !(
                    "ML-DSA-44".equalsIgnoreCase(priv.getAlgorithm()) ||
                            "ML-DSA-65".equalsIgnoreCase(priv.getAlgorithm()) ||
                            "ML-DSA-87".equalsIgnoreCase(priv.getAlgorithm()) ||
                            "Dilithium2".equalsIgnoreCase(priv.getAlgorithm()) ||
                            "Dilithium3".equalsIgnoreCase(priv.getAlgorithm()) ||
                            "Dilithium5".equalsIgnoreCase(priv.getAlgorithm())
            )) {
                throw new IllegalArgumentException("The private key algorithm must be ML-DSA-44, ML-DSA-65, ML-DSA-87, Dilithium2, Dilithium3 or Dilithium5");
            }

            this.priv = priv;
            return this;
        }


        /**
         * Sets the private ML-DSA key.
         *
         * @param seed The seed ML-DSA.
         *
         * @return This builder.
         */
        public Builder seed(final Base64URL seed) {

            if (seed == null) {
                throw new IllegalArgumentException("The seed must be non-null.");
            }

            this.seed = seed;
            return this;
        }


        /**
         * Sets the use ({@code use}) of the JWK.
         *
         * @param use The key use, {@code null} if not specified or if
         *            the key is intended for signing as well as
         *            encryption.
         *
         * @return This builder.
         */
        public Builder keyUse(final KeyUse use) {

            this.use = use;
            return this;
        }


        /**
         * Sets the operations ({@code key_ops}) of the JWK.
         *
         * @param ops The key operations, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder keyOperations(final Set<KeyOperation> ops) {

            this.ops = ops;
            return this;
        }


        /**
         * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
         *
         * @param alg The intended JOSE algorithm, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder algorithm(final Algorithm alg) {

            this.alg = alg;
            return this;
        }

        /**
         * Sets the ID ({@code kid}) of the JWK. The key ID can be used
         * to match a specific key. This can be used, for instance, to
         * choose a key within a {@link JWKSet} during key rollover.
         * The key ID may also correspond to a JWS/JWE {@code kid}
         * header parameter value.
         *
         * @param kid The key ID, {@code null} if not specified.
         *
         * @return This builder.
         */
        public Builder keyID(final String kid) {

            this.kid = kid;
            return this;
        }


        /**
         * Sets the ID ({@code kid}) of the JWK to its SHA-256 JWK
         * thumbprint (RFC 7638). The key ID can be used to match a
         * specific key. This can be used, for instance, to choose a
         * key within a {@link JWKSet} during key rollover. The key ID
         * may also correspond to a JWS/JWE {@code kid} header
         * parameter value.
         *
         * @return This builder.
         *
         * @throws JOSEException If the SHA-256 hash algorithm is not
         *                       supported.
         */
        public Builder keyIDFromThumbprint()
                throws JOSEException {

            return keyIDFromThumbprint("SHA-256");
        }


        /**
         * Sets the ID ({@code kid}) of the JWK to its JWK thumbprint
         * (RFC 7638). The key ID can be used to match a specific key.
         * This can be used, for instance, to choose a key within a
         * {@link JWKSet} during key rollover. The key ID may also
         * correspond to a JWS/JWE {@code kid} header parameter value.
         *
         * @param hashAlg The hash algorithm for the JWK thumbprint
         *                computation. Must not be {@code null}.
         *
         * @return This builder.
         *
         * @throws JOSEException If the hash algorithm is not
         *                       supported.
         */
        public Builder keyIDFromThumbprint(final String hashAlg)
                throws JOSEException {

            // Put mandatory params in sorted order
            LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();
            requiredParams.put(JWKParameterNames.ALGORITHM, alg.toString());
            requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.AKP.getValue());
//            requiredParams.put(JWKParameterNames.AKP_PUBLIC_KEY, Base64URL.encode(pub.getEncoded()).toString());
            requiredParams.put(JWKParameterNames.AKP_PUBLIC_KEY, MLDSAUtils.publicKeyToBase64(pub).toString());
            this.kid = ThumbprintUtils.compute(hashAlg, requiredParams).toString();
            return this;
        }


        /**
         * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
         *
         * @param x5u The X.509 certificate URL, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder x509CertURL(final URI x5u) {

            this.x5u = x5u;
            return this;
        }


        /**
         * Sets the X.509 certificate SHA-1 thumbprint ({@code x5t}) of
         * the JWK.
         *
         * @param x5t The X.509 certificate SHA-1 thumbprint,
         *            {@code null} if not specified.
         *
         * @return This builder.
         */
        @Deprecated
        public Builder x509CertThumbprint(final Base64URL x5t) {

            this.x5t = x5t;
            return this;
        }


        /**
         * Sets the X.509 certificate SHA-256 thumbprint
         * ({@code x5t#S256}) of the JWK.
         *
         * @param x5t256 The X.509 certificate SHA-256 thumbprint,
         *               {@code null} if not specified.
         *
         * @return This builder.
         */
        public Builder x509CertSHA256Thumbprint(final Base64URL x5t256) {

            this.x5t256 = x5t256;
            return this;
        }


        /**
         * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
         *
         * @param x5c The X.509 certificate chain as a unmodifiable
         *            list, {@code null} if not specified.
         *
         * @return This builder.
         */
        public Builder x509CertChain(final List<Base64> x5c) {

            this.x5c = x5c;
            return this;
        }


        /**
         * Sets the expiration time ({@code exp}) of the JWK.
         *
         * @param exp The expiration time, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder expirationTime(final Date exp) {

            this.exp = exp;
            return this;
        }


        /**
         * Sets the not-before time ({@code nbf}) of the JWK.
         *
         * @param nbf The not-before time, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder notBeforeTime(final Date nbf) {

            this.nbf = nbf;
            return this;
        }


        /**
         * Sets the issued-at time ({@code iat}) of the JWK.
         *
         * @param iat The issued-at time, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder issueTime(final Date iat) {

            this.iat = iat;
            return this;
        }


        /**
         * Sets the revocation ({@code revoked}) of the JWK.
         *
         * @param revocation The key revocation, {@code null} if not
         *                   specified.
         *
         * @return This builder.
         */
        public Builder keyRevocation(final KeyRevocation revocation) {

            this.revocation = revocation;
            return this;
        }


        /**
         * Sets the underlying key store.
         *
         * @param keyStore Reference to the underlying key store,
         *                 {@code null} if none.
         *
         * @return This builder.
         */
        public Builder keyStore(final KeyStore keyStore) {

            this.ks = keyStore;
            return this;
        }


        /**
         * Builds a new Elliptic Curve JWK.
         *
         * @return The Elliptic Curve JWK.
         *
         * @throws IllegalStateException If the JWK parameters were
         *                               inconsistently specified.
         */
        public MLDSAKey build() {

            try {
                if (priv == null && seed == null) {
                    // Public key
                    return new MLDSAKey(alg, pub, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
                }
                else if  (priv == null) {
                    return new MLDSAKey(alg, pub, seed, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
                }
                else {
                    return new MLDSAKey(alg, pub, priv, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
                }
                // Public / private key pair with 'd'


            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }


    /**
     * Returns the Base64URL encoding of the specified elliptic curve 'x',
     * 'y' or 'd' coordinate, with leading zero padding up to the specified
     * field size in bits.
     *
     * @param fieldSize  The field size in bits.
     * @param coordinate The elliptic curve coordinate. Must not be
     *                   {@code null}.
     *
     * @return The Base64URL-encoded coordinate, with leading zero padding
     *         up to the curve's field size.
     */
    public static Base64URL encodeCoordinate(final int fieldSize, final BigInteger coordinate) {

        final byte[] notPadded = BigIntegerUtils.toBytesUnsigned(coordinate);

        int bytesToOutput = (fieldSize + 7)/8;

        if (notPadded.length >= bytesToOutput) {
            // Greater-than check to prevent exception on malformed
            // key below
            return Base64URL.encode(notPadded);
        }

        final byte[] padded = new byte[bytesToOutput];

        System.arraycopy(notPadded, 0, padded, bytesToOutput - notPadded.length, notPadded.length);

        return Base64URL.encode(padded);
    }


    /**
     * The algorithm name.
     */
    private final Algorithm alg;


    /**
     * The public key.
     */
    private final PublicKey pub;


    /**
     * The private key.
     */
    private final PrivateKey priv;


    /**
     * The seed.
     */
    private final Base64URL seed;


    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final KeyStore ks) {

        this(alg, pub, use, ops, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
    }


    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final Base64URL pub,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final KeyStore ks) {

        this(alg, pub, use, ops, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
    }



    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters. The private key is specified by its
     * PKCS#11 handle.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param priv   The private ML-DSA key as a PKCS#11 handle, {@code null} if
     *               not specified.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final PrivateKey priv,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final KeyStore ks) {

        this(alg, pub, priv, use, ops, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters. The private key is specified by its
     * PKCS#11 handle.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA as a PKCS#11 handle, {@code null} if
     *               not specified.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final KeyStore ks) {

        this(alg, pub, seed, use, ops, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters. The private key is specified by its
     * PKCS#11 handle.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA as a PKCS#11 handle, {@code null} if
     *               not specified.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final Base64URL pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final KeyStore ks) {

        this(alg, pub, seed, use, ops, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
    }


    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param exp    The key expiration time, {@code null} if not
     *               specified.
     * @param nbf    The key not-before time, {@code null} if not
     *               specified.
     * @param iat    The key issued-at time, {@code null} if not specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat,
                    final KeyStore ks) {

        this(alg, pub, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
    }

    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param exp    The key expiration time, {@code null} if not
     *               specified.
     * @param nbf    The key not-before time, {@code null} if not
     *               specified.
     * @param iat    The key issued-at time, {@code null} if not specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final Base64URL pub,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat,
                    final KeyStore ks) {

        this(alg, pub, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
    }


    // JWK public
    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use        The key use, {@code null} if not specified or if
     *                   the key is intended for signing as well as
     *                   encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t        The X.509 certificate SHA-1 thumbprint,
     *                   {@code null} if not specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint,
     *                   {@code null} if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     * @param exp        The key expiration time, {@code null} if not
     *                   specified.
     * @param nbf        The key not-before time, {@code null} if not
     *                   specified.
     * @param iat        The key issued-at time, {@code null} if not
     *                   specified.
     * @param revocation The key revocation, {@code null} if not specified.
     * @param ks         Reference to the underlying key store,
     *                   {@code null} if not specified.
     */
    public MLDSAKey(final Algorithm alg, final PublicKey pub,
                    final KeyUse use, final Set<KeyOperation> ops,  final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
                    final KeyStore ks) {

        super(KeyType.AKP, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
        this.alg = Objects.requireNonNull(alg, "The algorithm must not be null");
        this.pub = Objects.requireNonNull(pub, "The public key must not be null");
        ensureMatches(getParsedX509CertChain());
        this.priv = null;
        this.seed = null;
    }


    // JWK public
    /**
     * Creates a new public Elliptic Curve JSON Web Key (JWK) with the
     * specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param use        The key use, {@code null} if not specified or if
     *                   the key is intended for signing as well as
     *                   encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t        The X.509 certificate SHA-1 thumbprint,
     *                   {@code null} if not specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint,
     *                   {@code null} if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     * @param exp        The key expiration time, {@code null} if not
     *                   specified.
     * @param nbf        The key not-before time, {@code null} if not
     *                   specified.
     * @param iat        The key issued-at time, {@code null} if not
     *                   specified.
     * @param revocation The key revocation, {@code null} if not specified.
     * @param ks         Reference to the underlying key store,
     *                   {@code null} if not specified.
     */
    public MLDSAKey(final Algorithm alg, final Base64URL pub,
                    final KeyUse use, final Set<KeyOperation> ops,  final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
                    final KeyStore ks) {

        super(KeyType.AKP, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
        this.alg = Objects.requireNonNull(alg, "The algorithm must not be null");
        this.pub = MLDSAUtils.base64toPublicKey(Objects.requireNonNull(pub, "The public key must not be null"), alg);
        ensureMatches(getParsedX509CertChain());
        this.priv = null;
        this.seed = null;
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param priv   The private ML-DSA key. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param exp    The key expiration time, {@code null} if not
     *               specified.
     * @param nbf    The key not-before time, {@code null} if not
     *               specified.
     * @param iat    The key issued-at time, {@code null} if not specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final PrivateKey priv,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat,
                    final KeyStore ks) {

        this(alg, pub, priv, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param exp    The key expiration time, {@code null} if not
     *               specified.
     * @param nbf    The key not-before time, {@code null} if not
     *               specified.
     * @param iat    The key issued-at time, {@code null} if not specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat,
                    final KeyStore ks) {

        this(alg, pub, seed, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
    }


    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA. Must not be {@code null}.
     * @param use    The key use, {@code null} if not specified or if the
     *               key is intended for signing as well as encryption.
     * @param ops    The key operations, {@code null} if not specified.
     * @param kid    The key ID, {@code null} if not specified.
     * @param x5u    The X.509 certificate URL, {@code null} if not
     *               specified.
     * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
     *               if not specified.
     * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
     *               if not specified.
     * @param x5c    The X.509 certificate chain, {@code null} if not
     *               specified.
     * @param exp    The key expiration time, {@code null} if not
     *               specified.
     * @param nbf    The key not-before time, {@code null} if not
     *               specified.
     * @param iat    The key issued-at time, {@code null} if not specified.
     * @param ks     Reference to the underlying key store, {@code null} if
     *               not specified.
     */
    @Deprecated
    public MLDSAKey(final Algorithm alg, final Base64URL pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat,
                    final KeyStore ks) {

        this(alg, pub, seed, use, ops, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
    }



    // JWK public + private
    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param priv   The private ML-DSA key. Must not be {@code null}.
     * @param use        The key use, {@code null} if not specified or if
     *                   the key is intended for signing as well as
     *                   encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t        The X.509 certificate SHA-1 thumbprint,
     *                   {@code null} if not specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint,
     *                   {@code null} if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     * @param exp        The key expiration time, {@code null} if not
     *                   specified.
     * @param nbf        The key not-before time, {@code null} if not
     *                   specified.
     * @param iat        The key issued-at time, {@code null} if not
     *                   specified.
     * @param revocation The key revocation, {@code null} if not specified.
     * @param ks         Reference to the underlying key store,
     *                   {@code null} if not specified.
     */
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final PrivateKey priv,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
                    final KeyStore ks) {

        super(KeyType.AKP, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
        this.alg = Objects.requireNonNull(alg, "The algorythm must not be null");
        this.pub = Objects.requireNonNull(pub, "The public key must not be null");
        this.priv = Objects.requireNonNull(priv, "The private key must not be null");
        ensureMatches(getParsedX509CertChain());
        this.seed = null;
    }


    // JWK public + private
    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA. Must not be {@code null}.
     * @param use        The key use, {@code null} if not specified or if
     *                   the key is intended for signing as well as
     *                   encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t        The X.509 certificate SHA-1 thumbprint,
     *                   {@code null} if not specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint,
     *                   {@code null} if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     * @param exp        The key expiration time, {@code null} if not
     *                   specified.
     * @param nbf        The key not-before time, {@code null} if not
     *                   specified.
     * @param iat        The key issued-at time, {@code null} if not
     *                   specified.
     * @param revocation The key revocation, {@code null} if not specified.
     * @param ks         Reference to the underlying key store,
     *                   {@code null} if not specified.
     */
    public MLDSAKey(final Algorithm alg, final PublicKey pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
                    final KeyStore ks) {

        super(KeyType.AKP, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
        this.alg = Objects.requireNonNull(alg, "The algorythm must not be null");
        this.pub = Objects.requireNonNull(pub, "The public key must not be null");
        this.seed = Objects.requireNonNull(seed, "The seed must not be null");
        this.priv = null;
        ensureMatches(getParsedX509CertChain());
    }


    // JWK public + private
    /**
     * Creates a new public / private Elliptic Curve JSON Web Key (JWK)
     * with the specified parameters.
     *
     * @param alg    The intended JOSE algorithm for the key. Must not be {@code null}.
     * @param pub    The public ML-DSA key. Must not be {@code null}.
     * @param seed   The seed ML-DSA. Must not be {@code null}.
     * @param use        The key use, {@code null} if not specified or if
     *                   the key is intended for signing as well as
     *                   encryption.
     * @param ops        The key operations, {@code null} if not specified.
     * @param kid        The key ID, {@code null} if not specified.
     * @param x5u        The X.509 certificate URL, {@code null} if not
     *                   specified.
     * @param x5t        The X.509 certificate SHA-1 thumbprint,
     *                   {@code null} if not specified.
     * @param x5t256     The X.509 certificate SHA-256 thumbprint,
     *                   {@code null} if not specified.
     * @param x5c        The X.509 certificate chain, {@code null} if not
     *                   specified.
     * @param exp        The key expiration time, {@code null} if not
     *                   specified.
     * @param nbf        The key not-before time, {@code null} if not
     *                   specified.
     * @param iat        The key issued-at time, {@code null} if not
     *                   specified.
     * @param revocation The key revocation, {@code null} if not specified.
     * @param ks         Reference to the underlying key store,
     *                   {@code null} if not specified.
     */
    public MLDSAKey(final Algorithm alg, final Base64URL pub, final Base64URL seed,
                    final KeyUse use, final Set<KeyOperation> ops, final String kid,
                    final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
                    final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
                    final KeyStore ks) {

        super(KeyType.AKP, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
        this.alg = Objects.requireNonNull(alg, "The algorythm must not be null");
        this.pub = MLDSAUtils.base64toPublicKey(Objects.requireNonNull(pub, "The public key must not be null"), alg);
        this.seed = Objects.requireNonNull(seed, "The seed must not be null");
        this.priv = null;
        ensureMatches(getParsedX509CertChain());
    }


    @Override
    public Algorithm getAlgorithm() {

        return alg;
    }

    public Base64URL getSeed() {

        return seed;
    }


    @Override
    public PublicKey toPublicKey() {
        return pub;
    }


    @Override
    public PrivateKey toPrivateKey() throws JOSEException {
        if (seed != null) {
            return MLDSAUtils.seedToPrivateKey(seed, alg);
//            return privateKey;
        }
        return priv;
    }


    @Override
    public KeyPair toKeyPair() throws JOSEException {
        return new KeyPair(pub, toPrivateKey());
    }


    @Override
    public MLDSAKey toRevokedJWK(final KeyRevocation keyRevocation) {

        if (getKeyRevocation() != null) {
            throw new IllegalStateException("Already revoked");
        }

        return new MLDSAKey.Builder(this)
                .keyRevocation(Objects.requireNonNull(keyRevocation))
                .build();
    }


    @Override
    public boolean matches(final X509Certificate cert) {

        PublicKey certKey;
        try {
            certKey = (PublicKey) getParsedX509CertChain().get(0).getPublicKey();
        } catch (ClassCastException ex) {
            return false;
        }
        return toPublicKey().equals(certKey);
    }


    /**
     * Calls {@link #matches(X509Certificate)} for the first X.509
     * certificate in the specified chain.
     *
     * @param chain The X.509 certificate chain, {@code null} if not
     *              specified.
     *
     * @throws IllegalArgumentException If a certificate chain is specified
     *                                  and the first certificate in it
     *                                  doesn't match.
     */
    private void ensureMatches(final List<X509Certificate> chain) {

        if (chain == null)
            return;

        if (! matches(chain.get(0)))
            throw new IllegalArgumentException("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
    }


    @Override
    public LinkedHashMap<String,?> getRequiredParams() {

        // Put mandatory params in sorted order
        LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();

        requiredParams.put(JWKParameterNames.ALGORITHM, alg.toString());
        requiredParams.put(JWKParameterNames.KEY_TYPE, getKeyType().getValue());
//        requiredParams.put(JWKParameterNames.AKP_PUBLIC_KEY, Base64URL.encode(pub.getEncoded()).toString());
        requiredParams.put(JWKParameterNames.AKP_PUBLIC_KEY, MLDSAUtils.publicKeyToBase64(pub).toString());
        return requiredParams;
    }


    @Override
    public boolean isPrivate() {
        if (priv == null) {
            return seed != null;
        } else {
            return priv != null;
        }
    }


    @Override
    public int size() {

        if (alg.equals(JWSAlgorithm.ML_DSA_44)) {
            return 2560;
        }
        else if (alg.equals(JWSAlgorithm.ML_DSA_65)) {
            return 4032;
        }
        else if (alg.equals(JWSAlgorithm.ML_DSA_87)) {
            return 4896;
        }
        else if (alg.equals(JWSAlgorithm.Dilithium2)) {
            return 2528;
        }
        else if (alg.equals(JWSAlgorithm.Dilithium3)) {
            return 4000;
        }
        else if (alg.equals(JWSAlgorithm.Dilithium5)) {
            return 4864;
        }
        else {
            throw new UnsupportedOperationException("Couldn't determine field size for algorithm " + alg.getName());
        }
    }


    /**
     * Returns a copy of this Elliptic Curve JWK with any private values
     * removed.toPublicJWK
     *
     * @return The copied public Elliptic Curve JWK.
     */
    @Override
    public MLDSAKey toPublicJWK() {

        return new MLDSAKey(
                getAlgorithm(), toPublicKey(),
                getKeyUse(), getKeyOperations(), getKeyID(),
                getX509CertURL(), getX509CertThumbprint(), getX509CertSHA256Thumbprint(), getX509CertChain(),
                getExpirationTime(), getNotBeforeTime(), getIssueTime(), getKeyRevocation(),
                getKeyStore());
    }


    @Override
    public Map<String, Object> toJSONObject() {

        Map<String, Object> o = super.toJSONObject();

        // Append EC specific attributes
//        o.put(JWKParameterNames.ALGORITHM, alg.toString());
        o.put(JWKParameterNames.AKP_PUBLIC_KEY, MLDSAUtils.publicKeyToBase64(pub).toString());

        if (seed != null) {
            o.put(JWKParameterNames.AKP_SEED, seed.toString());
        }

        if (priv != null) {
            o.put(JWKParameterNames.AKP_PRIVATE_KEY, MLDSAUtils.privateKeyToBase64URL(priv).toString());
        }

        return o;
    }


    /**
     * Parses a public / private Elliptic Curve JWK from the specified JSON
     * object string representation.
     *
     * @param s The JSON object string to parse. Must not be {@code null}.
     *
     * @return The public / private Elliptic Curve JWK.
     *
     * @throws ParseException If the string couldn't be parsed to an
     *                        Elliptic Curve JWK.
     */
    public static MLDSAKey parse(final String s)
            throws ParseException {

        return parse(JSONObjectUtils.parse(s));
    }


    /**
     * Parses a public / private Elliptic Curve JWK from the specified JSON
     * object representation.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     *
     * @return The public / private Elliptic Curve JWK.
     *
     * @throws ParseException If the JSON object couldn't be parsed to an
     *                        Elliptic Curve JWK.
     */
    public static MLDSAKey parse(final Map<String, Object> jsonObject)
            throws ParseException {

        // Check key type
        if (! KeyType.AKP.equals(JWKMetadata.parseKeyType(jsonObject))) {
            throw new ParseException("The key type \"kty\" must be AKT", 0);
        }

        // Parse the mandatory public key parameters
        Algorithm alg = JWKMetadata.parseAlgorithm(jsonObject);
        PrivateKey priv;
        PublicKey pub;
        Base64URL seed;

        Base64URL pubBase64 = JSONObjectUtils.getBase64URL(jsonObject, JWKParameterNames.AKP_PUBLIC_KEY);
        pub = MLDSAUtils.base64toPublicKey(pubBase64, alg);

        Base64URL privBase64 = JSONObjectUtils.getBase64URL(jsonObject, JWKParameterNames.AKP_PRIVATE_KEY);
        if (privBase64 == null) {
            priv = null;
        } else {
            try {
                priv = MLDSAUtils.base64toPrivateKey(privBase64, alg);
            } catch (JOSEException e) {
                throw new ParseException("Parse exception: " +  e.getMessage(), 0);
            }
        }

        seed = JSONObjectUtils.getBase64URL(jsonObject, JWKParameterNames.AKP_SEED);

        try {
            if (priv == null && seed == null) {
                // Public key
                return new MLDSAKey(alg, pub,
                        JWKMetadata.parseKeyUse(jsonObject),
                        JWKMetadata.parseKeyOperations(jsonObject),
                        JWKMetadata.parseKeyID(jsonObject),
                        JWKMetadata.parseX509CertURL(jsonObject),
                        JWKMetadata.parseX509CertThumbprint(jsonObject),
                        JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                        JWKMetadata.parseX509CertChain(jsonObject),
                        JWKMetadata.parseExpirationTime(jsonObject),
                        JWKMetadata.parseNotBeforeTime(jsonObject),
                        JWKMetadata.parseIssueTime(jsonObject),
                        JWKMetadata.parseKeyRevocation(jsonObject),
                        null);

            } else if (priv == null && seed != null) {
                return new MLDSAKey(alg, pub, seed,
                        JWKMetadata.parseKeyUse(jsonObject),
                        JWKMetadata.parseKeyOperations(jsonObject),
                        JWKMetadata.parseKeyID(jsonObject),
                        JWKMetadata.parseX509CertURL(jsonObject),
                        JWKMetadata.parseX509CertThumbprint(jsonObject),
                        JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                        JWKMetadata.parseX509CertChain(jsonObject),
                        JWKMetadata.parseExpirationTime(jsonObject),
                        JWKMetadata.parseNotBeforeTime(jsonObject),
                        JWKMetadata.parseIssueTime(jsonObject),
                        JWKMetadata.parseKeyRevocation(jsonObject),
                        null);
            } else {
                // Key pair
                return new MLDSAKey(alg, pub, priv,
                        JWKMetadata.parseKeyUse(jsonObject),
                        JWKMetadata.parseKeyOperations(jsonObject),
                        JWKMetadata.parseKeyID(jsonObject),
                        JWKMetadata.parseX509CertURL(jsonObject),
                        JWKMetadata.parseX509CertThumbprint(jsonObject),
                        JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
                        JWKMetadata.parseX509CertChain(jsonObject),
                        JWKMetadata.parseExpirationTime(jsonObject),
                        JWKMetadata.parseNotBeforeTime(jsonObject),
                        JWKMetadata.parseIssueTime(jsonObject),
                        JWKMetadata.parseKeyRevocation(jsonObject),
                        null);
            }

        } catch (Exception ex) {

            // Missing x or y, conflicting 'use' and 'key_ops'
            throw new ParseException(ex.getMessage(), 0);
        }
    }


    /**
     * Parses a public Elliptic Curve JWK from the specified X.509
     * certificate. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * <p>Sets the following JWK parameters:
     *
     * <ul>
     *     <li>The curve is obtained from the subject public key info
     *         algorithm parameters.
     *     <li>The JWK use inferred by {@link KeyUse#from}.
     *     <li>The JWK ID from the X.509 serial number (in base 10).
     *     <li>The JWK X.509 certificate chain (this certificate only).
     *     <li>The JWK X.509 certificate SHA-256 thumbprint.
     * </ul>
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     *
     * @return The public Elliptic Curve JWK.
     *
     * @throws JOSEException If parsing failed.
     */
    public static MLDSAKey parse(final X509Certificate cert)
            throws JOSEException {

        PublicKey publicKey = (PublicKey) cert.getPublicKey();
        Algorithm alg;
        try {
            JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

            String oid = certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString();

            switch (oid) {
                case "2.16.840.1.101.3.4.17":
                    alg = JWSAlgorithm.ML_DSA_44;
                    break;
                case "2.16.840.1.101.3.4.18":
                    alg = JWSAlgorithm.ML_DSA_65;
                    break;
                case "2.16.840.1.101.3.4.19":
                    alg = JWSAlgorithm.ML_DSA_87;
                    break;
                case "1.3.6.1.4.1.2.267.12.4.4":
                    alg = JWSAlgorithm.Dilithium2;
                    break;
                case "1.3.6.1.4.1.2.267.12.6.5":
                    alg = JWSAlgorithm.Dilithium3;
                    break;
                case "1.3.6.1.4.1.2.267.12.8.7":
                    alg = JWSAlgorithm.Dilithium5;
                    break;
                default:
                    throw new JOSEException("Couldn't determine ML-DSA, DILITHIUM JWK alg for OID " + oid);
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            return new MLDSAKey.Builder(alg, publicKey)
                    .keyUse(KeyUse.from(cert))
                    .keyID(cert.getSerialNumber().toString(10))
                    .x509CertChain(Collections.singletonList(Base64.encode(cert.getEncoded())))
                    .x509CertSHA256Thumbprint(Base64URL.encode(sha256.digest(cert.getEncoded())))
                    .expirationTime(cert.getNotAfter())
                    .notBeforeTime(cert.getNotBefore())
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't encode x5t parameter: " + e.getMessage(), e);
        } catch (CertificateEncodingException e) {
            throw new JOSEException("Couldn't encode x5c parameter: " + e.getMessage(), e);
        }
    }


    /**
     * Loads a public / private Elliptic Curve JWK from the specified JCA
     * key store. Requires BouncyCastle.
     *
     * <p><strong>Important:</strong> The X.509 certificate is not
     * validated!
     *
     * @param keyStore The key store. Must not be {@code null}.
     * @param alias    The alias. Must not be {@code null}.
     * @param pin      The pin to unlock the private key if any, empty or
     *                 {@code null} if not required.
     *
     * @return The public / private Elliptic Curve JWK., {@code null} if no
     *         key with the specified alias was found.
     *
     * @throws KeyStoreException On a key store exception.
     * @throws JOSEException     If EC key loading failed.
     */
    public static MLDSAKey load(final KeyStore keyStore,
                                final String alias,
                                final char[] pin)
            throws KeyStoreException, JOSEException {

        Certificate cert = keyStore.getCertificate(alias);

        if (!(cert instanceof X509Certificate)) {
            return null;
        }

        X509Certificate x509Cert = (X509Certificate)cert;

//        if (! (x509Cert.getPublicKey() instanceof ECPublicKey)) {
//            throw new JOSEException("Couldn't load EC JWK: The key algorithm is not EC");
//        }

        MLDSAKey mldsaJWK = MLDSAKey.parse(x509Cert);

        // Let kid=alias
        mldsaJWK = new MLDSAKey.Builder(mldsaJWK).keyID(alias).keyStore(keyStore).build();

        // Check for private counterpart
        Key key;
        try {
            key = keyStore.getKey(alias, pin);
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new JOSEException("Couldn't retrieve private ML-DSA key (bad pin?): " + e.getMessage(), e);
        }

        if (key instanceof PrivateKey && "ML-DSA".equalsIgnoreCase(key.getAlgorithm())) {
            // PKCS#11 store
            return new MLDSAKey.Builder(mldsaJWK)
                    .privateKey((PrivateKey)key)
                    .build();
        } else {
            return mldsaJWK;
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MLDSAKey)) return false;
        if (!super.equals(o)) return false;
        MLDSAKey mldsaKey = (MLDSAKey) o;
        return Objects.equals(alg, mldsaKey.alg) &&
                Objects.equals(pub, mldsaKey.pub) &&
                Objects.equals(priv, mldsaKey.priv) &&
                Objects.equals(seed, mldsaKey.seed);
    }


    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), alg, pub, priv);
    }
}
