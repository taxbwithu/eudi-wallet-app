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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.security.Key;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


public class MLDSAKeyGeneratorTest extends TestCase {


    private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
    private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
    private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);


    public void testGenMinimal()
            throws JOSEException  {

        for (JWSAlgorithm alg: Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87)) {

            MLDSAKey mldsaJWK = new MLDSAKeyGenerator(alg)
                    .generate();

            assertEquals(alg, mldsaJWK.getAlgorithm());

            assertNull(mldsaJWK.getKeyUse());
            assertNull(mldsaJWK.getKeyOperations());
            assertNull(mldsaJWK.getKeyID());
            assertNull(mldsaJWK.getExpirationTime());
            assertNull(mldsaJWK.getNotBeforeTime());
            assertNull(mldsaJWK.getIssueTime());
            assertNull(mldsaJWK.getKeyStore());
        }
    }


//    public void testWithBouncyCastleProvider()
//            throws JOSEException  {
//
//        for (JWSAlgorithm alg: Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87)) {
//
//            MLDSAKey mldsaJWK = new MLDSAKeyGenerator(alg)
//                    .provider(BouncyCastleProviderSingleton.getInstance())
//                    .generate();
//
//            assertEquals(alg, mldsaJWK.getAlgorithm());
//        }
//    }


    public void testWithSecureRandom()
            throws JOSEException {

        final AtomicInteger nextBytesCalls = new AtomicInteger();

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44)
                .secureRandom(new SecureRandom() {
                    @Override
                    public void nextBytes(byte[] bytes) {
                        assertEquals(32, bytes.length);
                        super.nextBytes(bytes);
                        nextBytesCalls.incrementAndGet();
                    }
                })
                .generate();

        assertEquals(2560, mldsaJWK.size());
        assertEquals(1, nextBytesCalls.get());
    }


    // The pub, priv values that are generated should all be distinct
    public void testDistinctness()
            throws JOSEException  {

        Set<Key> values = new HashSet<>();

        MLDSAKeyGenerator gen = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44);

        for (int i=0; i<100; i++) {

            MLDSAKey k = gen.generate();
            assertTrue(values.add(k.toPublicKey()));
            assertTrue(values.add(k.toPrivateKey()));
        }

        gen = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65);

        for (int i=0; i<100; i++) {

            MLDSAKey k = gen.generate();
            assertTrue(values.add(k.toPublicKey()));
            assertTrue(values.add(k.toPrivateKey()));
        }

        gen = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_87);

        for (int i=0; i<100; i++) {

            MLDSAKey k = gen.generate();
            assertTrue(values.add(k.toPublicKey()));
            assertTrue(values.add(k.toPrivateKey()));
        }
    }


    public void testGenWithParams_explicitKeyID()
            throws JOSEException  {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44)
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Collections.singleton(KeyOperation.SIGN))
                .keyID("1")
                .generate();

        assertEquals(JWSAlgorithm.ML_DSA_44, mldsaJWK.getAlgorithm());

        assertEquals(KeyUse.SIGNATURE, mldsaJWK.getKeyUse());
        assertEquals(Collections.singleton(KeyOperation.SIGN), mldsaJWK.getKeyOperations());
        assertEquals("1", mldsaJWK.getKeyID());
        assertNull(mldsaJWK.getKeyStore());
    }


    public void testGenWithParams_thumbprintKeyID()
            throws JOSEException  {

        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44)
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(Collections.singleton(KeyOperation.SIGN))
                .keyIDFromThumbprint(true)
                .generate();

        assertEquals(JWSAlgorithm.ML_DSA_44, mldsaJWK.getAlgorithm());

        assertEquals(KeyUse.SIGNATURE, mldsaJWK.getKeyUse());
        assertEquals(Collections.singleton(KeyOperation.SIGN), mldsaJWK.getKeyOperations());
        assertEquals(ThumbprintUtils.compute(mldsaJWK).toString(), mldsaJWK.getKeyID());
        assertNull(mldsaJWK.getKeyStore());
    }


    public void testGenWithTimestamps() throws JOSEException {

        MLDSAKey ecJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44)
                .keyUse(KeyUse.SIGNATURE)
                .expirationTime(EXP)
                .notBeforeTime(NBF)
                .issueTime(IAT)
                .generate();

        assertEquals(EXP, ecJWK.getExpirationTime());
        assertEquals(NBF, ecJWK.getNotBeforeTime());
        assertEquals(IAT, ecJWK.getIssueTime());
    }


    // Ed25519 and X25519 are not allowed in EC keys.
    // See OctetKeyPair instead.
    public void testGenInvalidCurves() {

        try {
            new ECKeyGenerator(Curve.Ed25519).generate();
            fail();
        } catch (JOSEException e) {
            // Passed
            assertEquals("ECParameterSpec or ECGenParameterSpec required for EC", e.getMessage());
        }

        try {
            new ECKeyGenerator(Curve.X25519).generate();
            fail();

        } catch (JOSEException e) {
            // Passed
            assertEquals("ECParameterSpec or ECGenParameterSpec required for EC", e.getMessage());
        }
    }
}
