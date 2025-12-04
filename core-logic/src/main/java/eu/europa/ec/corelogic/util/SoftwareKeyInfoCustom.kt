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

package eu.europa.ec.corelogic.util

import com.android.identity.cose.CoseKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.securearea.KeyAttestation
import com.android.identity.securearea.KeyInfo
import com.android.identity.securearea.KeyPurpose
import com.android.identity.securearea.PassphraseConstraints
import java.security.PublicKey

class SoftwareKeyInfo constructor(
    publicKey: EcPublicKey,
    attestation: KeyAttestation,
    keyPurposes: Set<KeyPurpose>,
    val isPassphraseProtected: Boolean,
    val passphraseConstraints: PassphraseConstraints?,
    val dilithiumPublicKey: CoseKey
): KeyInfo(
    publicKey,
    keyPurposes,
    attestation
)