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

package eu.europa.ec.eudi.wallet.document.credential

import java.security.PublicKey

class DilithiumPublicKey(private val encodedKey: ByteArray) : PublicKey {
    // TODO MM Restore to Dilithium3
    override fun getAlgorithm(): String = "Dilithium3"
    override fun getFormat(): String = "RAW"
    override fun getEncoded(): ByteArray = encodedKey
}