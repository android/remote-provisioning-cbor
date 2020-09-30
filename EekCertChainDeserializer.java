/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package com.google.remote.cbor;

import com.google.remote.cbor.CryptoUtil;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.security.*;
import java.util.ArrayList;

/*
 * The primary purpose of this class is to deserialize EEK certificate requests so that the
 * functionality of EekCertChainSerializer can be tested. The remote provisioning server should have
 * no actual use for this class.
 */
public class EekCertChainDeserializer {

    private ArrayList<PublicKey> keyChain;

    public EekCertChainDeserializer(byte[] cborEncodedEekCertChain) throws CborException,
                                                                           CryptoException{
        keyChain = new ArrayList<PublicKey>();
        CBORObject eekChain = CBORObject.DecodeFromBytes(cborEncodedEekCertChain);
        if (eekChain.getType() != CBORType.Array) {
            throw new CborException("cborEncodedEekCertChain decodes to the wrong type",
                                    CBORType.Array,
                                    eekChain.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (eekChain.size() <= 1) {
            throw new CborException("Length of certificate chain is: " + eekChain.size()
                                    + "\nExpected at least 2.", CborException.INCORRECT_LENGTH);
        }
        for (int i = 1; i < eekChain.size(); i++) {
            if (!CryptoUtil.verifyCert(eekChain.get(i-1), eekChain.get(i))) {
                throw new CryptoException("Certificate " + (i-1) + " verification of certificate "
                                          + i + " fails.", CryptoException.VERIFICATION_FAILURE);
            }
            keyChain.add(CryptoUtil.getKeyFromCert(eekChain.get(i-1)));
            if (i == eekChain.size() - 1) {
                keyChain.add(CryptoUtil.getKeyFromCert(eekChain.get(i)));
            }
        }
    }

    public PublicKey getEek() {
        return keyChain.get(keyChain.size() - 1);
    }

    public ArrayList<PublicKey> getKeyChain() {
        return keyChain;
    }

}
