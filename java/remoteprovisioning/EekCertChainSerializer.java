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

package remoteprovisioning;

import remoteprovisioning.CborException;
import remoteprovisioning.CborUtil;
import remoteprovisioning.CryptoUtil;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;

/*
 * This class is to be used to generate EEK certificate chains to send to a device so that the
 * device can use the X25519 public key contained in the leaf certificate to encrypt the payload it
 * will send back.
 */
public class EekCertChainSerializer {
    private CBORObject eekChain;

    /*
     * Constructs an EndpointEncryptionKeySerializer from the actual keys that will be used to
     * generate the EEK certificate chain.
     *
     * The root certificate corresponds to the offline key pair that is used to sign an intermediate
     * for production use. This is a CBOR encoded binary blob.
     */
    public EekCertChainSerializer(byte[] cborEncodedCerts,
                                  OneKey intSigningKey,
                                  X25519PublicKeyParameters eek)
                                  throws CborException, CryptoException {
        eekChain = CBORObject.DecodeFromBytes(cborEncodedCerts);
        if (eekChain.getType() != CBORType.Array) {
            throw new CborException("cborEncodedCerts decodes to the wrong type",
                                    CBORType.Array,
                                    eekChain.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        eekChain.Add(CryptoUtil.createCertificateEd25519(intSigningKey, eek));
    }

    /*
     * Constructs a CBOR encoded byte array of the EEK certificate chain
     *
     * @return byte[] the CBOR encoded byte array
     */
    public byte[] buildEekChain() {
        return eekChain.EncodeToBytes();
    }

    /*
     * Builds a random EEK certificate chain with a provided X25519 public key as the EEK.
     *
     * @return a CBOR encoded EEK certificate chain byte array
     */
    public static byte[] generateEekChain(X25519PublicKeyParameters eek) throws CryptoException {
        try {
            OneKey eekRootKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
            OneKey eekIntKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
            CBORObject certArray = CBORObject.NewArray();
            certArray.Add(
                CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekRootKeyPair.PublicKey()));
            certArray.Add(
                CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekIntKeyPair.PublicKey()));
            certArray.Add(CryptoUtil.createCertificateEd25519(eekIntKeyPair, eek));
        return certArray.EncodeToBytes();
        } catch (CoseException e) {
            throw new CryptoException("Could not generate Ed25519 Key Pair.",
                                      e, CryptoException.KEY_GENERATION_FAILURE);
        }
    }
}
