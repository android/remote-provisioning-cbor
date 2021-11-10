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


import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * This class is to be used to generate EEK certificate chains to send to a device so that the
 * device can use the X25519 public key contained in the leaf certificate to encrypt the payload it
 * will send back.
 */
public class EekCertChainSerializer {
  private final CBORObject eekChain;

  /**
   * Constructs an EndpointEncryptionKeySerializer from the actual keys that will be used to
   * generate the EEK certificate chain. The signing private key is provided as a serialized byte[].
   *
   * The root certificate corresponds to the offline key pair that is used to sign an intermediate
   * for production use. This is a CBOR encoded binary blob.
   *
   * @param encodedRootCert The self-signed encoded COSE_Sign1 corresponding to the root key.
   * @param encodedIntCert The COSE_Sign1 corresponding to the intermediate key signed by the root
   *                       key.
   * @param serializedIntSigningKey The byte array representing the Ed25519 private key used to sign
   *                                the X25519 leaf key.
   * @param eek The X25519 public key which will be used to encrypt the ProtectedData CBOR struct.
   */
  public EekCertChainSerializer(
      byte[] encodedRootCert, byte[] encodedIntCert,
      byte[] serializedIntSigningKey, X25519PublicKeyParameters eek)
      throws CborException, CryptoException {
    eekChain = CBORObject.NewArray();
    CBORObject rootCert = CBORObject.DecodeFromBytes(encodedRootCert);
    CBORObject intCert = CBORObject.DecodeFromBytes(encodedIntCert);
    eekChain.Add(rootCert);
    eekChain.Add(intCert);
    eekChain.Add(CryptoUtil.createCertificateEd25519(
        CryptoUtil.byteArrayToEd25519PrivateKey(serializedIntSigningKey), eek));
  }

  public EekCertChainSerializer(
      byte[] encodedRootCert,
      byte[] encodedIntCert,
      ECPrivateKey intSigningKey,
      ECPublicKey eek) throws CborException, CryptoException {
    eekChain = CBORObject.NewArray();
    CBORObject rootCert = CBORObject.DecodeFromBytes(encodedRootCert);
    CBORObject intCert = CBORObject.DecodeFromBytes(encodedIntCert);
    eekChain.Add(rootCert);
    eekChain.Add(intCert);
    try {
      eekChain.Add(CryptoUtil.createCertificate(new OneKey(null, intSigningKey),
                                                new OneKey(eek, null),
                                                AlgorithmID.ECDSA_256,
                                                AlgorithmID.ECDH_ES_HKDF_256));
    } catch (CoseException e) {
      throw new CryptoException("Failed to encode key.", e, CryptoException.MALFORMED_KEY);
    }
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
      eekRootKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
      OneKey eekIntKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
      eekIntKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
      CBORObject certArray = CBORObject.NewArray();
      certArray.Add(
          CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekRootKeyPair.PublicKey()));
      certArray.Add(CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekIntKeyPair.PublicKey()));
      certArray.Add(CryptoUtil.createCertificateEd25519(eekIntKeyPair, eek));
      return certArray.EncodeToBytes();
    } catch (CoseException e) {
      throw new CryptoException(
          "Could not generate Ed25519 Key Pair.", e, CryptoException.KEY_GENERATION_FAILURE);
    }
  }
}
