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

import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * The primary purpose of this class is to deserialize EEK certificate requests so that the
 * functionality of EekCertChainSerializer can be tested. The remote provisioning server should have
 * no actual use for this class.
 */
public class EekCertChainDeserializer {

  private final int alg;

  private final ArrayList<byte[]> signingKeyChain;
  private final ArrayList<ECPublicKey> signingKeyChainP256;

  private X25519PublicKeyParameters eek;
  private ECPublicKey eekP256;

  public EekCertChainDeserializer(byte[] cborEncodedEekCertChain)
      throws CborException, CryptoException {
    try {
      signingKeyChain = new ArrayList<>();
      signingKeyChainP256 = new ArrayList<>();
      CBORObject eekChain = CBORObject.DecodeFromBytes(cborEncodedEekCertChain);
      CborUtil.checkArrayMinLength(eekChain, 2, "EekChain");
      alg = getSigningAlg(eekChain.get(0));
      for (int i = 1; i < eekChain.size(); i++) {
        if (!CryptoUtil.verifyCert(eekChain.get(i - 1), eekChain.get(i))) {
          throw new CryptoException(
              "Certificate " + (i - 1) + " verification of certificate " + i + " fails.",
              CryptoException.VERIFICATION_FAILURE);
        }
        if (alg == -7) {
          OneKey pubKey =
              new OneKey(CBORObject.DecodeFromBytes(eekChain.get(i - 1).get(2).GetByteString()));
          signingKeyChainP256.add((ECPublicKey) pubKey.AsPublicKey());
          if (i == eekChain.size() - 1) {
            pubKey = new OneKey(CBORObject.DecodeFromBytes(eekChain.get(i).get(2).GetByteString()));
            eekP256 = (ECPublicKey) pubKey.AsPublicKey();
          }
        } else {
          signingKeyChain.add(CryptoUtil.getEd25519PublicKeyFromCert(eekChain.get(i - 1)));
          if (i == eekChain.size() - 1) {
            eek = CryptoUtil.getX25519PublicKeyFromCert(eekChain.get(i));
          }
        }
      }
    } catch (CoseException e) {
      throw new CborException("Failed to deserialize SignedEek key payload",
          e, CborException.DESERIALIZATION_ERROR);
    }
  }

  private static int getSigningAlg(CBORObject certObj) throws CborException {
    CborUtil.checkArray(certObj, 4 /* expectedLength */, "SignedEek");
    byte[] protectedHeaders = CborUtil.getSafeBstr(certObj.get(0), "SignedEek[0]");
    CBORObject protMap = CBORObject.DecodeFromBytes(protectedHeaders);
    CborUtil.checkMap(protMap, "Decoded SignedEek[0]");
    CBORObject algObj = protMap.get(1);
    if (algObj.isNumber()) {
      int alg = algObj.AsInt32();
      if (alg != -7 && alg != -8) {
        throw new CborException("Decoded SignedEek[0] entry for Algorithm is not valid: " + alg,
            CborException.DESERIALIZATION_ERROR);
      }
      return alg;
    } else {
      throw new CborException("Decoded SignedEek[0] entry for Algorithm is not a number.",
          CborException.DESERIALIZATION_ERROR);
    }
  }

  public int getSignatureAlgorithm() {
    return alg;
  }

  public ECPublicKey getEekP256() {
    return eekP256;
  }

  public List<ECPublicKey> getSigningKeyChainP256() {
    return signingKeyChainP256;
  }

  public X25519PublicKeyParameters getEek() {
    return eek;
  }

  public ArrayList<byte[]> getSigningKeyChain() {
    return signingKeyChain;
  }
}
