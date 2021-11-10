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
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * This class implements some of the COSE structure serialization / deserialization code that is not
 * yet fully implemented in the COSE library currently used in this project.
 */
public class CborUtil {

  private static final int COSE_ENCRYPT_LENGTH = 4;
  private static final int COSE_ENCRYPT_PROTECTED_HEADERS_INDEX = 0;
  private static final int COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX = 1;
  private static final int COSE_ENCRYPT_CIPHERTEXT_INDEX = 2;
  private static final int COSE_ENCRYPT_RECIPIENTS_INDEX = 3;

  private static final int COSE_RECIPIENT_LENGTH = 3; // Can be 4, but no nested recipients
  private static final int COSE_RECIPIENT_PROTECTED_HEADERS_INDEX = 0;
  private static final int COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX = 1;
  private static final int COSE_RECIPIENT_CIPHERTEXT_INDEX = 2;

  private CborUtil() {}

  /**
   * Encodes and encrypts a COSE_Encrypt message, provided a plaintext payload and corresponding
   * keys.
   *
   * @param plaintext the plaintext payload to be encrypted.
   * @param ephemeralKeyPair the ephemeral public key to be used in the X25519 operation.
   * @param eek the server key pair to be used in the X25519 operation.
   * @return a COSE_Encrypt message encoded in a CBORObject
   */
  public static CBORObject encodeEncryptMessage(
      byte[] plaintext, AsymmetricCipherKeyPair ephemeralKeyPair, X25519PublicKeyParameters eek)
      throws CborException, CryptoException {
    byte[] sendKey = CryptoUtil.deriveSharedKeySend(ephemeralKeyPair, eek);
    CBORObject ephemeralPubKey =
        CryptoUtil.x25519ToOneKey(
            (X25519PublicKeyParameters) ephemeralKeyPair.getPublic()).AsCBOR();
    byte[] keyId = CryptoUtil.digestX25519(eek);
    return encodeEncryptMessageInternal(plaintext, sendKey, ephemeralPubKey, keyId);
  }

  public static CBORObject encodeEncryptMessage(
      byte[] plaintext, KeyPair ephemeralKeyPair, ECPublicKey eek)
      throws CborException, CryptoException {
    try {
      byte[] sendKey = CryptoUtil.deriveSharedKeySend(ephemeralKeyPair, eek);
      CBORObject ephemeralPubKey = new OneKey(ephemeralKeyPair.getPublic(), null).AsCBOR();
      ephemeralPubKey.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
      byte[] keyId = CryptoUtil.digestP256(eek);
      return encodeEncryptMessageInternal(plaintext, sendKey, ephemeralPubKey, keyId);
    } catch (CoseException e) {
      throw new CryptoException(
          "Couldn't convert ECPublicKey to OneKey",  e, CryptoException.MALFORMED_KEY);
    }
  }

  private static CBORObject encodeEncryptMessageInternal(
      byte[] plaintext, byte[] aesKey, CBORObject ephemeralPubKey, byte[] keyId)
      throws CborException, CryptoException {
    SecureRandom rand = new SecureRandom();
    byte[] iv = new byte[16];
    rand.nextBytes(iv);

    // A COSE_Encrypt message is a CBOR array with 4 entries
    CBORObject encMsg = CBORObject.NewArray();
    CBORObject protectedHeaders = CBORObject.NewMap();
    protectedHeaders.Add(HeaderKeys.Algorithm.AsCBOR(), AlgorithmID.AES_GCM_256.AsCBOR());
    byte[] aad = buildEncStructure(protectedHeaders.EncodeToBytes(), null);

    CBORObject unprotectedHeaders = CBORObject.NewMap();
    unprotectedHeaders.Add(HeaderKeys.IV.AsCBOR(), CBORObject.FromObject(iv));

    CBORObject content = CBORObject.FromObject(CryptoUtil.encrypt(plaintext, aad, aesKey, iv));

    CBORObject recipients = CBORObject.NewArray();
    // Build a COSE_Recipient object containing the public keys needed for ECDH
    CBORObject recipient = CBORObject.NewArray();
    CBORObject protectedHeadersRecip = CBORObject.NewMap();
    protectedHeadersRecip.Add(HeaderKeys.Algorithm.AsCBOR(), AlgorithmID.ECDH_ES_HKDF_256.AsCBOR());

    CBORObject unprotectedHeadersRecip = CBORObject.NewMap();
    // This adds the kid too, which is not specified for this Key in the spec
    unprotectedHeadersRecip.Add(
        HeaderKeys.ECDH_EPK.AsCBOR(),
        ephemeralPubKey);
    unprotectedHeadersRecip.Add(HeaderKeys.KID.AsCBOR(), keyId);
    recipient.Add(protectedHeadersRecip.EncodeToBytes());
    recipient.Add(unprotectedHeadersRecip);
    recipient.Add(CBORObject.Null); // ciphertext field, nil if no key

    encMsg.Add(protectedHeaders.EncodeToBytes());
    encMsg.Add(unprotectedHeaders);
    encMsg.Add(content);
    recipients.Add(recipient);
    encMsg.Add(recipients);
    return encMsg;
  }

  private static CBORObject getRecipient(CBORObject recipients) throws CborException {
    checkArray(recipients, 1 /* expectedLength */, "Recipient list of ProtectedData");
    CBORObject recipient = recipients.get(0);
    checkArray(recipient, COSE_RECIPIENT_LENGTH, "Recipient of ProtectedData");
    return recipient;
  }

  public static byte[] extractEekId(byte[] cborProtectedData) throws CborException {
    CBORObject unprotectedHeadersRecip = getRecipientUnprotectedHeaders(cborProtectedData);
    return unprotectedHeadersRecip.get(HeaderKeys.KID.AsCBOR()).GetByteString();
  }

  public static int extractEcdhCurve(byte[] cborProtectedData) throws CborException {
    CBORObject unprotectedHeadersRecip = getRecipientUnprotectedHeaders(cborProtectedData);
    CBORObject ecdhEpk = unprotectedHeadersRecip.get(HeaderKeys.ECDH_EPK.AsCBOR());
    checkMap(ecdhEpk, "ECDH ephemeral public key");
    CBORObject curve = ecdhEpk.get(KeyKeys.EC2_Curve.AsCBOR());
    if (curve == null || curve.getType() != CBORType.Integer) {
      throw new CborException(
          "Curve on the ECDH ephemeral public key is null or has the wrong type",
          CborException.TYPE_MISMATCH);
    }
    return curve.AsInt32();
  }

  private static CBORObject getRecipientUnprotectedHeaders(byte[] encMsgBstr) throws CborException {
    CBORObject encMsg = CBORObject.DecodeFromBytes(encMsgBstr);
    checkArray(encMsg, COSE_ENCRYPT_LENGTH, "ProtectedData");
    CBORObject recipient = getRecipient(encMsg.get(COSE_ENCRYPT_RECIPIENTS_INDEX));
    return recipient.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX);
  }

  /**
   * Interprets {@code cborProtectedData} as a COSE_Encrypt message with a single recipient. The
   * method uses the provided {@code eek} to decrypt the content field of the message after
   * retrieving the ephemeral public key that KeyMint on the device in question generated in
   * order to encrypt the bundle. The content included should be a ProtectedDataPayload array
   * containing a signed mac key, a boot certificate chain, and any additional device public key
   * signatures from the OEM.
   *
   * @param cborProtectedData the COSE_Encrypt message representing ProtectedData
   *
   * @param eek The server's endpoint encryption key to be used in ECDH to derive the decryption
   *            key
   *
   * @return CBORObject the content field in the cborProtectedData object as a CBOR array
   */
  public static CBORObject decodeEncryptMessage(
      byte[] cborProtectedData, AsymmetricCipherKeyPair eek) throws CborException, CryptoException {
    CBORObject encMsg = CBORObject.DecodeFromBytes(cborProtectedData);
    checkArray(encMsg, COSE_ENCRYPT_LENGTH, "ProtectedData");
    byte[] serializedProtectedHeaders =
        encMsg.get(COSE_ENCRYPT_PROTECTED_HEADERS_INDEX).GetByteString();
    byte[] aad = buildEncStructure(serializedProtectedHeaders, null /* externalAad */);
    CBORObject protectedHeaders = CBORObject.DecodeFromBytes(serializedProtectedHeaders);
    CBORObject unprotectedHeaders = encMsg.get(COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX);
    byte[] content = encMsg.get(COSE_ENCRYPT_CIPHERTEXT_INDEX).GetByteString();
    CBORObject recipient = getRecipient(encMsg.get(COSE_ENCRYPT_RECIPIENTS_INDEX));
    CBORObject unprotectedHeadersRecip = recipient.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX);
    CBORObject ephemeralPublicKeyCbor = unprotectedHeadersRecip.get(HeaderKeys.ECDH_EPK.AsCBOR());
    byte[] ephemeralPublicKey = ephemeralPublicKeyCbor.get(KeyKeys.OKP_X.AsCBOR()).GetByteString();
    byte[] derivedKey =
        CryptoUtil.deriveSharedKeyReceive(
            eek, CryptoUtil.byteArrayToX25519PublicKey(ephemeralPublicKey));
    byte[] iv = unprotectedHeaders.get(HeaderKeys.IV.AsCBOR()).GetByteString();
    return CBORObject.DecodeFromBytes(CryptoUtil.decrypt(content, aad, derivedKey, iv));
  }

  public static CBORObject decodeEncryptMessage(
      byte[] cborProtectedData, KeyPair eek) throws CborException, CryptoException {
    CBORObject encMsg = CBORObject.DecodeFromBytes(cborProtectedData);
    checkArray(encMsg, COSE_ENCRYPT_LENGTH, "ProtectedData");
    byte[] serializedProtectedHeaders =
        encMsg.get(COSE_ENCRYPT_PROTECTED_HEADERS_INDEX).GetByteString();
    byte[] aad = buildEncStructure(serializedProtectedHeaders, null /* externalAad */);
    CBORObject protectedHeaders = CBORObject.DecodeFromBytes(serializedProtectedHeaders);
    CBORObject unprotectedHeaders = encMsg.get(COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX);
    byte[] content = encMsg.get(COSE_ENCRYPT_CIPHERTEXT_INDEX).GetByteString();
    CBORObject recipient = getRecipient(encMsg.get(COSE_ENCRYPT_RECIPIENTS_INDEX));
    CBORObject unprotectedHeadersRecip = recipient.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX);
    CBORObject ephemeralPublicKeyCbor = unprotectedHeadersRecip.get(HeaderKeys.ECDH_EPK.AsCBOR());
    try {
      ECPublicKey ephemeralPublicKey =
          (ECPublicKey) CryptoUtil.oneKeyToP256PublicKey(new OneKey(ephemeralPublicKeyCbor));
      byte[] derivedKey = CryptoUtil.deriveSharedKeyReceive(eek, ephemeralPublicKey);
      byte[] iv = unprotectedHeaders.get(HeaderKeys.IV.AsCBOR()).GetByteString();
      return CBORObject.DecodeFromBytes(CryptoUtil.decrypt(content, aad, derivedKey, iv));
    } catch (CoseException e) {
      throw new CborException("Failed to decode ephemeral public key in recipients.", e,
          CborException.DESERIALIZATION_ERROR);
    }
  }

  /**
   * Builds the COSE Enc_structure which becomes the AAD for encryption/decryption operations.
   * In this case, the context indicates this is for a COSE_Encrypt message only, but it could
   * be trivially modified to accept an enum for context selection in the future if the need
   * arises.
   *
   * Enc_structure = [
   *     context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
   *         "Mac_Recipient" / "Rec_Recipient",
   *     protected : empty_or_serialized_map,
   *     external_aad : bstr
   * ]
   */
  private static byte[] buildEncStructure(byte[] emptyOrSerializedMap, byte[] externalAad) {
    CBORObject encStructure = CBORObject.NewArray();
    encStructure.Add("Encrypt");
    encStructure.Add(emptyOrSerializedMap);
    // Absent external_aad should be represented as a bstr of length 0, not nil.
    if (externalAad == null) {
      externalAad = new byte[0];
    }
    encStructure.Add(externalAad);
    return encStructure.EncodeToBytes();
  }

  public static CBORObject buildParty(String identity, byte[] pubKey) {
    CBORObject party = CBORObject.NewArray();
    party.Add(CBORObject.FromObject(identity.getBytes(StandardCharsets.UTF_8)));
    party.Add(CBORObject.FromObject(new byte[0] /* nonce */));
    party.Add(CBORObject.FromObject(pubKey));
    return party;
  }

  public static byte[] buildKdfContext(CBORObject partyU, CBORObject partyV) {
    CBORObject context = CBORObject.NewArray();
    context.Add(AlgorithmID.AES_GCM_256.AsCBOR());
    context.Add(partyU);
    context.Add(partyV);
    CBORObject suppPubInfo = CBORObject.NewArray();
    suppPubInfo.Add(CBORObject.FromObject(256 /* Key Length */));
    suppPubInfo.Add(CBORObject.FromObject(new byte[0] /* Protected Headers */));
    context.Add(suppPubInfo);
    return context.EncodeToBytes();
  }

  private static void checkArr(CBORObject arr, String semanticName) throws CborException {
    if (arr == null) {
      throwNullException(semanticName);
    }
    if (arr.getType() != CBORType.Array) {
      throw new CborException(
          semanticName + " has the wrong type.",
          CBORType.Array,
          arr.getType(),
          CborException.TYPE_MISMATCH);
    }
  }

  public static void checkArray(CBORObject arr, int expectedLength, String semanticName)
      throws CborException {
    checkArr(arr, semanticName);
    if (arr.size() != expectedLength) {
      throw new CborException(
          semanticName + " has the wrong length.",
          expectedLength,
          arr.size(),
          CborException.INCORRECT_LENGTH);
    }
  }

  public static void checkArrayMinLength(CBORObject arr, int minLength, String semanticName)
      throws CborException {
    checkArr(arr, semanticName);
    if (arr.size() < minLength) {
      throw new CborException(
          semanticName + " doesn't match the minimum length.",
          minLength,
          arr.size(),
          CborException.INCORRECT_LENGTH);
    }
  }

  public static void checkMap(CBORObject map, String semanticName) throws CborException {
    if (map == null) {
      throwNullException(semanticName);
    }
    if (map.getType() != CBORType.Map) {
      throw new CborException(
          semanticName + " has the wrong type",
          CBORType.Map,
          map.getType(),
          CborException.TYPE_MISMATCH);
    }
  }

  public static byte[] getSafeBstr(CBORObject bstr, int expectedLength, String semanticName)
      throws CborException {
    if (bstr == null) {
      throwNullException(semanticName);
    }
    byte[] ret = getSafeBstr(bstr, semanticName);
    if (ret.length != expectedLength) {
      throw new CborException(
          semanticName + " has the wrong length.",
          expectedLength,
          ret.length,
          CborException.INCORRECT_LENGTH);
    }
    return ret;
  }

  public static byte[] getSafeBstr(CBORObject bstr, String semanticName) throws CborException {
    if (bstr == null) {
      throwNullException(semanticName);
    }
    if (bstr.getType() != CBORType.ByteString) {
      throw new CborException(
          semanticName + " has the wrong type",
          CBORType.ByteString,
          bstr.getType(),
          CborException.TYPE_MISMATCH);
    }
    return bstr.GetByteString();
  }

  private static void throwNullException(String semanticName) throws CborException {
    throw new CborException(
          semanticName + " is null.",
          CborException.DESERIALIZATION_ERROR);
  }
}
