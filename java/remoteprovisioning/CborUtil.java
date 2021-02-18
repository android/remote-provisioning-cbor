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

import remoteprovisioning.CryptoException;
import remoteprovisioning.CryptoUtil;
import remoteprovisioning.ProtectedDataPayload;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import COSE.AlgorithmID;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.Message;

import java.security.*;

/*
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

    public static CBORObject encodeEncryptMessage(byte[] plaintext, 
                                                  AsymmetricCipherKeyPair ephemeralKeyPair,
                                                  X25519PublicKeyParameters eek)
                                                  throws CborException, CryptoException {
        // Generate an IV and derive the sender key
        SecureRandom rand = new SecureRandom();
        byte[] iv = new byte[16];
        rand.nextBytes(iv);
        byte[] sendKey = CryptoUtil.deriveSharedKeySend(ephemeralKeyPair, eek);

        // A COSE_Encrypt message is a CBOR array with 4 entries
        CBORObject encMsg = CBORObject.NewArray();
        CBORObject protectedHeaders = CBORObject.NewMap();
        protectedHeaders.Add(HeaderKeys.Algorithm.AsCBOR(), AlgorithmID.AES_GCM_256.AsCBOR());
        byte[] aad = buildEncStructure(protectedHeaders.EncodeToBytes(), null);

        CBORObject unprotectedHeaders = CBORObject.NewMap();
        unprotectedHeaders.Add(HeaderKeys.IV.AsCBOR(), CBORObject.FromObject(iv));

        CBORObject content = CBORObject.FromObject(CryptoUtil.encrypt(plaintext, aad, sendKey, iv));

        CBORObject recipients = CBORObject.NewArray();
        // Build a COSE_Recipient object containing the public keys needed for ECDH
        CBORObject recipient = CBORObject.NewArray();
        CBORObject protectedHeadersRecip = CBORObject.NewMap();
        protectedHeadersRecip.Add(HeaderKeys.Algorithm.AsCBOR(),
            AlgorithmID.ECDH_ES_HKDF_256.AsCBOR());

        CBORObject unprotectedHeadersRecip = CBORObject.NewMap();
        // This adds the kid too, which is not specified for this Key in the spec
        unprotectedHeadersRecip.Add(
            HeaderKeys.ECDH_EPK.AsCBOR(),
            CryptoUtil.cborEncodeX25519PubKey((X25519PublicKeyParameters) ephemeralKeyPair.getPublic()));
        unprotectedHeadersRecip.Add(HeaderKeys.KID.AsCBOR(), CryptoUtil.digestX25519(eek));
        recipient.Add(protectedHeadersRecip.EncodeToBytes());
        recipient.Add(unprotectedHeadersRecip);
        recipient.Add(CBORObject.Null);  // ciphertext field, nil if no key

        encMsg.Add(protectedHeaders.EncodeToBytes());
        encMsg.Add(unprotectedHeaders);
        encMsg.Add(content);
        recipients.Add(recipient);
        encMsg.Add(recipients);
        return encMsg;
    }

    private static CBORObject getRecipient(CBORObject recipients) throws CborException {
        if (recipients.getType() != CBORType.Array) {
            throw new CborException("Recipient list of ProtectedData has the wrong type",
                                    CBORType.Array,
                                    recipients.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (recipients.size() != 1) {
            throw new CborException(
                "Recipient list of ProtectedData has the wrong number of recipients",
                1,
                recipients.size(),
                CborException.INCORRECT_LENGTH);
        }
        CBORObject recipient = recipients.get(0);
        if (recipient.getType() != CBORType.Array) {
            throw new CborException("Recipient of ProtectedData has the wrong type",
                                    CBORType.Array,
                                    recipient.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (recipient.size() != COSE_RECIPIENT_LENGTH) {
            throw new CborException("Recipient of ProtectedData has the wrong length",
                                    COSE_RECIPIENT_LENGTH,
                                    recipient.size(),
                                    CborException.INCORRECT_LENGTH);
        }
        return recipient;
    }

    public static byte[] extractEekId(byte[] cborProtectedData) throws CborException {
        CBORObject encMsg = CBORObject.DecodeFromBytes(cborProtectedData);
        if (encMsg.getType() != CBORType.Array) {
            throw new CborException("ProtectedData has the wrong type",
                                    CBORType.Array,
                                    encMsg.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (encMsg.size() != COSE_ENCRYPT_LENGTH) {
            throw new CborException("ProtectedData has the wrong length",
                                    COSE_ENCRYPT_LENGTH,
                                    encMsg.size(),
                                    CborException.INCORRECT_LENGTH);
        }
        CBORObject recipient = getRecipient(encMsg.get(COSE_ENCRYPT_RECIPIENTS_INDEX));
        CBORObject unprotectedHeadersRecip =
            recipient.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX);
        return unprotectedHeadersRecip.get(HeaderKeys.KID.AsCBOR()).GetByteString();
    }

    /*
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
    public static CBORObject decodeEncryptMessage(byte[] cborProtectedData,
                                                  AsymmetricCipherKeyPair eek)
            throws CborException, CryptoException {
        CBORObject encMsg = CBORObject.DecodeFromBytes(cborProtectedData);
        if (encMsg.getType() != CBORType.Array) {
            throw new CborException("ProtectedData has the wrong type",
                                    CBORType.Array,
                                    encMsg.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (encMsg.size() != COSE_ENCRYPT_LENGTH) {
            throw new CborException("ProtectedData has the wrong length",
                                    COSE_ENCRYPT_LENGTH,
                                    encMsg.size(),
                                    CborException.INCORRECT_LENGTH);
        }
        byte[] serializedProtectedHeaders =
                encMsg.get(COSE_ENCRYPT_PROTECTED_HEADERS_INDEX).GetByteString();
        byte[] aad = buildEncStructure(serializedProtectedHeaders, null /* externalAad */);
        CBORObject protectedHeaders = CBORObject.DecodeFromBytes(serializedProtectedHeaders);
        CBORObject unprotectedHeaders = encMsg.get(COSE_ENCRYPT_UNPROTECTED_HEADERS_INDEX);
        byte[] content = encMsg.get(COSE_ENCRYPT_CIPHERTEXT_INDEX).GetByteString();
        CBORObject recipient = getRecipient(encMsg.get(COSE_ENCRYPT_RECIPIENTS_INDEX));
        CBORObject unprotectedHeadersRecip =
            recipient.get(COSE_RECIPIENT_UNPROTECTED_HEADERS_INDEX);
        CBORObject ephemeralPublicKeyCbor =
            CBORObject.DecodeFromBytes(
                unprotectedHeadersRecip.get(HeaderKeys.ECDH_EPK.AsCBOR())
                .GetByteString());
        byte[] ephemeralPublicKey =
            ephemeralPublicKeyCbor.get(KeyKeys.OKP_X.AsCBOR()).GetByteString();
        byte[] derivedKey =
            CryptoUtil.deriveSharedKeyReceive(
                eek, CryptoUtil.byteArrayToX25519PublicKey(ephemeralPublicKey));
        byte[] iv = unprotectedHeaders.get(HeaderKeys.IV.AsCBOR()).GetByteString();
        return CBORObject.DecodeFromBytes(CryptoUtil.decrypt(content, aad, derivedKey, iv));
    }

    /*
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
        party.Add(CBORObject.FromObject(identity));
        party.Add(CBORObject.FromObject(new byte[0] /* nonce */));
        party.Add(CBORObject.FromObject(pubKey));
        return party;
    }

    public static byte[] buildKdfContext(CBORObject partyU, CBORObject partyV) {
        CBORObject context = CBORObject.NewArray();
        context.Add(AlgorithmID.AES_GCM_128.AsCBOR());
        context.Add(partyU);
        context.Add(partyV);
        CBORObject suppPubInfo = CBORObject.NewArray();
        suppPubInfo.Add(CBORObject.FromObject(128 /* Key Length */));
        suppPubInfo.Add(CBORObject.FromObject(new byte[0] /* Protected Headers */));
        context.Add(suppPubInfo);
        return context.EncodeToBytes();
    }
}
