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

import com.google.remote.cbor.CborUtil;
import com.google.remote.cbor.CryptoException;
import com.google.remote.cbor.CryptoUtil;
import com.google.remote.cbor.DeviceInfo;
import com.google.remote.cbor.ProtectedDataPayload;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import COSE.OneKey;
import COSE.KeyKeys;
import COSE.Message;
import COSE.MessageTag;
import COSE.Sign1Message;
import COSE.CoseException;

import java.security.*;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/*
 * This is a convenience class for returning the results of the encrypted portion of the certificate
 * request from a device. The BCC and MAC key are both contained in this portion of the request, so
 * class provides a handy interface for storing and retrieving them from the decryption call.
 *
 * The device public key should be used to lookup and validate the device in the key database. After
 * that lookup is complete, the key should be discarded. The MAC key will be needed by whichever
 * separate server will be checking the validity of the MAC over the CSRs.
 *
 * Additionally, a CertificateRequest can contain additional device public key signatures in the
 * AdditionalDkSignatures field. This field contains some number of certificate chains of length
 * two, where the root is some OEM or SoC root of trust and the leaf is the device public key. This
 * class will also record the IDs of those additional roots of trusts, along with the root public
 * key that corresponds to them.
 */
public class ProtectedDataPayload {

    private static final int BCC_LENGTH = 2;         // The device key index and an array of certs
    private static final int BCC_DEVICE_PUBLIC_KEY_INDEX = 0;
    private static final int BCC_CHAIN_INDEX = 1;

    private static final int PROTECTED_DATA_PAYLOAD_NUM_ENTRIES = 3;
    private static final int PROTECTED_DATA_SIGNED_MAC_INDEX = 0;
    private static final int PROTECTED_DATA_BCC_INDEX = 1;
    private static final int PROTECTED_DATA_ADDITIONAL_DK_SIGNATURES = 2;

    // Signer root cert -> Device public key leaf cert
    private static final int ADDITIONAL_DK_SIGNATURE_CERT_CHAIN_LENGTH = 2;
    private static final int ADDITIONAL_DK_SIGNATURE_ROOT_INDEX = 0;
    private static final int ADDITIONAL_DK_SIGNATURE_DEVICE_KEY_INDEX = 1;

    private static final int SIGNED_DATA_AAD_NUM_ENTRIES = 2;
    private static final int SIGNED_DATA_AAD_DEVICE_INFO_INDEX = 0;
    private static final int SIGNED_DATA_AAD_CHALLENGE_INDEX = 1;

    private byte[] mDevicePublicKey;
    private byte[] mMacKey;
    private HashMap<Integer, byte[]> mSignerIdToKey;

    public ProtectedDataPayload(byte[] devicePublicKey, byte[] macKey) {
        mDevicePublicKey = devicePublicKey;
        mMacKey = macKey;
        mSignerIdToKey = new HashMap<Integer, byte[]>();
    }

    /*
     * Construct a ProtectedDataPayload from the CBOR blob corresponding to this structured data.
     */
    public ProtectedDataPayload(byte[] cborPayload,
                                byte[] challenge,
                                byte[] deviceInfo,
                                AsymmetricCipherKeyPair eek) throws CborException, CryptoException {
        mSignerIdToKey = new HashMap<Integer, byte[]>();
        decryptAndValidateProtectedData(cborPayload, challenge, deviceInfo, eek);
    }

    /*
     * Return the ID of the public portion of the EEK that was used to encrypt this payload.
     */
    public static byte[] getEekId(byte[] cborPayload) throws CborException {
        return CborUtil.extractEekId(cborPayload);
    }

    /*
     * Add an entry to the map of Signer IDs to signer keys.
     */
    public void addSignerAndKey(int signerId, byte[] key) {
        mSignerIdToKey.put(signerId, key);
    }

    /*
     * Get the device public key, used by the server to verify that the request is coming from a
     * real Android device.
     */
    public byte[] getDevicePublicKey() {
        return mDevicePublicKey;
    }

    /*
     * Get the MAC key, used to verify the MAC on the MacedKeysToSign field.
     */
    public byte[] getMacKey() {
        return mMacKey;
    }

    /*
     * Provide the entries in the map of signer IDs to signer keys as an iterable set.
     *
     * Returns: Set<Map.Entry<Integer, byte[]>> The entries in the signer map as an iterable set
     */
    public Set<Map.Entry<Integer, byte[]>> getSignerIdsToKeys() {
        return mSignerIdToKey.entrySet();
    }

    /*
     * Get the signer IDs.
     */
    public Set<Integer> getSignerIds() {
        return mSignerIdToKey.keySet();
    }

    /*
     * Get the signer public keys
     */
    public Collection<byte[]> getSignerKeys() {
        return mSignerIdToKey.values();
    }

    /*
     * Verifies the provided CBORObject as a proper certificate chain and then extracts and returns
     * the device public key. The CBOR blob is described by the following CDDL:
     *
     * @param bcc the boot certificate chain which contains DK_pub
     *
     * @return OneKey DK_pub in a COSE key object
     */
    private OneKey verifyBccAndExtractDevicePublicKey(CBORObject bcc) throws CborException,
                                                                             CryptoException {
        if (bcc.getType() != CBORType.Array) {
            throw new CborException("BCC Type Wrong",
                                    CBORType.Array,
                                    bcc.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (bcc.size() != BCC_LENGTH) {
            throw new CborException("BCC incorrect length ",
                                    BCC_LENGTH,
                                    bcc.size(),
                                    CborException.INCORRECT_LENGTH);
        }
        if (bcc.get(BCC_DEVICE_PUBLIC_KEY_INDEX).getType() != CBORType.Integer) {
            throw new CborException("First entry in the BCC has the wrong type",
                                    CBORType.Integer,
                                    bcc.get(BCC_DEVICE_PUBLIC_KEY_INDEX).getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (bcc.get(BCC_CHAIN_INDEX).getType() != CBORType.Array) {
            throw new CborException("Second entry in the BCC has the wrong type",
                                    CBORType.Array,
                                    bcc.get(BCC_CHAIN_INDEX).getType(),
                                    CborException.TYPE_MISMATCH);
        }
        int devicePublicKeyIndex =
            bcc.get(BCC_DEVICE_PUBLIC_KEY_INDEX).ToObject(Integer.class);
        CBORObject bccChain = bcc.get(BCC_CHAIN_INDEX);

        // verify the certificate chain
        if (!CryptoUtil.validateCertificateChain(bccChain)) {
            throw new CryptoException("Failed to verify certificate chain",
                CryptoException.VERIFICATION_FAILURE);
        }

        // Extract and return the public key
        try {
            Sign1Message devicePublicKeyCert = (Sign1Message) Message.DecodeFromBytes(
                bccChain.get(devicePublicKeyIndex).EncodeToBytes(), MessageTag.Sign1);
            CBORObject devicePublicKeyCertContent =
                CBORObject.DecodeFromBytes(devicePublicKeyCert.GetContent());
            return new OneKey(devicePublicKeyCertContent);
        } catch (CoseException e) {
            throw new CborException(
                "Failed to decode the certificate containing the device public key",
                e, CborException.DESERIALIZATION_ERROR);
        }
    }

    private void extractAdditionalDkSignatures(CBORObject additionalDkSignatures,
                                               OneKey devicePublicKey)
            throws CborException, CryptoException {
        if (additionalDkSignatures.getType() != CBORType.Map) {
            throw new CborException(
                "AdditionalDKSignatures in ProtectedDataPayload has the wrong type",
                CBORType.Map,
                additionalDkSignatures.getType(),
                CborException.TYPE_MISMATCH);
        }
        if (additionalDkSignatures.size() > 0) {
            for (CBORObject key : additionalDkSignatures.getKeys()) {
                CBORObject certChain = additionalDkSignatures.get(key);
                if (certChain.getType() != CBORType.Array) {
                    throw new CborException("A DKCertChain is not properly encoded",
                        CBORType.Array,
                        certChain.getType(),
                        CborException.TYPE_MISMATCH);
                }
                if (certChain.size() != ADDITIONAL_DK_SIGNATURE_CERT_CHAIN_LENGTH) {
                    throw new CborException("A DKCertChain has the wrong number of certs.",
                                            ADDITIONAL_DK_SIGNATURE_CERT_CHAIN_LENGTH,
                                            certChain.size(),
                                            CborException.INCORRECT_LENGTH);
                }

                // Verify the root is self signed
                if (!CryptoUtil.verifyCert(certChain.get(ADDITIONAL_DK_SIGNATURE_ROOT_INDEX),
                                           certChain.get(ADDITIONAL_DK_SIGNATURE_ROOT_INDEX))) {
                    throw new CryptoException("DKCertChain root certificate is not self signed",
                                              CryptoException.VERIFICATION_FAILURE);
                }
                if (!CryptoUtil.verifyCert(certChain.get(ADDITIONAL_DK_SIGNATURE_ROOT_INDEX),
                                           certChain.get(ADDITIONAL_DK_SIGNATURE_DEVICE_KEY_INDEX),
                                           devicePublicKey)) {
                    throw new CryptoException("DKCertChain leaf is not signed by the root",
                                              CryptoException.VERIFICATION_FAILURE);
                }
                EdDSAPublicKey oemRoot =
                    (EdDSAPublicKey) CryptoUtil.getEd25519PublicKeyFromCert(
                        certChain.get(ADDITIONAL_DK_SIGNATURE_ROOT_INDEX));
                this.addSignerAndKey(key.AsInt32Value(), oemRoot.getAbyte());
            }
        }
    }

    /*
     * This function takes the provided eekPrivateKey and uses it to decrypt the CBOR blob which
     * contains the boot certificate chain, MAC key, and device public key.
     *
     * @param cborProtectedData the CBOR encoded byte array representing a ProtectedData object
     *
     * @param challenge the challenge that was retrieved from the CertificateRequest blob. Part of
     *                  the AAD
     *
     * @param deviceInfo the CBOR encoded byte array representing the DeviceInfo blob. Part of the
     *                   AAD
     *
     * @param eek The server X25519 key pair that will be used to decrypt the ProtectedData
     *
     * @return ProtectedDataPayload object that contains the MAC key and device public key
     */
    private void decryptAndValidateProtectedData(byte[] cborProtectedData,
                                                         byte[] challenge,
                                                         byte[] deviceInfo,
                                                         AsymmetricCipherKeyPair eek)
                                                         throws CborException, CryptoException {
        CBORObject protectedDataPayload = CborUtil.decodeEncryptMessage(cborProtectedData, eek);
        if (protectedDataPayload == null) {
            throw new CborException(
                "Failed to deserialize protected data payload from decrypted data",
                CborException.DESERIALIZATION_ERROR);
        }

        // Validate BCC chain, retrieve the device public key, and validate the MAC signature
        if (protectedDataPayload.size() != PROTECTED_DATA_PAYLOAD_NUM_ENTRIES) {
            throw new CborException("Protected data payload incorrect length:",
                                    PROTECTED_DATA_PAYLOAD_NUM_ENTRIES,
                                    protectedDataPayload.size(),
                                    CborException.INCORRECT_LENGTH);
        }

        Sign1Message signedMac;
        try {
            byte[] signedMacEncoded =
                protectedDataPayload.get(PROTECTED_DATA_SIGNED_MAC_INDEX).EncodeToBytes();
            signedMac = (Sign1Message) Message.DecodeFromBytes(signedMacEncoded, MessageTag.Sign1);
        } catch (CoseException e) {
            throw new CborException("Signed MAC decoding failure",
                                    e, CborException.DESERIALIZATION_ERROR);
        }

        // Build the Associated Authenticated Data
        CBORObject arr = CBORObject.NewArray();
        arr.Add(CBORObject.DecodeFromBytes(deviceInfo));
        arr.Add(CBORObject.FromObject(challenge));
        signedMac.setExternal(arr.EncodeToBytes());

        CBORObject bccChain = protectedDataPayload.get(PROTECTED_DATA_BCC_INDEX);
        OneKey devicePublicKey = verifyBccAndExtractDevicePublicKey(bccChain);
        try {
            if (!signedMac.validate(devicePublicKey)) {
                throw new CryptoException("Can't validate signature on MAC key",
                    CryptoException.MAC_WITH_AAD_SIGNATURE_VERIFICATION_FAILED);
            }
        } catch (CoseException e) {
            throw new CryptoException("Can't validate signature on MAC key", e,
                CryptoException.MAC_WITH_AAD_SIGNATURE_VERIFICATION_FAILED);
        }

        CBORObject additionalDkSignatures =
            protectedDataPayload.get(PROTECTED_DATA_ADDITIONAL_DK_SIGNATURES);
        mDevicePublicKey = devicePublicKey.get(KeyKeys.OKP_X).ToObject(byte[].class);
        mMacKey = CBORObject.DecodeFromBytes(signedMac.GetContent()).ToObject(byte[].class);
        // Additional signatures are optional; they are only required in a solution where the
        // signer cannot upload public keys from the factory floor due to various restrictions
        // or obstacles they may deal with.
        extractAdditionalDkSignatures(additionalDkSignatures, devicePublicKey);
    }
}
