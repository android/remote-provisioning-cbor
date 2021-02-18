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

import remoteprovisioning.CborUtil;
import remoteprovisioning.CryptoException;
import remoteprovisioning.CryptoUtil;
import remoteprovisioning.DeviceInfo;
import remoteprovisioning.ProtectedDataPayload;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

import COSE.MAC0Message;
import COSE.OneKey;
import COSE.KeyKeys;
import COSE.Message;
import COSE.MessageTag;
import COSE.Sign1Message;
import COSE.CoseException;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/*
 * CertificateRequestDeserializer is used by any server that receives CertificateRequest CBOR blobs
 * from an Android device. This class handles verifying all data on the request as well as
 * retrieving relevant info from the request in a privacy preserving way.
 *
 * Example Usage:
 * byte[] deviceCertificateRequest = ... // CBOR blob received from device
 * KeyPair serverKeyPair = ... // The public/private keypair of the EEK
 * CertificateRequestDeserializer certReq =
 *     new CertificateRequestDeserializer(deviceCertificateRequest);
 * byte[] protectedData = certReq.getProtectedData();
 * byte[] challenge = certReq.getChallenge();
 * byte[] deviceInfo = certReq.getDeviceInfoEncoded();
 * byte[] publicKeys = certReq.getMacedKeysToSign();
 *
 * // payload contains the device public key and MAC key. It should be decrypted by a separate
 * // from the one that receives the initial CBOR blob, so that no server can see both the requested
 * // public keys and the device unique public key.
 * ProtectedDataPayload payload =
 *          CertificateRequestDeserializer.decryptAndValidateProtectedData(
 *              protectedData,
 *              challenge,
 *              deviceInfo,
 *              serverKeyPair);
 *
 * // publicKeys are the attestation public keys corresponding to the private keys that the device
 * // generated. These should have their MAC checked and be signed by a separate server from the one
 * // that retrieves the MAC key and device unique public key, so that no server can see both the
 * // requested public keys and the device unique public keys.
 * ArrayList<byte[]> publicKeys =
 *          CertificateRequestDeserializer.retrievePublicKeys(publicKeys,
 *                                                            payload.getMacKey());
 */
public class CertificateRequestDeserializer {
    private static final int CERTIFICATE_REQUEST_NUM_ENTRIES = 4;
    private static final int CERTIFICATE_REQUEST_DEVICE_INFO_INDEX = 0;
    private static final int CERTIFICATE_REQUEST_CHALLENGE_INDEX = 1;
    private static final int CERTIFICATE_REQUEST_PROTECTED_DATA_INDEX = 2;
    private static final int CERTIFICATE_REQUEST_MACED_KEYS_INDEX = 3;

    private static final String DEVICE_INFO_BRAND_KEY = "brand";
    private static final String DEVICE_INFO_MANUFACTURER_KEY = "manufacturer";
    private static final String DEVICE_INFO_PRODUCT_KEY = "product";
    private static final String DEVICE_INFO_MODEL_KEY = "model";
    private static final String DEVICE_INFO_BOARD_KEY = "board";

    private CBORObject mDeviceInfo;
    private byte[] mChallenge;

    private MAC0Message mMacedKeysToSign;
    private CBORObject mProtectedData;

    /*
     * Constructor that takes as input the CBOR blob received on the server that was sent by a
     * device requesting certificates.
     */
    public CertificateRequestDeserializer(byte[] data) throws CborException, CryptoException {
        CBORObject certRequest = CBORObject.DecodeFromBytes(data);
        if (certRequest.getType() != CBORType.Array) {
            throw new CborException("CertificateRequest Type Wrong",
                                    CBORType.Array,
                                    certRequest.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        if (certRequest.size() != CERTIFICATE_REQUEST_NUM_ENTRIES) {
            throw new CborException("CertificateRequest has the wrong number of entries",
                                    CERTIFICATE_REQUEST_NUM_ENTRIES,
                                    certRequest.size(),
                                    CborException.INCORRECT_LENGTH);
        }
        mMacedKeysToSign = new MAC0Message();
        mProtectedData = CBORObject.NewArray();
        try {
            mDeviceInfo = certRequest.get(CERTIFICATE_REQUEST_DEVICE_INFO_INDEX);
            mChallenge = certRequest.get(
                CERTIFICATE_REQUEST_CHALLENGE_INDEX).ToObject(byte[].class);
            mProtectedData =
                certRequest.get(CERTIFICATE_REQUEST_PROTECTED_DATA_INDEX);
            mMacedKeysToSign.DecodeFromCBORObject(
                certRequest.get(CERTIFICATE_REQUEST_MACED_KEYS_INDEX));
        } catch (CoseException e) {
            throw new CborException("CertificateRequest deserialization failure",
                                    e, CborException.DESERIALIZATION_ERROR);
        }
    }

    /*
     * Parses a provided DeviceInfo CBOR object and populates a DeviceInfo object with the contained
     * values
     *
     * @return DeviceInfo An object that contains the different fields contained within the device
     *          info field
     */
    private static DeviceInfo parseDeviceInfo(CBORObject cborDeviceInfo) throws CborException {
        if (cborDeviceInfo.getType() != CBORType.Map) {
            throw new CborException("DeviceInfo Type Wrong",
                                    CBORType.Map,
                                    cborDeviceInfo.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        return new DeviceInfo(cborDeviceInfo);
    }

    /*
     * Returns the deserialized device info.
     *
     * @return DeviceInfo the device info structure containing information on the device
     */
    public DeviceInfo getDeviceInfo() throws CborException {
        return parseDeviceInfo(mDeviceInfo);
    }

    /*
     * Returns the device info in a CBOR encoded array. This info is needed by the server that will
     * decrypt the ProtectedData object. It is part of the AAD and will be needed to verify the
     * signature on ProtectedData.
     *
     * @return byte[] the encoded device info
     */
    public byte[] getDeviceInfoEncoded() {
        return mDeviceInfo.EncodeToBytes();
    }

    /*
     * Returns the challenge that was sent to the device by the server. This challenge is needed
     * by the server that will decrypt the ProtectedData object. It is part of the AAD and will be
     * needed to verify the signature on ProtectedData.
     *
     * Returns byte[] the deserialized challenge
     */
    public byte[] getChallenge() {
        return mChallenge;
    }

    /*
     * Provides the encrypted ProtectedData entry in the CertificateRequest array as a CBOR encoded
     * byte array. This is intended to be used to retrieve this portion of the CertificateRequest
     * so that it may be sent off to the server that contains the EEK keys which will decrypt it.
     *
     * @return byte[] the CBOR encoded ProtectedData entry
     */
    public byte[] getProtectedData() {
        return mProtectedData.EncodeToBytes();
    }

    /*
     * Returns the CBOR encoding of the MACed public keys that need to be signed and returned to the
     * device. To preserve privacy, the service decrypts the protected data payload (which contains
     * the device public key and the MAC key) should not also check the signatures on the keys and
     * send the CSR off to the CA. This should be handled by a separate server that is passed the
     * MAC key. To facilitate that, this method should be used to extract the MacedKeysToSign CBOR
     * object so that it can be sent separately over the wire to whichever service will validate
     * the public key request.
     *
     * @return byte[] the CBOR encoded attestation public keys
     */
    public byte[] getMacedKeysToSign() throws CborException {
        try {
            return mMacedKeysToSign.EncodeToBytes();
        } catch (CoseException e) {
            throw new CborException("Maced keys to sign encoding failure",
                                    e, CborException.SERIALIZATION_ERROR);
        }
    }

    /*
     * Parses the CBOR blob, {@code serializedMacedKeysToSign}, containing the MACed keys and
     * returns the individual public keys after checking the MAC with the provided {@code macKey}.
     * The {@code macKey} should have been retrieved from the ProtectedData object.
     *
     * @return ArrayList byte arrays where each byte array is a public key to be signed
     */
    public static ArrayList<PublicKey> retrievePublicKeys(byte[] serializedMacedKeysToSign,
                                                          byte[] macKey)
                                                          throws CborException, CryptoException {
        MAC0Message macedKeysToSign = new MAC0Message();
        try {
            macedKeysToSign.DecodeFromCBORObject(
                CBORObject.DecodeFromBytes(serializedMacedKeysToSign));
            if (!macedKeysToSign.Validate(macKey)) {
                throw new CryptoException("MAC on the public keys failed to validate",
                                          CryptoException.PUBLIC_KEYS_MAC_VERIFICATION_FAILED);
            }
        } catch (CoseException e) {
            throw new CborException("Couldn't decode MACed keys",
                                    e, CborException.DESERIALIZATION_ERROR);
        }

        ArrayList<PublicKey> deserializedPublicKeys = new ArrayList<PublicKey>();
        CBORObject serializedPublicKeys = CBORObject.DecodeFromBytes(macedKeysToSign.GetContent());
        if (serializedPublicKeys.getType() != CBORType.Array) {
            throw new CborException("KeysToCertify Type Wrong",
                                    CBORType.Array,
                                    serializedPublicKeys.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        for (int i = 0; i < serializedPublicKeys.size(); i++) {
            try {
                OneKey key = new OneKey(serializedPublicKeys.get(i));
                deserializedPublicKeys.add(CryptoUtil.oneKeyToP256PublicKey(key));
            } catch (CoseException e) {
                throw new CborException("Failure to deserialize public keys",
                                        e, CborException.DESERIALIZATION_ERROR);
            }
        }
        return deserializedPublicKeys;
    }
}
