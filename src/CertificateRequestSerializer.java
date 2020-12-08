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

import com.google.remote.cbor.CborException;
import com.google.remote.cbor.CryptoException;
import com.google.remote.cbor.CryptoUtil;
import com.google.remote.cbor.DeviceInfo;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.MAC0Message;
import COSE.OneKey;
import COSE.Sign1Message;

import java.security.*;

/*
 * The main purpose of this class is to help test the CertificateRequestDeserializer. A server or
 * tool making use of this library will have no need to put together a CertificateRequest; the CDDL
 * blob will come from the device in question.
 *
 * For testing (and future) purposes, this class provides a builder class to set all the relevant
 * fields contained in the CertificateRequest CDDL, and a method to return those fields as a
 * properly encoded CBOR byte array.
 */
public class CertificateRequestSerializer {
    private CBORObject mDeviceInfo;
    private X25519PublicKeyParameters mEek;
    private CBORObject mPublicKeys;
    private CBORObject mMacKey;
    private CBORObject mChallenge;
    private CBORObject mBcc;
    private CBORObject mAdditionalDkSignatures;
    private OneKey mDkPriv;
    private AsymmetricCipherKeyPair mEphemeralKeyPair;

    public CertificateRequestSerializer(CBORObject deviceInfo,
                                         X25519PublicKeyParameters eek,
                                         CBORObject publicKeys,
                                         CBORObject macKey,
                                         CBORObject challenge,
                                         CBORObject bcc,
                                         OneKey dkPriv,
                                         CBORObject additionalDkSignatures,
                                         AsymmetricCipherKeyPair ephemeralKeyPair) {
        mDeviceInfo = deviceInfo;
        mEek = eek;
        mPublicKeys = publicKeys;
        mMacKey = macKey;
        mChallenge = challenge;
        mBcc = bcc;
        mDkPriv = dkPriv;
        mAdditionalDkSignatures = additionalDkSignatures;
        mEphemeralKeyPair = ephemeralKeyPair;
    }

    public X25519PublicKeyParameters getEphemeralPubKey() {
        return (X25519PublicKeyParameters) mEphemeralKeyPair.getPublic();
    }

    // publicKeys are the keys to be signed
    // macKey is the key used for the MAC
    private  CBORObject buildMacedKeysToSign() throws CborException, CryptoException {
        MAC0Message msg = new MAC0Message();
        try {
            msg.addAttribute(
                HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        } catch (CoseException e) {
            throw new CborException ("Malformed input - this should not happen",
                                     e, CborException.SERIALIZATION_ERROR);
        }
        msg.SetContent(mPublicKeys.EncodeToBytes());
        try {
            msg.Create(mMacKey.ToObject(byte[].class));
        } catch (CoseException e) {
            throw new CryptoException("Failed to MAC the MACed keys to sign",
                                      e, CryptoException.MACING_FAILURE);
        }
        try {
            return msg.EncodeToCBORObject();
        } catch (CoseException e) {
            throw new CborException("Failed to serialize MACed keys to sign",
                                    e, CborException.SERIALIZATION_ERROR);
        }
    }

    /*
     * Produces a CBORObject that contains the associated, authenticated data that goes along with
     * the SignedMac entry
     *
     * @return CBORObject CBOR array containing the challenge and the device info
     */
    private CBORObject buildSignedDataAad() {
        CBORObject arr = CBORObject.NewArray();
        arr.Add(mDeviceInfo);
        arr.Add(mChallenge);
        return arr;
    }

    /*
     * Produces a CBORObject representing the SignedMac entry, signed with the device private key
     *
     * @return CBORObject A CBOR array containing the fields of a COSE_Sign1 Message
     */
    private CBORObject buildSignedMac() throws CryptoException, CborException {
        Sign1Message msg = new Sign1Message();
        try {
            msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        } catch (CoseException e) {
            throw new CborException ("Malformed input - this should not happen",
                                     e, CborException.SERIALIZATION_ERROR);
        }
        msg.setExternal(buildSignedDataAad().EncodeToBytes());
        msg.SetContent(mMacKey.EncodeToBytes());
        try {
            msg.sign(mDkPriv);
        } catch (CoseException e) {
            throw new CryptoException("Failed to sign MAC key with device private key",
                                      e, CryptoException.SIGNING_FAILURE);
        }
        try {
            return msg.EncodeToCBORObject();
        } catch (CoseException e) {
            throw new CborException("Failed to serialize signed MAC",
                                    e, CborException.SERIALIZATION_ERROR);
        }
    }

    private CBORObject buildProtectedData() throws CborException, CryptoException {
        CBORObject protectedDataPayload = CBORObject.NewArray();
        protectedDataPayload.Add(buildSignedMac());
        protectedDataPayload.Add(mBcc);
        protectedDataPayload.Add(mAdditionalDkSignatures);
        CBORObject encMsg =
            CborUtil.encodeEncryptMessage(
                protectedDataPayload.EncodeToBytes(), mEphemeralKeyPair, mEek);
        return encMsg;
    }

    /*
     * Puts together the CBOR blob representing a CertificateRequest, composed of the data
     * provided in the builder constructor class.
     *
     * @return byte[] the CertificateRequest as a CBOR encoded byte array
     */
    public byte[] buildCertificateRequest() throws CborException, CryptoException {
        CBORObject certRequest = CBORObject.NewArray();
        certRequest.Add(mDeviceInfo);
        certRequest.Add(mChallenge);
        certRequest.Add(buildProtectedData());
        certRequest.Add(buildMacedKeysToSign());
        return certRequest.EncodeToBytes();
    }

    /*
     * A builder class to put together all the relevant information needed to form a
     * CertificateRequest as defined by the CDDL
     */
    public final static class Builder {
        private CBORObject mDeviceInfo;
        private X25519PublicKeyParameters mEek;
        private CBORObject mPublicKeys;
        private CBORObject mMacKey;
        private CBORObject mChallenge;
        private CBORObject mBcc;
        private CBORObject mAdditionalDkSignatures = CBORObject.NewMap();
        private OneKey mDkPriv;

        /*
         * Builder constructor that takes an X25519 public key as an input parameter. This key
         * corresponds to the private key held by the server.
         */
        public Builder(X25519PublicKeyParameters eek) {
            mEek = eek;
        }

        public Builder setDeviceInfo(DeviceInfo deviceInfo) {
            mDeviceInfo = CBORObject.NewArray();
            mDeviceInfo.Add(deviceInfo.getBrand());
            mDeviceInfo.Add(deviceInfo.getManufacturer());
            mDeviceInfo.Add(deviceInfo.getProduct());
            mDeviceInfo.Add(deviceInfo.getModel());
            mDeviceInfo.Add(deviceInfo.getBoard());
            return this;
        }

        public Builder setPublicKeys(byte[][] publicKeys) {
            mPublicKeys = CBORObject.NewArray();
            for (int i = 0; i < publicKeys.length; i++) {
                OneKey key = new OneKey();
                key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
                key.add(KeyKeys.Algorithm, CBORObject.FromObject(-8));                   //EdDSA
                key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_Ed25519);
                key.add(KeyKeys.OKP_X, CBORObject.FromObject(publicKeys[i]));
                mPublicKeys.Add(key.AsCBOR());
            }
            return this;
        }

        public Builder setPublicKeys(OneKey[] publicKeys) {
            mPublicKeys = CBORObject.NewArray();
            for (int i = 0; i < publicKeys.length; i++) {
                mPublicKeys.Add(publicKeys[i].AsCBOR());
            }
            return this;
        }

        public Builder setMacKey(byte[] macKey) {
            mMacKey = CBORObject.FromObject(macKey);
            return this;
        }

        public Builder setChallenge(byte[] challenge) {
            mChallenge = CBORObject.FromObject(challenge);
            return this;
        }

        public Builder setBcc(Sign1Message[] bcc, int deviceKeyEntry) throws CborException {
            mBcc = CBORObject.NewArray();
            mBcc.Add(deviceKeyEntry);
            CBORObject certChain = CBORObject.NewArray();
            for (int i = 0; i < bcc.length; i++) {
                try {
                    certChain.Add(bcc[i].EncodeToCBORObject());
                } catch (CoseException e) {
                    throw new CborException("BCC encoding failure",
                                            e, CborException.SERIALIZATION_ERROR);
                }
            }
            mBcc.Add(certChain);
            return this;
        }

        public Builder addAdditionalDkSignature(int signerId, Sign1Message[] dkSignature)
                throws CborException {
            CBORObject certs = CBORObject.NewArray();
            try {
                certs.Add(dkSignature[0].EncodeToCBORObject());
                certs.Add(dkSignature[1].EncodeToCBORObject());
                mAdditionalDkSignatures.Add(CBORObject.FromObject(signerId), certs);
            } catch (CoseException e) {
                throw new CborException("Additional device key signature encoding failure",
                                        e, CborException.SERIALIZATION_ERROR);
            }
            return this;
        }

        public Builder setDkPriv(OneKey dkPriv) {
            mDkPriv = dkPriv;
            return this;
        }

        public CertificateRequestSerializer build() throws CryptoException {
            return new CertificateRequestSerializer(
                            mDeviceInfo,
                            mEek,
                            mPublicKeys,
                            mMacKey,
                            mChallenge,
                            mBcc,
                            mDkPriv,
                            mAdditionalDkSignatures,
                            CryptoUtil.genX25519());
        }
    }
}
