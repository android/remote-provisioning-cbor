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

import junit.framework.TestCase;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.junit.*;
import org.junit.Test;
import org.junit.runner.*;
import org.junit.runners.*;
import static org.junit.Assert.*;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.HeaderKeys;
import COSE.KeyKeys;
import COSE.OneKey;
import COSE.Sign1Message;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;


@RunWith(JUnit4.class)
public class CertificateRequestDeserializerTest {
    private byte[] mac = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                          15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                          27, 28, 29, 30, 31, 32};

    private byte[] challenge = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                14, 15, 16};
    private byte[] certificateRequestSerialized;
    private DeviceInfo deviceInfo = new DeviceInfo("a", "b", "c", "d", "e");

    private OneKey deviceKeyPair;
    private OneKey[] keysToSign;
    private Sign1Message[] bcc;
    private KeyPair serverKeyPair;
    private OneKey oemKeyPair;
    private Sign1Message[] additionalDkSignatureChain;

    private CertificateRequestDeserializer certRequest;

    @BeforeClass
    public static void beforeAllTestMethods() {
        Security.addProvider(new EdDSASecurityProvider());
    }

    @Before
    public void setUp() throws Exception {
        deviceKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
        deviceKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
        keysToSign = new OneKey[] { OneKey.generateKey(KeyKeys.OKP_Ed25519).PublicKey() };
        
        // Generate a BCC and self sign
        Sign1Message bccCert = new Sign1Message();
        bccCert.addAttribute(HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        bccCert.SetContent(deviceKeyPair.PublicKey().EncodeToBytes());
        bccCert.sign(deviceKeyPair);
        bcc = new Sign1Message[] { bccCert };

        // Generate the EEK server key pair
        serverKeyPair = genX25519();

        // Generate the additional device key signing certificates.
        // OEM certificate is self signed; device certificate is signed by the OEM key pair
        oemKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
        oemKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
        Sign1Message signingCert = new Sign1Message();
        Sign1Message deviceCert = new Sign1Message();
        signingCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        signingCert.SetContent(oemKeyPair.PublicKey().EncodeToBytes());
        signingCert.sign(oemKeyPair);

        deviceCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        deviceCert.SetContent(deviceKeyPair.PublicKey().EncodeToBytes());
        deviceCert.sign(oemKeyPair);
        additionalDkSignatureChain = new Sign1Message[] { signingCert, deviceCert };

        // Build the CBOR blob
        certificateRequestSerialized = new CertificateRequestSerializer.Builder(
                                (XECPublicKey) serverKeyPair.getPublic())
                                .setDeviceInfo(deviceInfo)
                                .setPublicKeys(keysToSign)
                                .setMacKey(mac)
                                .setChallenge(challenge)
                                .setBcc(bcc, 0 /* deviceKeyEntry */)
                                .setDkPriv(deviceKeyPair)
                                .addAdditionalDkSignature(0 /* signerId */,
                                                          additionalDkSignatureChain)
                                .build()
                                .buildCertificateRequest();
        certRequest = new CertificateRequestDeserializer(certificateRequestSerialized);
    }

    private KeyPair genX25519() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        return kpg.generateKeyPair();
    }

    private KeyPair genEd25519() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }

    @Test
    public void TestSerializeDeserialize() throws Exception {
        ProtectedDataPayload payload =
            new ProtectedDataPayload(
                certRequest.getProtectedData(),
                certRequest.getChallenge(),
                certRequest.getDeviceInfoEncoded(),
                serverKeyPair);
        assertNotNull(payload);
        assertTrue(Arrays.equals(
            payload.getDevicePublicKey(),
            deviceKeyPair.PublicKey().get(KeyKeys.OKP_X).ToObject(byte[].class)));
        assertTrue(Arrays.equals(payload.getMacKey(), mac));

        ArrayList<byte[]> publicKeys =
            CertificateRequestDeserializer.retrievePublicKeys(certRequest.getMacedKeysToSign(),
                                                              payload.getMacKey());
        assertNotNull(publicKeys);
        assertEquals(1, publicKeys.size());
        assertTrue(
            Arrays.equals(publicKeys.get(0),
                          CryptoUtil.byteArrayToEd25519PublicKey(
                              keysToSign[0]
                                  .get(KeyKeys.OKP_X)
                                  .ToObject(byte[].class))
                          .getEncoded()));
    }

    @Test
    public void TestWrongMacFails() throws Exception {
        byte[] badMac = Arrays.copyOf(mac, mac.length);
        badMac[4] = 21;
        try {
            CertificateRequestDeserializer.retrievePublicKeys(certRequest.getMacedKeysToSign(),
                                                              badMac);
        } catch (CryptoException e) {
            assertEquals(CryptoException.PUBLIC_KEYS_MAC_VERIFICATION_FAILED, e.getErrorCode());
            return;
        }
        fail();
    }

    @Test
    public void TestWrongEekFails() throws Exception {
        KeyPair fakeKeyPair = genX25519();
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    certRequest.getChallenge(),
                    certRequest.getDeviceInfoEncoded(),
                    fakeKeyPair);
        } catch (CryptoException e) {
            assertEquals(CryptoException.DECRYPTION_FAILURE, e.getErrorCode());
            return;
        }
        fail();
    }

    @Test
    public void TestWrongChallengeAadMacFails() throws Exception {
        byte[] badChallenge = Arrays.copyOf(challenge, challenge.length);
        badChallenge[0] = 12;
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    badChallenge,
                    certRequest.getDeviceInfoEncoded(),
                    serverKeyPair);
        } catch (CryptoException e) {
            assertEquals(CryptoException.MAC_WITH_AAD_SIGNATURE_VERIFICATION_FAILED,
                         e.getErrorCode());
            return;
        }
        fail();
    }

    @Test
    public void TestWrongDeviceInfoAadMacFails() throws Exception {
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    certRequest.getChallenge(),
                    // equivalent to an encoded: new DeviceInfo('a','b','c','d','f');
                    new byte[] {-123, 97, 97, 97, 98, 97, 99, 97, 100, 97, 102},
                    serverKeyPair);
        } catch (CryptoException e) {
            assertEquals(CryptoException.MAC_WITH_AAD_SIGNATURE_VERIFICATION_FAILED,
                         e.getErrorCode());
            return;
        }
        fail();
    }

    @Test
    public void TestAdditionalSignatureMapEmptyPasses() throws Exception {
        certificateRequestSerialized = new CertificateRequestSerializer.Builder(
                            (XECPublicKey) serverKeyPair.getPublic())
                            .setDeviceInfo(deviceInfo)
                            .setPublicKeys(keysToSign)
                            .setMacKey(mac)
                            .setChallenge(challenge)
                            .setBcc(bcc, 0 /* deviceKeyEntry */)
                            .setDkPriv(deviceKeyPair)
                            .build()
                            .buildCertificateRequest();
        certRequest = new CertificateRequestDeserializer(certificateRequestSerialized);
        ProtectedDataPayload payload =
            new ProtectedDataPayload(
                certRequest.getProtectedData(),
                challenge,
                certRequest.getDeviceInfoEncoded(),
                serverKeyPair);
        assertNotNull(payload);
    }

    @Test
    public void TestAdditionalSignatureBadRootSigFails() throws Exception {
        Sign1Message signingCert = new Sign1Message();
        Sign1Message deviceCert = new Sign1Message();
        signingCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        signingCert.SetContent(oemKeyPair.PublicKey().EncodeToBytes());
        // Sign with the wrong key
        signingCert.sign(deviceKeyPair);

        deviceCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        deviceCert.SetContent(deviceKeyPair.PublicKey().EncodeToBytes());
        deviceCert.sign(oemKeyPair);
        additionalDkSignatureChain = new Sign1Message[] { signingCert, deviceCert };

        certificateRequestSerialized = new CertificateRequestSerializer.Builder(
                            (XECPublicKey) serverKeyPair.getPublic())
                            .setDeviceInfo(deviceInfo)
                            .setPublicKeys(keysToSign)
                            .setMacKey(mac)
                            .setChallenge(challenge)
                            .setBcc(bcc, 0 /* deviceKeyEntry */)
                            .setDkPriv(deviceKeyPair)
                            .addAdditionalDkSignature(0 /* signerId */, additionalDkSignatureChain)
                            .build()
                            .buildCertificateRequest();
        certRequest = new CertificateRequestDeserializer(certificateRequestSerialized);
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    challenge,
                    certRequest.getDeviceInfoEncoded(),
                    serverKeyPair);
        } catch (CryptoException e) {
            assertEquals(e.getErrorCode(), CryptoException.VERIFICATION_FAILURE);
            return;
        }
        fail();
    }

    @Test
    public void TestAdditionalSignatureBadLeafSigFailes() throws Exception {
        Sign1Message signingCert = new Sign1Message();
        Sign1Message deviceCert = new Sign1Message();
        signingCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        signingCert.SetContent(oemKeyPair.PublicKey().EncodeToBytes());
        signingCert.sign(oemKeyPair);

        deviceCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        deviceCert.SetContent(deviceKeyPair.PublicKey().EncodeToBytes());
        // Sign with the wrong key
        deviceCert.sign(deviceKeyPair);
        additionalDkSignatureChain = new Sign1Message[] { signingCert, deviceCert };

        certificateRequestSerialized = new CertificateRequestSerializer.Builder(
                            (XECPublicKey) serverKeyPair.getPublic())
                            .setDeviceInfo(deviceInfo)
                            .setPublicKeys(keysToSign)
                            .setMacKey(mac)
                            .setChallenge(challenge)
                            .setBcc(bcc, 0 /* deviceKeyEntry */)
                            .setDkPriv(deviceKeyPair)
                            .addAdditionalDkSignature(0 /* signerId */, additionalDkSignatureChain)
                            .build()
                            .buildCertificateRequest();
        certRequest = new CertificateRequestDeserializer(certificateRequestSerialized);
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    challenge,
                    certRequest.getDeviceInfoEncoded(),
                    serverKeyPair);
        } catch (CryptoException e) {
            assertEquals(e.getErrorCode(), CryptoException.VERIFICATION_FAILURE);
            return;
        }
        fail();
    }

    @Test
    public void TestAdditionalSignatureWrongDeviceKeyFails() throws Exception {
        Sign1Message signingCert = new Sign1Message();
        Sign1Message deviceCert = new Sign1Message();
        signingCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        signingCert.SetContent(oemKeyPair.PublicKey().EncodeToBytes());
        signingCert.sign(oemKeyPair);

        deviceCert.addAttribute(
            HeaderKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR(), Attribute.PROTECTED);
        // Sign the wrong key
        deviceCert.SetContent(oemKeyPair.PublicKey().EncodeToBytes());
        deviceCert.sign(oemKeyPair);
        additionalDkSignatureChain = new Sign1Message[] { signingCert, deviceCert };

        certificateRequestSerialized = new CertificateRequestSerializer.Builder(
                            (XECPublicKey) serverKeyPair.getPublic())
                            .setDeviceInfo(deviceInfo)
                            .setPublicKeys(keysToSign)
                            .setMacKey(mac)
                            .setChallenge(challenge)
                            .setBcc(bcc, 0 /* deviceKeyEntry */)
                            .setDkPriv(deviceKeyPair)
                            .addAdditionalDkSignature(0 /* signerId */, additionalDkSignatureChain)
                            .build()
                            .buildCertificateRequest();
        certRequest = new CertificateRequestDeserializer(certificateRequestSerialized);
        try {
            ProtectedDataPayload payload =
                new ProtectedDataPayload(
                    certRequest.getProtectedData(),
                    challenge,
                    certRequest.getDeviceInfoEncoded(),
                    serverKeyPair);
        } catch (CryptoException e) {
            assertEquals(e.getErrorCode(), CryptoException.VERIFICATION_FAILURE);
            return;
        }
        fail();
    }
}
