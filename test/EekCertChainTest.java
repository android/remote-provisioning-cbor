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

package remoteprovisioning.test;


import static org.junit.Assert.assertTrue;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.OneKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import remoteprovisioning.CryptoUtil;
import remoteprovisioning.EekCertChainDeserializer;
import remoteprovisioning.EekCertChainSerializer;

/**
 * Class to test the Eek chain serialization and deserialization classes.
 */
@RunWith(JUnit4.class)
public class EekCertChainTest {

  @Before
  public void setUp() {
    Security.addProvider(new EdDSASecurityProvider());
  }

  @Test
  public void testSerializeDeserialize25519() throws Exception {
    OneKey eekRootKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
    eekRootKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
    OneKey eekIntKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
    eekIntKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
    AsymmetricCipherKeyPair eekKeyPair = CryptoUtil.genX25519();
    EekCertChainSerializer serializer =
        new EekCertChainSerializer(
            CryptoUtil.createCertificateEd25519(
                eekRootKeyPair, eekRootKeyPair.PublicKey()).EncodeToBytes(),
            CryptoUtil.createCertificateEd25519(
                eekRootKeyPair, eekIntKeyPair.PublicKey()).EncodeToBytes(),
            eekIntKeyPair.get(KeyKeys.OKP_D).GetByteString(),
            (X25519PublicKeyParameters) eekKeyPair.getPublic());
    byte[] serialized = serializer.buildEekChain();
    EekCertChainDeserializer deserializer = new EekCertChainDeserializer(serialized);
    X25519PublicKeyParameters expected = (X25519PublicKeyParameters) eekKeyPair.getPublic();
    X25519PublicKeyParameters actual = deserializer.getEek();
    assertTrue(Arrays.equals(expected.getEncoded(), actual.getEncoded()));
  }

  @Test
  public void testSerializeDeserializeP256() throws Exception {
    OneKey eekRootKeyPair = OneKey.generateKey(KeyKeys.EC2_P256);
    OneKey eekIntKeyPair = OneKey.generateKey(KeyKeys.EC2_P256);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair eekKeyPair = kpg.genKeyPair();
    EekCertChainSerializer serializer =
        new EekCertChainSerializer(
            CryptoUtil.createCertificate(
                eekRootKeyPair, eekRootKeyPair.PublicKey(),
                AlgorithmID.ECDSA_256, AlgorithmID.ECDSA_256).EncodeToBytes(),
            CryptoUtil.createCertificate(
                eekRootKeyPair, eekIntKeyPair.PublicKey(),
                AlgorithmID.ECDSA_256, AlgorithmID.ECDSA_256).EncodeToBytes(),
            (ECPrivateKey) eekIntKeyPair.AsPrivateKey(),
            (ECPublicKey) eekKeyPair.getPublic());
    byte[] serialized = serializer.buildEekChain();
    EekCertChainDeserializer deserializer = new EekCertChainDeserializer(serialized);
    ECPublicKey expected = (ECPublicKey) eekKeyPair.getPublic();
    ECPublicKey actual = deserializer.getEekP256();
    assertTrue(Arrays.equals(expected.getEncoded(), actual.getEncoded()));
  }
}
