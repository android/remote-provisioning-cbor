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


import static org.junit.Assert.*;

import COSE.AlgorithmID;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import java.security.*;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.*;
import org.junit.Test;
import org.junit.runner.*;
import org.junit.runners.*;

@RunWith(JUnit4.class)
public class EekCertChainTest {

  private OneKey eekRootKeyPair;
  private OneKey eekIntKeyPair;
  private AsymmetricCipherKeyPair eekKeyPair;
  private EekCertChainSerializer serializer;

  @BeforeClass
  public static void beforeAllTestMethods() {
    Security.addProvider(new EdDSASecurityProvider());
  }

  @Before
  public void setUp() throws Exception {
    eekRootKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
    eekRootKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
    eekIntKeyPair = OneKey.generateKey(KeyKeys.OKP_Ed25519);
    eekIntKeyPair.add(KeyKeys.Algorithm, AlgorithmID.EDDSA.AsCBOR());
    eekKeyPair = CryptoUtil.genX25519();
    CBORObject certArray = CBORObject.NewArray();
    certArray.Add(CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekRootKeyPair.PublicKey()));
    certArray.Add(CryptoUtil.createCertificateEd25519(eekRootKeyPair, eekIntKeyPair.PublicKey()));
    serializer =
        new EekCertChainSerializer(
            certArray.EncodeToBytes(),
            eekIntKeyPair,
            (X25519PublicKeyParameters) eekKeyPair.getPublic());
  }

  @Test
  public void testSerializeDeserialize() throws Exception {
    byte[] serialized = serializer.buildEekChain();
    EekCertChainDeserializer deserializer = new EekCertChainDeserializer(serialized);
    X25519PublicKeyParameters expected = (X25519PublicKeyParameters) eekKeyPair.getPublic();
    X25519PublicKeyParameters actual = (X25519PublicKeyParameters) deserializer.getEek();
    assertTrue(Arrays.equals(expected.getEncoded(), actual.getEncoded()));
  }
}
