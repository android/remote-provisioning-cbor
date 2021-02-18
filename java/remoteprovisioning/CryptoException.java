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


/*
 * This exception, when thrown, is indicative that some cryptographic operation has failed -
 * verification of a MAC or signature, decryption, etc - while attempting to parse and verify the
 * different fields of a CertificateRequest structure.
 */
public class CryptoException extends Exception {

  public static final int PUBLIC_KEYS_MAC_VERIFICATION_FAILED = 1;
  public static final int MAC_WITH_AAD_SIGNATURE_VERIFICATION_FAILED = 2;
  public static final int MACING_FAILURE = 3;
  public static final int SIGNING_FAILURE = 4;
  public static final int ENCRYPTION_FAILURE = 5;
  public static final int VERIFICATION_FAILURE = 6;
  public static final int NO_SUCH_ALGORITHM = 7;
  public static final int MALFORMED_KEY = 8;
  public static final int KEY_GENERATION_FAILURE = 9;
  public static final int DECRYPTION_FAILURE = 10;

  private int mErrorCode;

  public CryptoException(String message, int errorCode) {
    super(message);
    mErrorCode = errorCode;
  }

  public CryptoException(String message, Throwable cause, int errorCode) {
    super(message, cause);
    mErrorCode = errorCode;
  }

  public int getErrorCode() {
    return mErrorCode;
  }
}
