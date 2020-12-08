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

import java.lang.Enum;

/*
 * This exception, when thrown, is indicative that the underlying Keymint or Keystore
 * implementation is producing CBOR encoding errors for the affected portion of the CBOR blob.
 */
public class CborException extends Exception {

    public static final int TYPE_MISMATCH = 1;
    public static final int INVALID_CBOR = 2;
    public static final int SERIALIZATION_ERROR = 3;
    public static final int INCORRECT_LENGTH = 4;
    public static final int DESERIALIZATION_ERROR = 5;
    public static final int INCORRECT_COSE_TYPE = 6;

    private int mErrorCode;

    public CborException(String message) {
        super(message);
    }

    public CborException(String message, int errorCode) {
        super(message);
        mErrorCode = errorCode;
    }

    /*
     * This constructor is intended to be a message format helper for when CBOR arrays have
     * unexpected sizes.
     */
    public CborException(String message, int expectedLength, int actualLength, int errorCode) {
        this(message + "\nExpected: " + expectedLength + "\nActual" + actualLength,
             errorCode);
    }

    /*
     * This constructor is intended to be a message format helper for when CBOR objects have
     * unexpected CBOR types.
     */
    public CborException(String message, Enum expectedType, Enum actualType, int errorCode) {
        this(message + "\nExpected: " + expectedType.toString()
             + "\nActual: " + actualType.toString(), errorCode);
    }

    public CborException(String message, Throwable cause, int errorCode) {
        super(message, cause);
        mErrorCode = errorCode;
    }

    public int getErrorCode() {
        return mErrorCode;
    }
}
