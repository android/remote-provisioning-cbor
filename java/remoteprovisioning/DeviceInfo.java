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


import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.Optional;

public class DeviceInfo {
  public static int DEVICE_INFO_NUM_ENTRIES = 2;
  public static int DEVICE_INFO_VERIFIED = 0;
  public static int DEVICE_INFO_UNVERIFIED = 1;

  // DeviceInfoVerified Entries
  private String mBrand;
  private String mManufacturer;
  private String mProduct;
  private String mModel;
  private String mBoard;
  private String mDevice;
  private String mVbState;
  private String mBootloaderState;
  private String mVbmetaDigest;
  private String mOsVersion;
  private String mSecurityLevel;

  private int mSystemPatchLevel;
  private int mBootPatchLevel;
  private int mVendorPatchLevel;
  private int mVersion;

  // DeviceInfoUnverified Entries
  private String mFingerprint;

  public DeviceInfo(CBORObject map) throws CborException {
    parseDeviceInfo(map);
  }

  private void parseDeviceInfo(CBORObject deviceInfo) throws CborException {
    if (deviceInfo.getType() != CBORType.Array) {
      throw new CborException(
        "DeviceInfo type wrong", CBORType.Array, deviceInfo.getType(), CborException.TYPE_MISMATCH);
    }
    if (deviceInfo.size() != DEVICE_INFO_NUM_ENTRIES) {
      throw new CborException(
        "DeviceInfo has incorrect number of entries.",
        DEVICE_INFO_NUM_ENTRIES, deviceInfo.size(), CborException.INCORRECT_LENGTH);
    }
    if (deviceInfo.get(DEVICE_INFO_VERIFIED).getType() != CBORType.Map) {
      throw new CborException(
        "DeviceInfoVerified type wrong",
        CBORType.Map, deviceInfo.get(DEVICE_INFO_VERIFIED).getType(), CborException.TYPE_MISMATCH);
    }
    if (deviceInfo.get(DEVICE_INFO_UNVERIFIED).getType() != CBORType.Map) {
      throw new CborException(
        "DeviceInfoUnverified type wrong",
        CBORType.Map,
        deviceInfo.get(DEVICE_INFO_UNVERIFIED).getType(),
        CborException.TYPE_MISMATCH);
    }
    CBORObject devInfoVerified = deviceInfo.get(DEVICE_INFO_VERIFIED);
    mBrand = Optional.ofNullable(devInfoVerified.get("brand")).map(x -> x.AsString()).orElse("");
    mManufacturer =
        Optional.ofNullable(devInfoVerified.get("manufacturer")).map(x -> x.AsString()).orElse("");
    mProduct =
        Optional.ofNullable(devInfoVerified.get("product")).map(x -> x.AsString()).orElse("");
    mModel = Optional.ofNullable(devInfoVerified.get("model")).map(x -> x.AsString()).orElse("");
    mBoard = Optional.ofNullable(devInfoVerified.get("board")).map(x -> x.AsString()).orElse("");
    mDevice = Optional.ofNullable(devInfoVerified.get("device")).map(x -> x.AsString()).orElse("");
    mVbState =
        Optional.ofNullable(devInfoVerified.get("vb_state")).map(x -> x.AsString()).orElse("");
    mBootloaderState =
        Optional.ofNullable(
            devInfoVerified.get("bootloader_state")).map(x -> x.AsString()).orElse("");
    mVbmetaDigest =
        Optional.ofNullable(devInfoVerified.get("vbmeta_digest")).map(x -> x.AsString()).orElse("");
    mOsVersion =
        Optional.ofNullable(devInfoVerified.get("os_version")).map(x -> x.AsString()).orElse("");
    mSystemPatchLevel =
        Optional.ofNullable(
            devInfoVerified.get("system_patch_level")).map(x -> x.AsInt32()).orElse(-1);
    mBootPatchLevel =
        Optional.ofNullable(
            devInfoVerified.get("boot_patch_level")).map(x -> x.AsInt32()).orElse(-1);
    mVendorPatchLevel =
        Optional.ofNullable(
            devInfoVerified.get("vendor_patch_level")).map(x -> x.AsInt32()).orElse(-1);
    mVersion =
        Optional.ofNullable(devInfoVerified.get("version")).map(x -> x.AsInt32()).orElse(-1);
    mSecurityLevel =
        Optional.ofNullable(
            devInfoVerified.get("security_level")).map(x -> x.AsString()).orElse("");
    CBORObject devInfoUnverified = deviceInfo.get(DEVICE_INFO_UNVERIFIED);
    mFingerprint =
        Optional.ofNullable(devInfoUnverified.get("fingerprint")).map(x -> x.AsString()).orElse("");
  }

  public String getBrand() {
    return mBrand;
  }

  public String getManufacturer() {
    return mManufacturer;
  }

  public String getProduct() {
    return mProduct;
  }

  public String getModel() {
    return mModel;
  }

  public String getBoard() {
    return mBoard;
  }

  public String getDevice() {
    return mDevice;
  }

  public int getVersion() {
    return mVersion;
  }

  public String getVbState() {
    return mVbState;
  }

  public String getBootloaderState() {
    return mBootloaderState;
  }

  public String getVbmetaDigest() {
    return mVbmetaDigest;
  }

  public String getOsVersion() {
    return mOsVersion;
  }

  public int getSystemPatchLevel() {
    return mSystemPatchLevel;
  }

  public int getBootPatchLevel() {
    return mBootPatchLevel;
  }

  public int getVendorPatchLevel() {
    return mVendorPatchLevel;
  }

  public String getFingerprint() {
    return mFingerprint;
  }

  public String getSecurityLevel() {
    return mSecurityLevel;
  }

  @Override
  public String toString() {
    StringBuilder str = new StringBuilder();
    str.append("Device Info:");
    str.append("\nVersion: ").append(mVersion);
    str.append("Verified Info:");
    str.append("\n\tBrand: ").append(this.getBrand());
    str.append("\n\tManufacturer: ").append(this.getManufacturer());
    str.append("\n\tProduct: ").append(this.getProduct());
    str.append("\n\tModel: ").append(this.getModel());
    str.append("\n\tBoard: ").append(this.getBoard());
    str.append("\n\tDevice: ").append(this.getDevice());
    str.append("\n\tVerified Boot State: ").append(this.getVbState());
    str.append("\n\tBootloader State: ").append(this.getBootloaderState());
    str.append("\n\tVBMeta Digest: ").append(this.getVbmetaDigest());
    str.append("\n\tOS Version: ").append(this.getOsVersion());
    str.append("\n\tSystem Patch Level: ").append(this.getSystemPatchLevel());
    str.append("\n\tBoot Patch Level: ").append(this.getBootPatchLevel());
    str.append("\n\tVendor Patch Level: ").append(this.getVendorPatchLevel());
    str.append("\n\tSecurity Level: ").append(this.getSecurityLevel());
    str.append("\nUnverified Info:");
    str.append("\n\tFingerprint: ").append(this.getFingerprint());
    return str.toString();
  }
}
