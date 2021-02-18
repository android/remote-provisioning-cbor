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

import remoteprovisioning.CborException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.lang.StringBuilder;
import java.util.Optional;

public class DeviceInfo {
    private String mBrand;
    private String mManufacturer;
    private String mProduct;
    private String mModel;
    private String mBoard;
    private String mVbState;
    private String mBootloaderState;
    private String mVbmetaDigest;
    private String mOsVersion;

    private int mSystemPatchLevel;
    private int mBootPatchLevel;
    private int mVendorPatchLevel;

    public DeviceInfo(CBORObject map) throws CborException {
        parseDeviceInfo(map);
    }

    private void parseDeviceInfo(CBORObject deviceInfo) throws CborException {
        if (deviceInfo.getType() != CBORType.Map) {
            throw new CborException("DeviceInfo type wrong",
                                    CBORType.Map,
                                    deviceInfo.getType(),
                                    CborException.TYPE_MISMATCH);
        }
        mBrand = Optional.ofNullable(deviceInfo.get("brand"))
                         .map(x -> x.AsString())
                         .orElse("");
        mManufacturer = Optional.ofNullable(deviceInfo.get("manufacturer"))
                                .map(x -> x.AsString())
                                .orElse("");
        mProduct = Optional.ofNullable(deviceInfo.get("product"))
                           .map(x -> x.AsString())
                           .orElse("");
        mModel = Optional.ofNullable(deviceInfo.get("model"))
                                .map(x -> x.AsString())
                                .orElse("");
        mBoard = Optional.ofNullable(deviceInfo.get("board"))
                                .map(x -> x.AsString())
                                .orElse("");
        mVbState = Optional.ofNullable(deviceInfo.get("vb_state"))
                                .map(x -> x.AsString())
                                .orElse("");
        mBootloaderState = Optional.ofNullable(deviceInfo.get("bootloader_state"))
                                .map(x -> x.AsString())
                                .orElse("");
        mVbmetaDigest = Optional.ofNullable(deviceInfo.get("vbmeta_digest"))
                                .map(x -> x.AsString())
                                .orElse("");
        mOsVersion = Optional.ofNullable(deviceInfo.get("os_version"))
                                .map(x -> x.AsString())
                                .orElse("");
        mSystemPatchLevel = Optional.ofNullable(deviceInfo.get("system_patch_level"))
                                .map(x -> x.AsInt32())
                                .orElse(-1);
        mBootPatchLevel = Optional.ofNullable(deviceInfo.get("boot_patch_level"))
                                .map(x -> x.AsInt32())
                                .orElse(-1);
        mVendorPatchLevel = Optional.ofNullable(deviceInfo.get("vendor_patch_level"))
                                .map(x -> x.AsInt32())
                                .orElse(-1);
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

    @Override
    public String toString() {
        StringBuilder str = new StringBuilder();
        str.append("Device Info:\n");
        str.append("\tBrand: " + this.getBrand());
        str.append("\tManufacturer: " + this.getManufacturer());
        str.append("\tProduct: " + this.getProduct());
        str.append("\tModel: " + this.getModel());
        str.append("\tBoard: " + this.getBoard());
        str.append("\tVerified Boot State: " + this.getVbState());
        str.append("\tBootloader State: " + this.getBootloaderState());
        str.append("\tVBMeta Digest: " + this.getVbmetaDigest());
        str.append("\tOS Version: " + this.getOsVersion());
        str.append("\tSystem Patch Level: " + this.getSystemPatchLevel());
        str.append("\tBoot Patch Level: " + this.getBootPatchLevel());
        str.append("\tVendor Patch Level: " + this.getVendorPatchLevel());
        return str.toString();
    }
}
