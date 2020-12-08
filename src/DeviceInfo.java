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

import java.lang.StringBuilder;

public class DeviceInfo {
    private String mBrand;
    private String mManufacturer;
    private String mProduct;
    private String mModel;
    private String mBoard;

    public DeviceInfo() { }

    public DeviceInfo(DeviceInfo other) {
        this(other.getBrand(),
             other.getManufacturer(),
             other.getProduct(),
             other.getModel(),
             other.getBoard());
    }

    public DeviceInfo(String brand,
                      String manufacturer,
                      String product,
                      String model,
                      String board) {
        mBrand = brand;
        mManufacturer = manufacturer;
        mProduct = product;
        mModel = model;
        mBoard = board;
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (!(other instanceof DeviceInfo)) {
            return false;
        }
        DeviceInfo o = (DeviceInfo)other;
        return mBrand.equals(o.getBrand())
               && mManufacturer.equals(o.getManufacturer())
               && mProduct.equals(o.getProduct())
               && mModel.equals(o.getModel())
               && mBoard.equals(o.getBoard());
    }

    public void setBrand(String brand) {
        mBrand = brand;
    }

    public void setManufacturer(String manufacturer) {
        mManufacturer = manufacturer;
    }

    public void setProduct(String product) {
        mProduct = product;
    }

    public void setModel(String model) {
        mModel = model;
    }

    public void setBoard(String board) {
        mBoard = board;
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

    @Override
    public String toString() {
        StringBuilder str = new StringBuilder();
        str.append("Device Info:\n");
        str.append("\tBrand: " + this.getBrand());
        str.append("\tManufacturer: " + this.getManufacturer());
        str.append("\tProduct: " + this.getProduct());
        str.append("\tModel: " + this.getModel());
        str.append("\tBoard: " + this.getBoard());
        return str.toString();
    }
}
