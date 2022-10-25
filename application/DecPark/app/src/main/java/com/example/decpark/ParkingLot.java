package com.example.decpark;

import java.math.BigInteger;

public class ParkingLot {
    public BigInteger no_l;//id
    String lat;//精度
    String lng;//维度
    String price;//价格
    public BigInteger ps_pre;//上一时期停车位数量
    public BigInteger ps_current;//当前停车位数量
    private int imageId;//停车场图片的src

    public ParkingLot(BigInteger no_l, BigInteger ps_pre, BigInteger ps_current, String lat, String lng, String price, int imageId) {
        this.no_l = no_l;
        this.ps_pre = ps_pre;
        this.ps_current = ps_current;
        this.lat = lat;
        this.lng = lng;
        this.price = price;
        this.imageId = imageId;
    }

    public ParkingLot() {

    }

    public String getNo_l() {
        return "pl_id:" + no_l + "            " + "spots:" + ps_current ;
    }

    public void setNo_l(BigInteger no_l) {
        this.no_l = no_l;
    }

    public BigInteger getPs_pre() {
        return ps_pre;
    }

    public void setPs_pre(BigInteger ps_pre) {
        this.ps_pre = ps_pre;
    }

    public BigInteger getPs_current() {
        return ps_current;
    }

    public void setPs_current(BigInteger ps_current) {
        this.ps_current = ps_current;
    }

    public String getLat() {
        return "latitude:" + lat;
    }

    public void setLat(String lat) {
        this.lat = lat;
    }

    public String getLng() {
        return "longitude:" + lng;
    }

    public void setLng(String lng) {
        this.lng = lng;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }









    @Override
    public String toString() {
        return  "🚘"+"\n"+
                "pl_id:" + no_l + "            "+ "spots:" + ps_current +"\n"+
                "         " + price +"\n"+
                "🌎"+"\n"+
                "latitude:" + lat +"\n"+
                "longitude:" + lng +"\n";
    }

    public int getImageId() {
        return imageId;
    }

    public void setImageId(int imageId) {
        this.imageId = imageId;
    }




}
