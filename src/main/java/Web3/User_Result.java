package Web3;

import java.math.BigInteger;

public class User_Result {
    public BigInteger no_l;
    public BigInteger ps_pre;
    public BigInteger ps_current;
    String lat;
    String lng;
    String price;
    public BigInteger node_index;

//    public User_Result(BigInteger no_l, BigInteger ps_pre, BigInteger ps_current, String lat, String lng, String price) {
//        this.no_l = no_l;
//        this.ps_pre = ps_pre;
//        this.ps_current = ps_current;
//        this.lat = lat;
//        this.lng = lng;

    public User_Result(BigInteger no_l, BigInteger ps_pre, BigInteger ps_current, String lat, String lng, String price, BigInteger node_index) {
        this.no_l = no_l;
        this.ps_pre = ps_pre;
        this.ps_current = ps_current;
        this.lat = lat;
        this.lng = lng;
        this.price = price;
        this.node_index = node_index;
    }
//        this.price = price;
//    }

    public BigInteger getNo_l() {
        return no_l;
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
        return lat;
    }

    public void setLat(String lat) {
        this.lat = lat;
    }

    public String getLng() {
        return lng;
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
        return "User_Result{" +
                "no_l=" + no_l +
                ", ps_pre=" + ps_pre +
                ", ps_current=" + ps_current +
                ", lat='" + lat + '\'' +
                ", lng='" + lng + '\'' +
                ", price='" + price + '\'' +
                '}';
    }
}
