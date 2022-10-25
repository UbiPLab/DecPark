package TokenCompute;


import Leaf.Param;
import PrefixEncoding.IndexElementEncoding;
import Leaf.LocationEncoding;
import javafx.util.Pair;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
;
public class User {
    /*token compute*/
    int bitsize0 = 6;  // 求id前缀族时用的size
    int bitsize = 7;  // 求区域编号前缀族用的size
    int id;//查找的id
    int  n = 2000;  // 数据的长度2000 - 10000(间隔2000)
    double lat;//所在纬度
    double lng;//所在精度
    String K0;
    byte[] userid_hash;

    public byte[] getUserid_hash() throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("sha-256");
        return instance.digest((String.valueOf(id)+String.valueOf(lat)+String.valueOf(lng)).getBytes());
    }

    public User(int id, int n, double lat, double lng, String K0) {
        this.id = id;
        this.n = n;
        this.lat = lat;
        this.lng = lng;
        this.K0 = K0;
    }

    public  ArrayList<String> R(){
        int  slength = IndexElementEncoding.range(bitsize0, 1, n).length;
        ArrayList<String> S = new ArrayList<String>();
        if (id % 2 == 0){
            for (int i = 0; i < slength; i++){
                String [] temp =  IndexElementEncoding.range(bitsize0, id + 2 * i, id + 2 * i + 1);
                Collections.addAll(S, temp);
            }
        }else {
            for (int i = 0; i < slength; i++){
                String [] temp =  IndexElementEncoding.range(bitsize0, id + 2 * i -  1, id + 2 * i);
                Collections.addAll(S, temp);
            }
        }
        return S;
    }
    public  ArrayList<String> EXP(){
        int  gi4 = LocationEncoding.generalID(lat, lng, 8, 8);
        ArrayList<String> result = new ArrayList<>();
        if (gi4 == 1){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4, gi4 + 2);  // 1-4
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 + 8, gi4 + 10);   // 9-11
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 16, gi4 + 18);  // 17 -19
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (gi4 == 8){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 2, gi4);  // 6-8
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 + 6, gi4 + 8);  // 14-16
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 14, gi4 + 16);  // 22-24
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (gi4 == 57){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4, gi4 + 2);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 - 8, gi4 - 6);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 - 16, gi4 - 14);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (gi4 == 64){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 2, gi4);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 - 10, gi4 - 8);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 - 18, gi4 - 16);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (gi4 >= 2 && gi4 <= 7){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 1, gi4 + 1);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 + 7, gi4 + 9);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 15, gi4 + 17);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (gi4 >= 58 && gi4 <= 63){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 1, gi4 + 1);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 - 9, gi4 - 7);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 - 17, gi4 - 15);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (judge_contains(range(9, 50, 8), gi4)){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 8, gi4 - 6);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4, gi4 + 2);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 8, gi4 + 10);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else if (judge_contains(range(16, 57, 8), gi4)){
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 10, gi4 - 8);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 - 2, gi4);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 6, gi4 + 8);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }else {
            String[]  n1 = IndexElementEncoding.range(bitsize, gi4 - 9, gi4 - 7);
            String[]  n2 = IndexElementEncoding.range(bitsize, gi4 - 1, gi4 + 1);
            String[]  n3 = IndexElementEncoding.range(bitsize, gi4 + 7, gi4 + 9);
            Collections.addAll(result, n1);
            Collections.addAll(result, n2);
            Collections.addAll(result, n3);
        }
        return result;
    }
    public ArrayList<String> get_T1() throws NoSuchAlgorithmException {
        ArrayList<String> LC = new ArrayList<>();
        MessageDigest mdinstance = MessageDigest.getInstance("sha-256");
        int gi2 = LocationEncoding.generalID(lat, lng, 2, 2);
        byte[] outbytes = mdinstance.digest((gi2 + K0).getBytes());
        String outhex = byte2Hex(outbytes);
        String  lc2 = "2" + outhex;
        int gi3 = LocationEncoding.generalID(lat, lng, 4, 4);
        byte[] outbytes2 = mdinstance.digest((gi3 + K0).getBytes());
        String outhex2 = byte2Hex(outbytes2);
        String  lc3 = "3" + outhex2;
        LC.add(lc2);
        LC.add(lc3);
        return LC;
    }
    public ArrayList<String> get_T2(){
        ArrayList<String> R_list = R();
        ArrayList<String> grid_list = EXP();
        ArrayList<String> MC = new ArrayList<>();
        for (int i = 0; i < grid_list.size(); i++) {
            for (int j =0; j < R_list.size(); j++){
                MC.add("4" + grid_list.get(i) + R_list.get(j));
            }
        }
        return MC;
    }
    public ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> T1_raw_locations(ArrayList<String> t1) throws NoSuchAlgorithmException {
        MessageDigest mdinstance = MessageDigest.getInstance("sha-256");
        MessageDigest H = MessageDigest.getInstance("sha-384");
        String[] keylist = Param.keylist;
        int ibflength = Param.ibflength;
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_list = new ArrayList<>();
        for (String s : t1) {
            ArrayList<Pair<BigInteger, BigInteger>> pairs = new ArrayList<>();
            for (int i = 0; i < keylist.length - 1; i++) {
                byte[] outbytes = H.digest((s + keylist[i]).getBytes());
                BigInteger bi = new BigInteger(1, outbytes);
                int twinindex = bi.mod(BigInteger.valueOf(ibflength)).intValue();
                BigInteger twinindex_B = BigInteger.valueOf(twinindex);
                byte[] hkp1 = H.digest((String.valueOf(twinindex)+keylist[keylist.length-1]).getBytes());//h_k+1
//                BigInteger hkp1bi = new BigInteger(1, hkp1);//这是hkb+1(twinindex)
                BigInteger hkp1bi = new BigInteger(1, hkp1).mod(new BigInteger("11579208923731619542357098500868790785326998466564056403945758400791312963993"));//这是hkb+1(twinindex)
                Pair<BigInteger, BigInteger> pair = new Pair<>(twinindex_B, hkp1bi);
                pairs.add(pair);
            }
            t1_list.add(pairs);
        }
        return t1_list;
    }

public HashMap<String,twinAndhkp> get_token_map(ArrayList<String> t1, ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations){
    HashMap<String,twinAndhkp> token1_map=new HashMap<String,twinAndhkp>();
    for (int i = 0; i < t1.size(); i++) {
        String token1_value = t1.get(i);
        ArrayList<Pair<BigInteger, BigInteger>> pair_list = t1_raw_locations.get(i);
        List<BigInteger> twinindex_list = new ArrayList<>();
        List<BigInteger> hkpbi_list= new ArrayList<>();
        for (int j = 0; j < pair_list.size(); j++) {
            Pair<BigInteger, BigInteger> pair = pair_list.get(j);
            BigInteger twindex = pair.getKey();
            BigInteger hkpbi = pair.getValue();
            twinindex_list.add(twindex);
            hkpbi_list.add(hkpbi);
        }
        twinAndhkp twinAndhkp = new twinAndhkp(twinindex_list, hkpbi_list);
        token1_map.put(token1_value,twinAndhkp);
    }
    return token1_map;
}


    public  String byte2Hex(byte[] bytes){
        StringBuffer stringBuffer = new StringBuffer();
        String temp = null;
        for (int i=0;i<bytes.length;i++){
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length()==1){
                stringBuffer.append("0");
            }
            stringBuffer.append(temp);
        }
        return stringBuffer.toString();
    }










    public  int[] range(int from, int to, int step) {
        if(step == 0)    //步长为0非法
            throw new IllegalArgumentException(String.valueOf(step));
        int[] sequence = null;
        if(!(from<to ^ step>0)) {    //递增序列则步长必须为正数，反之亦然
            sequence = new int[(int) Math.ceil((to - from) * 1.0 / step)];    //预算长度
            for (int i = 0, len = sequence.length; i < len; from += step)
                sequence[i++] = from;
        } else
            sequence = new int[0];
        return sequence;
    }
    public  boolean judge_contains(int[] a, int b){
        for (int i =0; i < a.length; i++){
            if (a[i] == b){return true;}
        }
        return false;
    }







}
