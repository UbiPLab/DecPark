package Leaf;

import PrefixEncoding.IndexElementEncoding;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;

public class Leafhandle {
   static int bitsize0 ;
   static int bitsize ;
    static {
        bitsize = 7;
        bitsize0 = 6;
    }
    public static ArrayList<String> get_Prefixs(int id, double lat, double lng, String K0) throws Exception {
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
        int gi4 = LocationEncoding.generalID(lat, lng, 8, 8);
        String[] PF1 = IndexElementEncoding.prefix(bitsize, gi4);
        String[] PF2 = IndexElementEncoding.prefix(bitsize0, id);
        for (String pf1:PF1){
            for (String pf2: PF2){
                LC.add("4" + pf1 + pf2);
            }
        }
        return LC;
    }

    public static String byte2Hex(byte[] bytes){
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
    public static byte[] toByteArray(String s) {
        if (s.startsWith("0x")){
            s = s.substring(2);
        }
        return DatatypeConverter.parseHexBinary(s);
    }
    public static String Biginteger_to_Hex64(BigInteger num){
        String str = new BigInteger(String.valueOf(num), 10).toString(16);
        StringBuilder a = new StringBuilder("0x");
        if (str.length()< 64){
            StringBuilder tem = new StringBuilder();
            for (int i = 0; i < 64 - str.length(); i++) {
                tem.append(0);
            }
            a.append(tem);
        }
        a.append(str);
        return a.toString();
    }
}
