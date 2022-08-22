package IBF;

import Leaf.Leafhandle;
import TokenCompute.T1;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class IBFConstruction {


    public static IBF IndistinguishableBloomFilter(int ibfLength, int rb, String[] keylist) throws NoSuchAlgorithmException {
        IBF ibf = new IBF();
        ibf.length = ibfLength;
        ibf.Keylist = keylist;
        ibf.twinlist = new byte[2][ibfLength];
        ibf.rb = rb;
        ibf.mdinstance = MessageDigest.getInstance("sha-256");
        ibf.H = MessageDigest.getInstance("sha-384");
        return ibf;
    }

    /*
            use  AES  create Secret key
    public static String[] CreateSecretKey(int keylength){
        String[] keylist = new String[keylength];
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance("AES");
            kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256
            for(int i=0;i<keylength;i++) {
                SecretKey sk = kg.generateKey();    //密钥
                byte[] b = sk.getEncoded();     //加密
                String skey=byteToHexString(b); //转换形式
               // System.out.println("第"+i+"个密钥："+skey);
                keylist[i]=skey;                                        //  密钥组 k+1个
            }
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return keylist;
    }

     */
    public static String[] CreateSecretKey(int keylength) {
        String[] keylist = new String[keylength];
        StringBuffer bigstring = new StringBuffer();
        Random random = new Random();
        int length = 1024;
        for (int j = 0; j < keylist.length; j++) {
            for (int i = 0; i < length; i++) {
                bigstring.append(random.nextInt(10));
            }
            keylist[j] = bigstring.toString();
        }
        return keylist;
    }


    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex = Integer.toHexString(bytes[i]);
            if (strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if (strHex.length() < 2) {
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }

    public static String getRandomString(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static String getRandomString2(int length) {
        String str = "0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(10);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }


    public static void showIBF(IBF ibf) {
        int firstline[] = new int[ibf.length];
        int secondline[] = new int[ibf.length];
        byte[] top = ibf.twinlist[0];
        List<BigInteger> top_1_location = new ArrayList<BigInteger>();
        for (int i = 0; i < top.length; i++) {
            if (top[i]==1){
                top_1_location.add(BigInteger.valueOf(i));
            }
        }
        byte[] bottom = ibf.twinlist[1];
        List<BigInteger> bottom_1_location = new ArrayList<BigInteger>();
        for (int i = 0; i < top.length; i++) {
            if (bottom[i]==1){
                bottom_1_location.add(BigInteger.valueOf(i));
            }
        }

        System.out.println("IBF Content: ");
        System.out.println(top_1_location);
        System.out.println(bottom_1_location);
    }

    public static String IBF_value(IBF ibf) {
        byte[] top = ibf.twinlist[0];
        byte[] bottom = ibf.twinlist[1];
        StringBuilder a = new StringBuilder();
        for (int i = 0; i < top.length; i++) {
           a.append(top[i]);
        }
        for (int i = 0; i < bottom.length; i++) {
            a.append(bottom[i]);
        }
        return a.toString();
    }

    public static void insert(IBF ibf, String data) {
        for (int i = 0; i < ibf.Keylist.length - 1; i++) {
            byte[] outbytes = ibf.H.digest((data + ibf.Keylist[i]).getBytes());
            BigInteger bi = new BigInteger(1, outbytes);
            int twinindex = bi.mod(BigInteger.valueOf(ibf.length)).intValue();
            byte[] hkp1 = ibf.H.digest((String.valueOf(twinindex)+ibf.Keylist[ibf.Keylist.length-1]).getBytes());//h_k+1
            BigInteger hkp1bi = new BigInteger(1, hkp1).mod(new BigInteger("11579208923731619542357098500868790785326998466564056403945758400791312963993"));//这是hkb+1(twinindex)
            byte[] bytes1 = hash_bytes(hkp1bi, ibf.rb);
            byte[] sha1bytes = ibf.mdinstance.digest(bytes1);//sha1_xor
            int location = new BigInteger(1, sha1bytes).mod(BigInteger.valueOf(2)).intValue();//mod2
            if (location == 0) {
                ibf.twinlist[0][twinindex] = 1;
                ibf.twinlist[1][twinindex] = 0;
            } else {
                ibf.twinlist[1][twinindex] = 1;
                ibf.twinlist[0][twinindex] = 0;
            }
        }
    }
    public static byte[] hash_bytes(BigInteger hkp1bi, int rb){
        BigInteger xor_value = hkp1bi.xor(BigInteger.valueOf(rb));
        String b = Leafhandle.Biginteger_to_Hex64(xor_value);
        byte[] bytes = Leafhandle.toByteArray(b);
        return bytes;
    }
    public static boolean search(IBF ibf, String data) {
        int count =0;
        for (int i = 0; i < ibf.Keylist.length - 1; i++) {
            byte[] outbytes = ibf.H.digest((data + ibf.Keylist[i]).getBytes());
            BigInteger bi = new BigInteger(1, outbytes);
            int twinindex = bi.mod(BigInteger.valueOf(ibf.length)).intValue();
            byte[] hkp1 = ibf.H.digest((String.valueOf(twinindex)+ibf.Keylist[ibf.Keylist.length-1]).getBytes());//h_k+1
            BigInteger hkp1bi = new BigInteger(1, hkp1);
            byte[] sha1bytes = ibf.mdinstance.digest(hkp1bi.xor(BigInteger.valueOf(ibf.rb)).toByteArray());//sha1_xor
            int location = new BigInteger(1, sha1bytes).mod(BigInteger.valueOf(2)).intValue();//mod2
            if (location == 0 && ibf.twinlist[0][twinindex] == 1) {count += 1;}
            if (location == 1 && ibf.twinlist[1][twinindex] == 1){count += 1;}
        }
        if (count == ibf.Keylist.length - 1 ){
            return true;
        }else {
            return false;
        }
    }
    public static   List<BigInteger> get_top_location(IBF ibf){
        byte[] top = ibf.twinlist[0];
        List<BigInteger> top_1_location = new ArrayList<BigInteger>();
        for (int i = 0; i < top.length; i++) {
            if (top[i]==1){
                top_1_location.add(BigInteger.valueOf(i));
            }
        }
        return top_1_location;
    }
    public static   List<BigInteger> get_Bottom_location(IBF ibf){
        byte[] bottom = ibf.twinlist[1];
        List<BigInteger> bottom_1_location = new ArrayList<BigInteger>();
        for (int i = 0; i < bottom.length; i++) {
            if (bottom[i]==1){
                bottom_1_location.add(BigInteger.valueOf(i));
            }
        }
        return bottom_1_location;
    }

    public static byte[] addBytes(byte[] data1, byte[] data2) {
        byte[] data3 = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, data3, 0, data1.length);
        System.arraycopy(data2, 0, data3, data1.length, data2.length);
        return data3;

    }


}




