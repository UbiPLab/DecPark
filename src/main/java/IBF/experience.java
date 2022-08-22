package IBF;


import Leaf.Leafhandle;
import Leaf.PLs;
import Leaf.Param;
import TokenCompute.User;
import javafx.util.Pair;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class experience {

    public static void main(String[] args) throws Exception {
        MessageDigest mdinstance = MessageDigest.getInstance("sha-256");

        double lat = 34.0550558;
        double lng = -118.2448534;
        User user = new User(5,Param.data_number,lat,lng, Param.K0);
        ArrayList<String> t1 = user.get_T1();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
        for (int i = 0; i < t1_raw_locations.size(); i++) {
            
        }

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

}

