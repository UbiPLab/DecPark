package TokenCompute;

import Leaf.Leafhandle;
import Leaf.Param;
import PrefixEncoding.IndexElementEncoding;
import javafx.util.Pair;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class TestCompute {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        double lat = 34.0550558;
        double lng = -118.2448534;
        User user = new User(1,Param.data_number,lat,lng, Param.K0);
        ArrayList<String> t1 = user.get_T1();
        ArrayList<String> t2 = user.get_T2();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);
        System.out.println(t1_raw_locations);
        System.out.println(t2_raw_locations);
        HashMap<String, twinAndhkp> token1_map = user.get_token_map(t1, t1_raw_locations);
        HashMap<String, twinAndhkp> token2_map = user.get_token_map(t2, t2_raw_locations);

        for (Map.Entry<String, twinAndhkp> entry : token1_map.entrySet()) {
            System.out.println(entry.getKey());
            System.out.println(entry.getValue().twinindex_list);
            System.out.println(entry.getValue().hkpb1_list);
        }
        for (Map.Entry<String, twinAndhkp> entry : token2_map.entrySet()) {
            System.out.println(entry.getKey());
            System.out.println(entry.getValue().twinindex_list);
            System.out.println(entry.getValue().hkpb1_list);
        }




    }
}
