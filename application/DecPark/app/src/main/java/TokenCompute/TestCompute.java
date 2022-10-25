package TokenCompute;

import Leaf.Param;
import javafx.util.Pair;

import java.math.BigInteger;
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
//        HashMap<String,twinAndhkp> token1_map=new HashMap<String,twinAndhkp>();
//        HashMap<String,twinAndhkp> token2_map=new HashMap<String,twinAndhkp>();
//        for (int i = 0; i < t1.size(); i++) {
//            String token1_value = t1.get(i);
//            ArrayList<Pair<BigInteger, BigInteger>> pair_list = t1_raw_locations.get(i);
//            List<BigInteger> twinindex_list = new ArrayList<>();
//            List<BigInteger> hkpbi_list= new ArrayList<>();
//            for (int j = 0; j < pair_list.size(); j++) {
//                Pair<BigInteger, BigInteger> pair = pair_list.get(j);
//                BigInteger twindex = pair.getKey();
//                BigInteger hkpbi = pair.getValue();
//                twinindex_list.add(twindex);
//                hkpbi_list.add(hkpbi);
//            }
//            twinAndhkp twinAndhkp = new twinAndhkp(twinindex_list, hkpbi_list);
//            token1_map.put(token1_value,twinAndhkp);
//        }
//        for (int i = 0; i < t2.size(); i++) {
//            String token1_value = t2.get(i);
//            ArrayList<Pair<BigInteger, BigInteger>> pair_list = t2_raw_locations.get(i);
//            List<BigInteger> twinindex_list = new ArrayList<>();
//            List<BigInteger> hkpbi_list= new ArrayList<>();
//            for (int j = 0; j < pair_list.size(); j++) {
//                Pair<BigInteger, BigInteger> pair = pair_list.get(j);
//                BigInteger twindex = pair.getKey();
//                BigInteger hkpbi = pair.getValue();
//                twinindex_list.add(twindex);
//                hkpbi_list.add(hkpbi);
//            }
//            twinAndhkp twinAndhkp = new twinAndhkp(twinindex_list, hkpbi_list);
//            token2_map.put(token1_value,twinAndhkp);
//        }
        // 第三种方法，foreach entrySet
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
