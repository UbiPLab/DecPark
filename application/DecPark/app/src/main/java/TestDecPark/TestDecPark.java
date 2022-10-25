package TestDecPark;

import Leaf.Param;
import TokenCompute.User;
import TokenCompute.twinAndhkp;
import Web3.User_Result;
import javafx.util.Pair;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.*;

public class TestDecPark {
    public static void main(String[] args) throws Exception {
        double lat = 39.92420959472657;
        double lng = 116.39786529541014;
        //用户计算Token
        User user = new User(5,Param.data_number,lat,lng, Param.K0);
        byte[] driver1 = user.getUserid_hash();
        System.out.println("用户十六进制字符串:"+Numeric.toHexString(user.getUserid_hash()));

        ArrayList<String> t1 = user.get_T1();
        ArrayList<String> t2 = user.get_T2();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);

        HashMap<String, twinAndhkp> token1_map = user.get_token_map(t1, t1_raw_locations);
        HashMap<String, twinAndhkp> token2_map = user.get_token_map(t2, t2_raw_locations);


        BigInteger k = new BigInteger("5");
        BigInteger treeindex = new BigInteger("1");
        UseDecPark.PushToken1(driver1,token1_map);

//        //查询并得到结果
//        UseDecPark.Query(driver1,k);
//        List<User_Result> R = UseDecPark.get_R(user.getUserid_hash(), new BigInteger("5"), Param.AESkey);
//        System.out.println(R);


    }


}
