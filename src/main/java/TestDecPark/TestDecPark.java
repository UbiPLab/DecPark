package TestDecPark;
import IBF.IBtree;
import IBF.IBtreeConstruction;
import Leaf.Leafhandle;
import Leaf.PLs;
import Leaf.Param;
import TokenCompute.User;
import TokenCompute.twinAndhkp;
import javafx.util.Pair;
import java.math.BigInteger;
import java.util.*;

public class TestDecPark {
    public static void main(String[] args) throws Exception {
        double lat = 34.0550558;
        double lng = -118.2448534;
        ArrayList<PLs> pl_list = PLs.parseInfoFromInputFile("src/main/resources/LosAngelParkingLots.xlsx", 0,14);
        String[][] prefixs = new String[pl_list.size()][];
        PLs[] data    = new PLs[pl_list.size()];
        for (int i = 0; i < pl_list.size(); i++) {
            PLs pl = pl_list.get(i);
            ArrayList<String> t1 = Leafhandle.get_Prefixs(pl.getId(), pl.getLat(), pl.getLng(), Param.K0);
            String[] str = t1.toArray(new String[t1.size()]);
            prefixs[i] = str;
            data[i]  = pl;
        }

        //Creat Tree
        IBtreeConstruction iBtreeConstruction = new IBtreeConstruction();
        IBtree tr = iBtreeConstruction.CreateTree(prefixs, data, Param.keylist);

        iBtreeConstruction.initTreeNode(tr,Param.keylist,Param.rb_list);

        //User compute Token
        User user = new User(5,Param.data_number,lat,lng, Param.K0);
        User user2 = new User(6,Param.data_number,lat,lng, Param.K0);
        User user3 = new User(7,Param.data_number,lat,lng, Param.K0);
        byte[] driver1 = user.getUserid_hash();
        byte[] driver2 = user2.getUserid_hash();
        ArrayList<String> t1 = user.get_T1();
        ArrayList<String> t2 = user.get_T2();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);
        HashMap<String, twinAndhkp> token1_map = user.get_token_map(t1, t1_raw_locations);
        HashMap<String, twinAndhkp> token2_map = user.get_token_map(t2, t2_raw_locations);
        ArrayList<String> t11 = user2.get_T1();
        ArrayList<String> t22 = user2.get_T2();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t11_raw_locations = user2.T1_raw_locations(t1);
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t22_raw_locations = user2.T1_raw_locations(t2);
        HashMap<String, twinAndhkp> token11_map = user.get_token_map(t11, t11_raw_locations);
        HashMap<String, twinAndhkp> token22_map = user.get_token_map(t22, t22_raw_locations);

        //Sequential storage
        ArrayList<IBtree> iBtrees = iBtreeConstruction.PrintFromTopToBottom(tr);
        HashMap<BigInteger,ArrayList<IBtree>> Tree_map = new HashMap<>();
        BigInteger k = new BigInteger("5");
        BigInteger treeindex = new BigInteger("1");
        Tree_map.put(treeindex,iBtrees);

//        Creat Tree in smart contract
        UseDecPark.CreatTree(treeindex,iBtrees,29);
//        Push token in smart contract
        UseDecPark.PushToken1(driver1,token1_map);
        UseDecPark.PushToken2(driver1,token2_map);
        UseDecPark.PushToken1(driver2,token11_map);
        UseDecPark.PushToken2(driver2,token22_map);


////        simulate driver2 parking and compute B1 and B2
//        BigInteger start_block = UseDecPark.get_current_block();
//        UseDecPark.Update();
//        UseDecPark.Query(driver2,k);
//        BigInteger pl = new BigInteger("22");
//        UseDecPark.ParkingThread(pl,driver2,50,20);
//        BigInteger end_block = UseDecPark.get_current_block();
//        System.out.println(start_block);
//        System.out.println(end_block);
//        ArrayList<BigInteger> b1_b2 = UseDecPark.get_B1_B2(start_block, end_block);
//        System.out.println(b1_b2);

//
        //driver1 query and verify result
//        UseDecPark.Query(driver1,k);
//        List<User_Result> R = UseDecPark.get_R(user.getUserid_hash(), new BigInteger("5"), Param.AESkey);
//        System.out.println(R);
//        ArrayList<Poc1> poc_1_list = UseDecPark.get_Poc_1(user.getUserid_hash(), Tree_map);
//
//        ArrayList<ArrayList<Poc2>> all_poc_2_list = UseDecPark.get_Poc_2(user.getUserid_hash());
//        System.out.println(poc_1_list);
//        UseDecPark.verify_Poc1(user, poc_1_list);
//        UseDecPark.verify_Poc2(user.getUserid_hash(), all_poc_2_list, Tree_map);
////        verify POC_3
//        boolean verify_result3 = UseDecPark.verify_B1_B2(pl, driver2,k, Param.AESkey, start_block, end_block);
//        System.out.println(verify_result3);

    }


}
