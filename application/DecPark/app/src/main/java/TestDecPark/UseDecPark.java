package TestDecPark;

import android.content.SharedPreferences;

import androidx.appcompat.app.AppCompatActivity;

import CommonUtility.AESUtils3;
import TokenCompute.twinAndhkp;
import Web3.User_Result;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tuples.generated.Tuple14;
import org.web3j.tuples.generated.Tuple4;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import java.math.BigInteger;
import java.util.*;

public class UseDecPark  {
    private static String netWorkUrl = "http://114.213.210.166:8545";//测试链地址
    private static String privatekey;//账户私钥
    private static String contractAddress = "0xc0b5115e04E0b7F55c5cD7500711eE2d9BfB76AE";//合约地址
    public static DecPark contract;
    public static Web3j web3;

    static {
        Concontract();
    }

    public static void Concontract() {
        try {
            //连接对应的以太坊
            web3 = Web3j.build(new HttpService(netWorkUrl));
            privatekey = "890bc3a1ee6944465fc8432c45e251c9b0110ccf78880dc6de5dd310abc00af7";
//            privatekey = exportPrivateKey("src/main/resources/keystore/UTC--2022-08-17T07-14-49.119451100Z--fc07321b4e8caf11ae4262f5e827a88d7604ce05", "123");
            Credentials credentials = Credentials.create(privatekey);
            BigInteger gasPrice = web3.ethGasPrice().send().getGasPrice();
            BigInteger gasLimit = BigInteger.valueOf(80000000L);
            long pollingInterval = 1000;
            FastRawTransactionManager fastRawTxMgr = new FastRawTransactionManager(web3, credentials, new PollingTransactionReceiptProcessor(web3, pollingInterval, 40));
            contract = DecPark.load(contractAddress, web3, fastRawTxMgr, gasPrice, gasLimit);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public synchronized static <T> void PushToken1(byte[] driver, HashMap<String, twinAndhkp> token_map) throws Exception {

        for (Map.Entry<String, twinAndhkp> entry : token_map.entrySet()) {
            String token1_value = entry.getKey();
            List<BigInteger> twinindex_list = entry.getValue().twinindex_list;
            List<BigInteger> hkpb1_list = entry.getValue().hkpb1_list;
            System.out.println(contract.PushToken1(driver, token1_value, twinindex_list, hkpb1_list).sendAsync());
        }
    }

    public synchronized static <T> void PushToken2(byte[] driver, HashMap<String, twinAndhkp> token_map) throws Exception {
        for (Map.Entry<String, twinAndhkp> entry : token_map.entrySet()) {
            String token2_value = entry.getKey();
            List<BigInteger> twinindex_list = entry.getValue().twinindex_list;
            List<BigInteger> hkpb1_list = entry.getValue().hkpb1_list;
            System.out.println(contract.PushToken2(driver, token2_value, twinindex_list, hkpb1_list).sendAsync());
        }
    }


    public static void Query(byte[] driver, BigInteger k) {

        try {
            System.out.println("司机" + driver + "查询hash:");
            String transactionHash = contract.Query(driver, k).send().getTransactionHash();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static List<User_Result> get_R(byte[] driver, BigInteger k, String Aeskey) throws Exception {
        List<User_Result> query_decrpted = new ArrayList<>();
        Tuple4<BigInteger, BigInteger, BigInteger, BigInteger> lengths = contract.get_length(driver, driver).send();
        BigInteger R_length = lengths.component1();
        for (int i = 0; i < R_length.intValue(); i++) {
            Tuple14<BigInteger, String, byte[], BigInteger, BigInteger, BigInteger, byte[], byte[], BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger> query_result = contract.R(driver, BigInteger.valueOf(i)).send();
            BigInteger ps_pre = query_result.component9();
            BigInteger ps_current = query_result.component10();
            BigInteger node_index = query_result.component6();
            byte[] loc_encrypted = query_result.component7();
            byte[] price_encrypted = query_result.component8();

            byte[] plainBytes = AESUtils3.decrypt(loc_encrypted, Aeskey);
            String loc_String = new String(plainBytes);
            String[] lat_and_lng = loc_String.split(",");
            String lat = lat_and_lng[0];
            String lng = lat_and_lng[1];
            byte[] plainBytes2 = AESUtils3.decrypt(price_encrypted, Aeskey);
            String price_String = new String(plainBytes2);
            String[] id_and_price = price_String.split(",");
            String id = id_and_price[1];
            String price = id_and_price[0];
            BigInteger no_l = new BigInteger(id);
            User_Result sigle_user_result = new User_Result(no_l, ps_pre, ps_current, lat, lng, price, node_index);
            query_decrpted.add(sigle_user_result);
        }
        return query_decrpted;
    }


    public static void Parking(BigInteger pl, byte[] driver) throws Exception {
//        System.out.println("司机"+driver+"停车在" + pl.intValue()+"号停车场");
        String transactionHash = contract.Parking(pl, driver).send().getTransactionHash();
    }

    public static void Departing(BigInteger pl, byte[] driver) throws Exception {
//        System.out.println("司机"+driver+"离开" + pl.intValue()+"号停车场");
        String transactionHash = contract.Departing(pl, driver).send().getTransactionHash();
    }


    public static void Update() throws Exception {
        String transactionHash = contract.update().send().getTransactionHash();
    }


}
