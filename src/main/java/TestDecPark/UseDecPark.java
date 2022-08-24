package TestDecPark;
import Leaf.Param;
import org.apache.commons.collections4.CollectionUtils;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.core.methods.response.EthBlock.TransactionResult;
import IBF.IBtree;
import IBF.IBtreeConstruction;
import Leaf.AESUtils;
import TokenCompute.User;
import TokenCompute.twinAndhkp;
import Web3.User_Result;
import javafx.util.Pair;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tuples.generated.Tuple14;
import org.web3j.tuples.generated.Tuple2;
import org.web3j.tuples.generated.Tuple4;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.utils.Numeric;
import utilits.CommonUtilit;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

import static IBF.IBtreeConstruction.addBytes;

public class UseDecPark {
    private static String netWorkUrl = "http://localhost:8545";
    //    private static String credentialsAddress = "f8a25eb5050a58c9dd4316c5a8f5c72f993e77ebbdb06cd80ec0981aa229549a";
    private static String privatekey ;

    private static String contractAddress = "0xD86C56E4f612987332ED8Fb33b07eE405111C099";
    public static DecPark contract;
    public static Web3j web3;

    static {
        Concontract();
    }

    public static void Concontract() {
        try {

            web3 = Web3j.build(new HttpService(netWorkUrl));
            privatekey = exportPrivateKey("src/main/resources/keystore/UTC--2022-08-15T12-56-10.246215000Z--7ac8300a50b3b47b3e278c7d417ee844918272e6", "123");
//            privatekey = exportPrivateKey("src/main/resources/keystore/UTC--2022-08-17T07-14-49.119451100Z--fc07321b4e8caf11ae4262f5e827a88d7604ce05", "123");
            Credentials credentials = Credentials.create(privatekey);
            BigInteger gasPrice = web3.ethGasPrice().send().getGasPrice();
            BigInteger gasLimit = BigInteger.valueOf(800000000L);
            long pollingInterval = 3000; // 3 seconds
            FastRawTransactionManager fastRawTxMgr = new FastRawTransactionManager(web3, credentials, new PollingTransactionReceiptProcessor(web3, pollingInterval, 40));
            contract = DecPark.load(contractAddress, web3, fastRawTxMgr, gasPrice, gasLimit);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

//    public static void CreatTree(BigInteger treeindex, ArrayList<IBtree> IBtree_list, int nThread) throws Exception {
//        CreatThread(treeindex, IBtree_list, nThread);
//    }

    public synchronized static <T> void CreatTree(BigInteger treeindex, ArrayList<IBtree> IBtree_list, int nThread) throws Exception {
        if (CollectionUtils.isEmpty(IBtree_list) || nThread <= 0) {
            return;
        }
        Semaphore semaphore = new Semaphore(nThread);
        ExecutorService executorService = Executors.newFixedThreadPool(nThread);
        for (int i = 1; i < IBtree_list.size(); i++) {
            try {
                semaphore.acquire();
                int finalI = i;
                IBtree iBtree = IBtree_list.get(finalI);
                executorService.execute(() -> {

                    try {
                        BigInteger rb = BigInteger.valueOf(iBtree.rb);
                        BigInteger node_index = BigInteger.valueOf(iBtree.index);
                        BigInteger parent = BigInteger.valueOf(iBtree.parent);
                        BigInteger lc = BigInteger.valueOf(iBtree.lc);
                        BigInteger rc = BigInteger.valueOf(iBtree.rc);
                        BigInteger brother = BigInteger.valueOf(iBtree.brother);
                        System.out.println(contract.PushNode(treeindex, node_index, rb, iBtree.loc, iBtree.price, iBtree.ps, brother,iBtree.HV, parent, lc, rc).send().getTransactionHash());
                        System.out.println(contract.PushIBF_top(treeindex, node_index,iBtree.ibf_top_location ).send().getTransactionHash());
                        System.out.println(contract.PushIBF2_bottom(treeindex, node_index,iBtree.ibf_bottom_location ).send().getTransactionHash());
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (ExecutionException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    semaphore.release();
                });
            } catch (InterruptedException e) {

            }
            Thread.sleep(1000);
        }

        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
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






    public static void  Query(byte[] driver,BigInteger k){

        try {
            System.out.println("driver"+driver+"queryhash:");
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
            Tuple14<BigInteger, String, byte[], BigInteger, BigInteger, BigInteger, byte[], byte[], BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger> query_result = contract.R(driver,BigInteger.valueOf(i)).send();
            long start = System.currentTimeMillis();
            BigInteger ps_pre = query_result.component9();
            BigInteger ps_current = query_result.component10();
            BigInteger node_index = query_result.component6();
            byte[] loc_encrypted = query_result.component7();
            byte[] price_encrypted = query_result.component8();
            byte[] plainBytes = AESUtils.decrypt(loc_encrypted, Aeskey.getBytes());
            String loc_String = new String(plainBytes);
            String[] lat_and_lng = loc_String.split(",");
            String lat = lat_and_lng[0];
            String lng = lat_and_lng[1];
            byte[] plainBytes2 = AESUtils.decrypt(price_encrypted, Aeskey.getBytes());
            String price_String = new String(plainBytes2);
            String[] id_and_price = price_String.split(",");
            String id = id_and_price[1];
            String price = id_and_price[0];
            BigInteger no_l = new BigInteger(id);
            User_Result sigle_user_result = new User_Result(no_l, ps_pre, ps_current, lat, lng, price,node_index);
            query_decrpted.add(sigle_user_result);
            long end = System.currentTimeMillis();
            System.out.println((end - start)+"ms");
        }
        return query_decrpted;
    }
    public static ArrayList<Poc1> get_Poc_1(byte[] driver,HashMap<BigInteger,ArrayList<IBtree>> Tree_map) throws Exception {
        Tuple4<BigInteger, BigInteger, BigInteger, BigInteger> lengths = contract.get_length(driver, driver).send();
        BigInteger Poc1_length = lengths.component2();
        ArrayList<Poc1> poc1_list = new ArrayList<Poc1>();
        for (int i = 0; i < Poc1_length.intValue(); i++) {
            Tuple14<BigInteger, String, byte[], BigInteger, BigInteger, BigInteger, byte[], byte[], BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger> query_result = contract.Poc1_M(driver, BigInteger.valueOf(i)).send();
            BigInteger treeindex = query_result.component11();
            ArrayList<IBtree> TreeNodeList = Tree_map.get(treeindex);
            BigInteger node_index = query_result.component6();
            IBtree treenode = TreeNodeList.get(node_index.intValue());
            Poc1 poc1 = new Poc1(treenode.index, treenode.rb, treenode.ibf, treenode.lc, treenode.rc);
            poc1_list.add(poc1);
        }
        return poc1_list;
    }
    public static boolean verify_Poc1(User user, ArrayList<Poc1> Poc1_list) throws NoSuchAlgorithmException {
        long start = System.currentTimeMillis();
        ArrayList<String> t1 = user.get_T1();
        ArrayList<String> t2 = user.get_T2();
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
        ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);
        for (int i = 0; i < Poc1_list.size(); i++) {
            Poc1 poc1 = Poc1_list.get(i);
            if (poc1.lc==0&&poc1.rc==0){
                if (!IBtreeConstruction.leafcomon(poc1.ibf, t2_raw_locations)){
                    return false;
                }
            }else {
                if (IBtreeConstruction.hascomon(poc1.ibf, t1_raw_locations)){
                    return false;
                }
            }
        }
        long end = System.currentTimeMillis();
        System.out.println("verify Poc1:"+(end-start)+"ms");
        return true;
    }
    public static ArrayList<ArrayList<Poc2>> get_Poc_2(byte[] driver) throws Exception {
        Tuple4<BigInteger, BigInteger, BigInteger, BigInteger> lengths = contract.get_length(driver, driver).send();
        BigInteger R_length = lengths.component1();
        ArrayList<ArrayList<Poc2>> all_poc2_list = new ArrayList<ArrayList<Poc2>>();
        for (int i = 0; i < R_length.intValue(); i++) {
            Tuple14<BigInteger, String, byte[], BigInteger, BigInteger, BigInteger, byte[], byte[], BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger> query_result = contract.R(driver,BigInteger.valueOf(i)).send();
            byte[] node_hash = query_result.component3();
            BigInteger treeindex = query_result.component11();
            lengths = contract.get_length(driver, node_hash).send();
            BigInteger Poc2_length = lengths.component3();
            ArrayList<Poc2> Poc2_list = new ArrayList<Poc2>();
            for (int j = 0; j < Poc2_length.intValue(); j++) {
                Tuple2<BigInteger, byte[]> Poc2_Tuple = contract.Poc2_M(node_hash, BigInteger.valueOf(j)).send();
                BigInteger location = Poc2_Tuple.component1();
                byte[] HV = Poc2_Tuple.component2();
                Poc2 Poc2 = new Poc2(location, HV, treeindex.intValue());
                Poc2_list.add(Poc2);
            }
            all_poc2_list.add(Poc2_list);
        }
        return all_poc2_list;
    }
    public static boolean verify_Poc2(byte[] driver,ArrayList<ArrayList<Poc2>> all_Poc2_list,HashMap<BigInteger,ArrayList<IBtree>> Tree_map) throws Exception {
        int count = 0;
        Tuple4<BigInteger, BigInteger, BigInteger, BigInteger> lengths = contract.get_length(driver, driver).send();
        long start = System.currentTimeMillis();
        BigInteger R_length = lengths.component1();
        for (int i = 0; i < all_Poc2_list.size(); i++) {
            ArrayList<Poc2> poc2_list = all_Poc2_list.get(i);
            MessageDigest mdinstance = MessageDigest.getInstance("sha-256");
            int treeindex = poc2_list.get(0).treeindex;
            String randomString = CommonUtilit.getRandomString(200);
            byte[] out = mdinstance.digest(addBytes(poc2_list.get(0).HV, poc2_list.get(1).HV));
            for (int j = 2; j < poc2_list.size(); j++) {
                if (poc2_list.get(j).location.intValue()==0){
                    out = mdinstance.digest(addBytes(poc2_list.get(j).HV, out));
                }else {
                    out = mdinstance.digest(addBytes(out, poc2_list.get(j).HV));
                }
            }
            if (out == Tree_map.get(BigInteger.valueOf(treeindex)).get(1).HV){
                return false;
            }else {
                count += 1;
            }
        }
        long end = System.currentTimeMillis();
        System.out.println("verify Poc2:"+(end-start)+"ms");
        if (count == R_length.intValue()){
            return true;
        }else {
            return false;
        }
    }
    public static boolean verify_B1_B2(BigInteger pl, byte[] driver,BigInteger k,String Aeskey,BigInteger start_block, BigInteger end_block) throws Exception {
        int B1 = 0;
        int B2 = 0;
        long start = System.currentTimeMillis();
        for (int i = start_block.intValue();i< end_block.intValue()+1;i++){

            EthBlock.Block latestBlock2 = web3.ethGetBlockByNumber(DefaultBlockParameter.valueOf(new BigInteger(String.valueOf(i))), true).send().getBlock();

            List<TransactionResult> txlist = latestBlock2.getTransactions();

            for (TransactionResult transactionResult : txlist) {

                EthBlock.TransactionObject transaction = (EthBlock.TransactionObject) transactionResult.get();

                if (transaction.getInput().startsWith("0x027c6c5f")){
                    int pl_number = Integer.parseInt(transaction.getInput().substring(10, 74), 16);
                    if (pl_number == pl.intValue()){
                        B1 +=1;
                    }
                }
                if (transaction.getInput().startsWith("0xa89fd3a5")){
                    int pl_number = Integer.parseInt(transaction.getInput().substring(10, 74), 16);
                    if (pl_number == pl.intValue()){
                        B2 +=1;
                    }
                }
            }
        }
        List<User_Result> R_list = get_R(driver,k,Aeskey);
        int ps_pre = 0;
        int ps_c = 0;
        for (int i1 = 0; i1 < R_list.size(); i1++) {
            if (R_list.get(i1).getNo_l().intValue() == pl.intValue()){
                ps_pre = R_list.get(i1).getPs_pre().intValue();
                ps_c = R_list.get(i1).getPs_current().intValue();
            }
        }
        long end = System.currentTimeMillis();
        System.out.println("verify PoT:"+(end-start)+"ms");
        if (ps_c == ps_pre - B1 + B2){
            return true;
        }else {
            return false;
        }
    }
    public static ArrayList<BigInteger> get_B1_B2(BigInteger start_block, BigInteger end_block) throws Exception {
        int B1 = 0;
        int B2 = 0;
        ArrayList<BigInteger> Blist = new ArrayList<>();
        long start = System.currentTimeMillis();
        for (int i = start_block.intValue();i< end_block.intValue()+1;i++){

            EthBlock.Block latestBlock2 = web3.ethGetBlockByNumber(DefaultBlockParameter.valueOf(new BigInteger(String.valueOf(i))), true).send().getBlock();

            List<TransactionResult> txlist = latestBlock2.getTransactions();

            for (TransactionResult transactionResult : txlist) {

                EthBlock.TransactionObject transaction = (EthBlock.TransactionObject) transactionResult.get();

                if (transaction.getInput().startsWith("0x027c6c5f")){
                        B1 +=1;
                }
                if (transaction.getInput().startsWith("0xa89fd3a5")){
                        B2 +=1;
                }
            }
        }
        long end = System.currentTimeMillis();
        Blist.add(BigInteger.valueOf(B1));
        Blist.add(BigInteger.valueOf(B2));
        System.out.println("B1，B2:"+(end-start)+"ms");
        return Blist;
    }
    public synchronized static <T> void ParkingThread(BigInteger pl, byte[] driver, int npl ,int nThread) throws Exception {
        Semaphore semaphore = new Semaphore(nThread);
        ExecutorService executorService = Executors.newFixedThreadPool(nThread);
        for (int i = 0; i < npl/2; i++) {
            try {
                semaphore.acquire();
                executorService.execute(() -> {

                    try {
                        Parking(pl,driver);
                        Departing(pl,driver);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (ExecutionException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    semaphore.release();
                });
            } catch (InterruptedException e) {

            }
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
        }
    }
    public static void Parking(BigInteger pl, byte[] driver) throws Exception {
        String transactionHash = contract.Parking(pl, driver).send().getTransactionHash();
    }
    public static void Departing(BigInteger pl, byte[] driver) throws Exception {
        String transactionHash = contract.Departing(pl, driver).send().getTransactionHash();
    }


    public static void Update() throws Exception {
        String transactionHash = contract.update().send().getTransactionHash();
    }
    public static String exportPrivateKey(String keystorePath, String password) {
        try {
            Credentials credentials = WalletUtils.loadCredentials(password, keystorePath);
            BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
            return privateKey.toString(16);
        } catch (IOException | CipherException e) {
            e.printStackTrace();
        }
        return "";
    }
    public static BigInteger get_current_block() throws IOException {
        return web3.ethBlockNumber().send().getBlockNumber();
    }



}
