package IBF;

import Leaf.AESUtils;
import Leaf.Leafhandle;
import Leaf.PLs;
import Leaf.Param;
import javafx.util.Pair;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.*;

import static IBF.IBFConstruction.hash_bytes;

public class IBtreeConstruction {

    private int count = 0;
    private int count2 = 0;
    public static List<BigInteger> twindex_list = new ArrayList<BigInteger>();
    public static List<BigInteger> hkp1bi_list = new ArrayList<BigInteger>();

    public IBtree CreateTree(String[][] root, PLs[] pl_list, String[] keylist) throws NoSuchAlgorithmException {
        IBtree treeNode = null;
        if (root.length == 0) {
            return treeNode;
        }
        if (root.length == 1) {
            treeNode = new IBtree();
            treeNode.prefixs = root;
            treeNode.pl_data = pl_list;
            treeNode.height = 1;
            return treeNode;
        } else {
            int mid = root.length / 2;
            int mid_2 = pl_list.length / 2;
            int little = root.length % 2;
            int little_2 = pl_list.length % 2;
            treeNode = new IBtree();
            treeNode.prefixs = root;
            treeNode.pl_data = pl_list;
            treeNode.height = (Math.ceil(Math.log(root.length) / Math.log(2))) + 1;
            String[][] leftNums = new String[mid + little][root[0].length];
            PLs[] leftpls = new PLs[mid_2 + little_2];
            for (int i = 0; i < leftNums.length; i++) {
                for (int j = 0; j < root[0].length; j++) {
                    leftNums[i][j] = root[i][j];
                }
            }
            for (int i = 0; i < leftpls.length; i++) {
                leftpls[i] = pl_list[i];
            }
            String[][] rightNums = new String[root.length - mid - little][root[0].length];
            PLs[] rightpls = new PLs[pl_list.length - mid_2 - little_2];
            for (int i = 0; i < rightNums.length; i++) {
                for (int j = 0; j < root[0].length; j++) {
                    rightNums[i][j] = root[i + mid + little][j];
                }
            }
            for (int i = 0; i < rightpls.length; i++) {
                rightpls[i] = pl_list[i + mid_2 + little_2];
            }
            treeNode.left = CreateTree(leftNums, leftpls, keylist);
            treeNode.right = CreateTree(rightNums, rightpls, keylist);

            return treeNode;
        }
    }

    public void initTreeNode(IBtree treenode, String[] keylist, int[] rb_list) throws NoSuchAlgorithmException {
        if (treenode == null) {
            return;
        }
        initTreeNode(treenode.left, keylist, rb_list);
        initTreeNode(treenode.right, keylist, rb_list);
        if (treenode.tag != true) {
            if (treenode.height == 1) {
                count += 1;
                treenode.rb = rb_list[count];
                treenode.ibf = IBFConstruction.IndistinguishableBloomFilter(Param.ibflength, treenode.rb, keylist);
                for (int i = 0; i < treenode.prefixs.length; i++) {
                    for (int j = 0; j < treenode.prefixs[i].length; j++) {
                        IBFConstruction.insert(treenode.ibf, treenode.prefixs[i][j]);
                    }
                }
                treenode.tag = true;
                MessageDigest mdinstance = MessageDigest.getInstance("sha-256");
                byte[] outbytes = mdinstance.digest(IBFConstruction.IBF_value(treenode.ibf).getBytes());
                treenode.HV = outbytes;
            } else {
                count += 1;
                treenode.rb = rb_list[count];
                treenode.ibf = IBFConstruction.IndistinguishableBloomFilter(Param.ibflength, treenode.rb, keylist);
                for (int i = 0; i < treenode.ibf.length; i++) {
                    byte[] outbytes = treenode.ibf.H.digest((String.valueOf(i) + keylist[treenode.ibf.Keylist.length - 1]).getBytes());
                    BigInteger hkp1bi = new BigInteger(1, outbytes).mod(new BigInteger("11579208923731619542357098500868790785326998466564056403945758400791312963993"));//这是hkb+1(twinindex)
                    byte[] bytes1 = hash_bytes(hkp1bi, treenode.ibf.rb);
                    byte[] bytes2 = hash_bytes(hkp1bi, treenode.left.rb);
                    byte[] bytes3 = hash_bytes(hkp1bi, treenode.right.rb);
                    byte[] sha1bytes = treenode.ibf.mdinstance.digest(bytes1);
                    byte[] sha1bytesl = treenode.ibf.mdinstance.digest(bytes2);
                    byte[] sha1bytesr = treenode.ibf.mdinstance.digest(bytes3);
                    int location = new BigInteger(1, sha1bytes).mod(BigInteger.valueOf(2)).intValue();//mod2
                    int locationl = new BigInteger(1, sha1bytesl).mod(BigInteger.valueOf(2)).intValue();//mod2
                    int locationr = new BigInteger(1, sha1bytesr).mod(BigInteger.valueOf(2)).intValue();//mod2
                    treenode.ibf.twinlist[location][i] = together(treenode.left.ibf.twinlist[locationl][i],
                            treenode.right.ibf.twinlist[locationr][i]);
                    treenode.tag = true;
                    byte[] out = treenode.ibf.mdinstance.digest(addBytes(treenode.left.HV, treenode.right.HV));
                    treenode.HV = out;
                }
            }
        }
    }
    public  void search_Tree(IBtree treenode, int k, ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw,ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw){
        if (treenode==null) {
            return;
        }
        if (count2<k){
            if (hascomon(treenode.ibf,t1_raw)==false){

                return;
            }
            else {
                System.out.println(treenode.index+"\t"+ treenode.rb);
                if (treenode.height==1){
                    if (leafcomon(treenode.ibf,t2_raw)==true){
                        count2+=1;
                        System.out.println(treenode.index);
                        System.out.println(Numeric.toHexString(treenode.HV));
                    }
                }
                else {
                    search_Tree(treenode.left,k,t1_raw,t2_raw);
                    search_Tree(treenode.right,k,t1_raw,t2_raw);
                }
            }
        }
    }

    public static boolean hascomon(IBF ibf,ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw){
        for (int i = 0; i < t1_raw.size(); i++) {
            int count = 0;
            for (int j = 0; j < t1_raw.get(i).size(); j++) {
                Pair<BigInteger, BigInteger> pair = t1_raw.get(i).get(j);
                BigInteger twinindex_B = pair.getKey();
                int twindex = twinindex_B.intValue();
                BigInteger hkp1bi = pair.getValue();
                byte[] bytes = hash_bytes(hkp1bi, ibf.rb);
                byte[] sha1bytes = ibf.mdinstance.digest(bytes);//sha1_xor
                int location = new BigInteger(1, sha1bytes).mod(BigInteger.valueOf(2)).intValue();//mod2
                if (ibf.twinlist[location][twindex] == 1){
                    count+=1;
                }
            }
            if (count == Param.keylist.length-1){
                return true;
            }
        }
        return false;
    }
    public static boolean leafcomon(IBF ibf,ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw){
        for (int i = 0; i < t2_raw.size(); i++) {
            int count = 0;
            for (int j = 0; j < t2_raw.get(i).size(); j++) {
                Pair<BigInteger, BigInteger> pair = t2_raw.get(i).get(j);
                BigInteger twinindex_B = pair.getKey();
                int twinindex = twinindex_B.intValue();
                BigInteger hkp1bi = pair.getValue();
                byte[] bytes = hash_bytes(hkp1bi, ibf.rb);
                byte[] sha1bytes = ibf.mdinstance.digest(bytes);//sha1_xor
                int location = new BigInteger(1, sha1bytes).mod(BigInteger.valueOf(2)).intValue();//mod2
                if (ibf.twinlist[location][twinindex] == 1){
                    count+=1;
                }
            }
            if (count == Param.keylist.length-1){
                return true;
            }
        }
        return false;
    }

    public static byte[] addBytes(byte[] data1, byte[] data2) {
        byte[] data3 = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, data3, 0, data1.length);
        System.arraycopy(data2, 0, data3, data1.length, data2.length);
        return data3;

    }
    public static byte together(byte a, byte b) {               //取并集
        byte m = 1;
        if ((a == 1) || (b == 1)) {
            return m;
        } else {
            return a;
        }
    }

    public static void preOrder(IBtree node) {
        if (node == null) {
            return;
        }
        System.out.println(node.pl_data.length);
        System.out.println(IBFConstruction.search(node.ibf, "40000101001111"));
        preOrder(node.left);
        preOrder(node.right);
    }


    public static ArrayList<IBtree> PrintFromTopToBottom(IBtree root) throws Exception {
        ArrayList<IBtree> list = new ArrayList<IBtree>();
        Queue<IBtree> queue = new LinkedList<IBtree>();
        list.add(new IBtree());
        int index = 0;
        if (root != null) {
            queue.offer(root);
        }
        while (!queue.isEmpty()) {
            IBtree node = queue.poll();
            index += 1;
            node.index = index;
            if (node.index%2==0){
                node.brother = node.index+1;
            }
            if (node.index%2==1){
                node.brother = node.index - 1;
            }
            if (node.left != null) {
                node.lc = 2 * index;
                node.left.parent = index;
            }
            if (node.right != null) {
                node.rc = 2 * index + 1;
                node.right.parent = index;
            }
            PLs[] pl_data = node.pl_data;
            PLs pl = pl_data[0];
            String content;
            byte[] cipherBytes;
            DecimalFormat df = new DecimalFormat("#0.0000000");
            String lat_s = String.valueOf(df.format(pl.getLat()));
            String lng_s = String.valueOf(df.format(pl.getLng()));
            content = lat_s + "," + lng_s;
            cipherBytes = AESUtils.encrypt(content.getBytes(), Param.AESkey.getBytes());
            node.loc = cipherBytes;
            content = pl.getPrice() + "," + String.valueOf(pl.getId());
            cipherBytes = AESUtils.encrypt(content.getBytes(), Param.AESkey.getBytes());
            node.price = cipherBytes;
            node.ps = BigInteger.valueOf(pl.getPs());
            node.ibf_top_location = IBFConstruction.get_top_location(node.ibf);
            node.ibf_bottom_location = IBFConstruction.get_Bottom_location(node.ibf);
            list.add(node);
            if (node.left != null) {
                queue.offer(node.left);
            }
            if (node.right != null) {
                queue.offer(node.right);
            }
        }
        return list;
    }

    public static IBtree[] ListToString1(List<IBtree> list) {
        IBtree[] f = new IBtree[list.size()];
        for (int i = 0; i < f.length; i++) {
            f[i] = list.get(i);
        }
        return f;
    }


}
