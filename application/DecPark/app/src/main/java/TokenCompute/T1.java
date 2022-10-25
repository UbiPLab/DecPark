package TokenCompute;

import Leaf.Param;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class T1 {
    public  List<List<BigInteger>> top_locations;
    public  List<List<BigInteger>> bottom_locations;

    public void get_top_locations(ArrayList<String> t1, int rb) throws NoSuchAlgorithmException {
        MessageDigest mdinstance = MessageDigest.getInstance("sha-256");
        MessageDigest H = MessageDigest.getInstance("sha-384");



    }
}
