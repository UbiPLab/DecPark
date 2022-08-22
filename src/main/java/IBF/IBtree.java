package IBF;

import Leaf.PLs;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class IBtree {
    public IBF ibf;
    public int index;//8
    public int rb;//256
    public byte[] loc;
    public byte[] price;
    public BigInteger ps;//
    public byte[] HV;
    public List<BigInteger> ibf_top_location;
    public List<BigInteger> ibf_bottom_location;
    public PLs[] pl_data;
    public String[][] prefixs;
    public double height;
    public boolean tag;
    public int brother;
    public int lc;
    public int rc;
    public int parent;
    public IBtree left;

    @Override
    public String toString() {
        return  Arrays.toString(loc) +
                  Arrays.toString(price) ;
    }

    public IBtree right;


}
