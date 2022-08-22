package TestDecPark;

import IBF.IBF;

public class Poc1 {
    public int node_index;
    public int rb;
    public IBF ibf;
    public int lc;
    public int rc;
    public byte[] HV;

    @Override
    public String toString() {
        return "Poc1{" +
                "node_index=" + node_index +
                ", rb=" + rb +
                ", ibf=" + ibf +
                ", lc=" + lc +
                ", rc=" + rc +
                '}';
    }

    public Poc1(int node_index, int rb, IBF ibf, int lc, int rc) {
        this.node_index = node_index;
        this.rb = rb;
        this.ibf = ibf;
        this.lc = lc;
        this.rc = rc;
    }

}
