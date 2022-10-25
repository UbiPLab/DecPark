package com.lamductan.dblacr.lib.crypto.ticket;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.io.Serializable;
import java.math.BigInteger;

public class Ticket implements Serializable {
    private static final long serialVersionUID = 6529685098267757684L;

    private GroupParameters gp;
    private BigInteger b;
    private BigInteger t;
    private DBLACRSystem dblacrSystem;

    public Ticket(PrivateKey sk) {
        dblacrSystem = DBLACRSystem.getInstance();
        BigInteger N = sk.getN();
        BigInteger Modulus = sk.getModulus();
        gp = sk.getPublicKey().getGroupParams();
        SystemParameters sp = dblacrSystem.getSystemParameters();
        BigInteger r = Utils.computeRandomNumber(Modulus, sp);
        BigInteger g = sk.getG();
        b = g.modPow(r, N);
        t = b.modPow(sk.getP().add(sk.getQ()), Modulus);
    }

    public BigInteger getB() {return b;}
    public BigInteger getT() {return t;}

    public boolean verify(PrivateKey sk) {
        BigInteger tPrime = b.modPow(sk.getP().add(sk.getQ()), sk.getModulus());
        return t.equals(tPrime);
    }
}


