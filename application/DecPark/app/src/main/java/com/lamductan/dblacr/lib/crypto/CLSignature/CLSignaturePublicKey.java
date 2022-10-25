package com.lamductan.dblacr.lib.crypto.CLSignature;

import com.lamductan.dblacr.lib.crypto.key.IPublicKey;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

public class CLSignaturePublicKey implements IPublicKey, Serializable {
    private static final long serialVersionUID = 6529685098267757675L;

    private BigInteger n;
    private Vector<BigInteger> a;
    private BigInteger b;
    private BigInteger c;

    public CLSignaturePublicKey(BigInteger _n, Vector<BigInteger> _a, BigInteger _b, BigInteger _c) {
        n = _n;
        a = _a;
        b = _b;
        c = _c;
    }

    public BigInteger getN() {return n;}
    public Vector<BigInteger> getA() {return a;}
    public BigInteger getB() {return b;}
    public BigInteger getC() {return c;}
}
