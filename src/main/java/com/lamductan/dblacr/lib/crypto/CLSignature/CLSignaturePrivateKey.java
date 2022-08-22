package com.lamductan.dblacr.lib.crypto.CLSignature;

import com.lamductan.dblacr.lib.crypto.key.IPrivateKey;

import java.io.Serializable;
import java.math.BigInteger;

public class CLSignaturePrivateKey implements IPrivateKey, Serializable {
    private static final long serialVersionUID = 6529685098267757676L;

    private BigInteger p;
    private BigInteger q;

    public CLSignaturePrivateKey(BigInteger _p, BigInteger _q) {
        p = _p;
        q = _q;
    }

    @Override
    public BigInteger getP() {
        return p;
    }

    @Override
    public BigInteger getQ() {
        return q;
    }
}
