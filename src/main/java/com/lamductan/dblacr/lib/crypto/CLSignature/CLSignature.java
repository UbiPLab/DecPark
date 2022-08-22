package com.lamductan.dblacr.lib.crypto.CLSignature;

import java.io.Serializable;
import java.math.BigInteger;

public class CLSignature implements Serializable {
    private static final long serialVersionUID = 6529685098267757677L;

    private BigInteger e;
    private BigInteger s;
    private BigInteger v;
    private CLSignaturePublicKey clSignaturePublicKey;

    public CLSignature(BigInteger _e, BigInteger _s, BigInteger _v,
                       CLSignaturePublicKey _clSignaturePublicKey) {
        e = _e;
        s = _s;
        v = _v;
        clSignaturePublicKey = _clSignaturePublicKey;
    }

    public BigInteger getE() {return e;}
    public BigInteger getS() {return s;}
    public BigInteger getV() {return v;}
    public CLSignaturePublicKey getClSignaturePublicKey() {return clSignaturePublicKey;}
}
