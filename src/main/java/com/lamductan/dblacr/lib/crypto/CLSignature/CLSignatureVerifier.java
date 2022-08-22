package com.lamductan.dblacr.lib.crypto.CLSignature;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.math.BigInteger;
import java.util.Vector;

public class CLSignatureVerifier {
    private BigInteger n;
    private Vector<BigInteger> a;
    private BigInteger b;
    private BigInteger c;
    private BigInteger e;
    private BigInteger s;
    private BigInteger v;
    private SystemParameters sp;

    public CLSignatureVerifier(CLSignature clSignature, SystemParameters _sp) {
        e = clSignature.getE();
        s = clSignature.getS();
        v = clSignature.getV();
        CLSignaturePublicKey clSignaturePublicKey = clSignature.getClSignaturePublicKey();
        n = clSignaturePublicKey.getN();
        a = clSignaturePublicKey.getA();
        b = clSignaturePublicKey.getB();
        c = clSignaturePublicKey.getC();
        sp = _sp;
    }

    public boolean verify(Vector<BigInteger> message) {
        //if (e.bitLength() != sp.getL_e()) {
        //    System.out.println("Wrong length e");
         //   return false;
        //}
        BigInteger lhs = v.modPow(e, n);
        BigInteger rhs = b.modPow(s, n).multiply(c).mod(n);
        if (message.size() != a.size()) return false;

        for(int i = 0; i < message.size(); ++i) {
            rhs = rhs.multiply(a.get(i).modPow(message.get(i), n)).mod(n);
        }
        boolean res = lhs.equals(rhs);
        if (!res) {
            System.out.println("Wrong equation");
        }
        return res;
    }

    public boolean verify(BigInteger message) {
        Vector<BigInteger> m = new Vector<>();
        m.add(message);
        return verify(m);
    }

    public boolean verify(BigInteger message1, BigInteger message2) {
        Vector<BigInteger> m = new Vector<>();
        m.add(message1);
        m.add(message2);
        return verify(m);
    }
}
