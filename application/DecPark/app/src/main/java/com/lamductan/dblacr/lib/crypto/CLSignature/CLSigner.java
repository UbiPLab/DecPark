package com.lamductan.dblacr.lib.crypto.CLSignature;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

public class CLSigner implements Serializable {
    private static final long serialVersionUID = 6529685098267757671L;

    private SystemParameters sp;
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phiN;
    private BigInteger b;
    private BigInteger c;
    private CLSignaturePrivateKey clSignaturePrivateKey;

    public CLSigner(SystemParameters _sp) {
        sp = _sp;
        generateKey();
    }

    private void generateKey() {
        int len = sp.getL_n()/2;
        p = Utils.computeSafePrime(len, sp.getL_pt());
        q = Utils.computeSafePrime(sp.getL_n() - len, sp.getL_pt());
        phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        n = p.multiply(q);
        b = Utils.computeGeneratorQuadraticResidue(n, sp);
        c = Utils.computeGeneratorQuadraticResidue(n, sp);
        clSignaturePrivateKey = new CLSignaturePrivateKey(p, q);
    }

    public CLSignaturePrivateKey getClSignaturePrivateKey() {return clSignaturePrivateKey;}

    public BigInteger getN() {return n;}
    public BigInteger getB() {return b;}
    public BigInteger getC() {return c;}

    public CLSignature sign(Vector<BigInteger> message) {
        Vector<BigInteger> a = new Vector<>();
        Pair<BigInteger, BigInteger> tmp = AuxUtils.computeRandomInvertible(sp.getL_e(), n, phiN);
        BigInteger e = tmp.getKey();
        BigInteger eInversePhiN = tmp.getValue();
//        assert (e.bitLength() == sp.getL_e());
        BigInteger s = AuxUtils.computeRandomNumber(sp.getL_n() + sp.getL_m());

        BigInteger y = b.modPow(s, n).multiply(c).mod(n);
        int i = 0;
        for(BigInteger m : message) {
            i++;
            BigInteger a_i = Utils.computeGeneratorQuadraticResidue(n, sp);
            y = y.multiply(a_i.modPow(m, n)).mod(n);
            a.add(a_i);
        }

        BigInteger v = y.modPow(eInversePhiN, n);
        CLSignaturePublicKey clSignaturePublicKey = new CLSignaturePublicKey(n, a, b, c);
        return new CLSignature(e, s, v, clSignaturePublicKey);
    }

    public CLSignature sign(BigInteger message) {
        Vector<BigInteger> m = new Vector<>();
        m.add(message);
        return sign(m);
    }

    public CLSignature sign(BigInteger message1, BigInteger message2) {
        Vector<BigInteger> m = new Vector<>();
        m.add(message1);
        m.add(message2);
        return sign(m);
    }
}
