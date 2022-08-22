package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType22;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class CategoryType22SPKProver extends SPKProverInterface {
    protected Vector<BigInteger> witnesses;
    protected CLSignature clSignature;
    protected BigInteger n;
    protected Vector<BigInteger> a;
    protected BigInteger b;
    protected BigInteger c;
    protected BigInteger e, s, v;
    protected int nWitnesses;

    protected BigInteger w, rw, z, rwPrime;
    protected Vector<BigInteger> r;

    protected int nRelations;

    public CategoryType22SPKProver(SystemParameters sp, Vector<BigInteger> _witnesses,
                                   CLSignature _clSignature) {
        super(sp, ONE);
        freeVars = new TreeMap<>();
        witnesses = _witnesses;
        clSignature = _clSignature;
        n = clSignature.getClSignaturePublicKey().getN();
        a = clSignature.getClSignaturePublicKey().getA();
        b = clSignature.getClSignaturePublicKey().getB();
        c = clSignature.getClSignaturePublicKey().getC();
        nWitnesses = witnesses.size();
        e = clSignature.getE();
        s = clSignature.getS();
        v = clSignature.getV();

        g = AuxUtils.computeGeneratorQuadraticResidueInvertibleWithModulus(n, sp);
        h = AuxUtils.computeGeneratorQuadraticResidueInvertibleWithModulus(n, sp);
        Modulus = n;
        N = n;
        inputNRelations();
        super.inputObjectsFreeVarsRelations();
    }

    public Vector<BigInteger> getR() {return r;}
    public BigInteger getN() {return n;}

    @Override
    protected void inputNRelations() {
        nRelations = nWitnesses + 3;
    }

    @Override
    protected void inputObjects() {
        w = Utils.computeRandomNumber(Modulus, sp);
        rw = Utils.computeRandomNumber(Modulus, sp);
        r = new Vector<>();
        for(int i = 0; i < nWitnesses; ++i) {
            BigInteger r_i = Utils.computeRandomNumber(Modulus, sp);
            r.add(r_i);
        }
        z = w.multiply(e);
        rwPrime = rw.multiply(e);
        BigInteger capTv = v.multiply(g.modPow(w, Modulus)).mod(Modulus);
        BigInteger capTw = g.modPow(w, Modulus).multiply(h.modPow(rw, Modulus)).mod(Modulus);
        Vector<BigInteger> capT = new Vector<>();
        for(int i = 0; i < nWitnesses; ++i) {
            BigInteger t = g.modPow(witnesses.get(i), Modulus)
                    .multiply(h.modPow(r.get(i), Modulus)).mod(Modulus);
            capT.add(t);
        }

        for(int i = 0; i < nWitnesses; ++i) {
            objects.put("a" + i, a.get(i));
            try {
                objects.put("T" + i + "Inverse", capT.get(i).modInverse(Modulus));
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("T = " + capT.get(i));
                System.out.println("Modulus = " + Modulus);
            }
        }
        objects.put("b", b);
        objects.put("c", c);
        objects.put("g", g);
        objects.put("h", h);
        objects.put("TvInverse", capTv.modInverse(Modulus));
        objects.put("TwInverse", capTw.modInverse(Modulus));
    }

    @Override
    protected void inputFreeVars() {
        // Compute FreeVars
        freeVars.put("s", s);
        freeVars.put("v", v);
        freeVars.put("e", e);
        freeVars.put("w", w);
        freeVars.put("z", z);
        freeVars.put("rw", rw);
        freeVars.put("rwPrime", rwPrime);
        for(int i = 0; i < nWitnesses; ++i) {
            freeVars.put("witness" + i, witnesses.get(i));
            freeVars.put("r" + i, r.get(i));
        }
    }

    @Override
    protected void inputLengthConditions() {
        int len = sp.getL_m()/2;
        bitLengthUpperBounds.put("e", sp.getL_e());
        for(int i = 0; i < nWitnesses; ++i) {
            bitLengthUpperBounds.put("witness" + i, len);
        }
    }

    @Override
    protected void createRelations() {
        super.createRelations(nRelations);
        TreeMap<String, Pair<String, BigInteger>> relationRow;

        // Tw = g^w^h^rw
        relationRow = relations.get(0);
        relationRow.put("g", createNewPair("w", w));
        relationRow.put("h", createNewPair("rw", rw));
        relationRow.put("TwInverse", createNewPair("1", ONE));

        // Tw^e = g^z^h^rwPrime
        relationRow = relations.get(1);
        relationRow.put("g", createNewPair("z", z));
        relationRow.put("h", createNewPair("rwPrime", rwPrime));
        relationRow.put("TwInverse", createNewPair("e", e));

        for(int i = 0; i < nWitnesses; ++i) {
            relationRow = relations.get(i + 2);
            relationRow.put("g", createNewPair("witness" + i, witnesses.get(i)));
            relationRow.put("h", createNewPair("r" + i, r.get(i)));
            relationRow.put("T" + i + "Inverse", createNewPair("1", ONE));
        }

        relationRow = relations.get(nRelations - 1);
        relationRow.put("TvInverse", createNewPair("e", e));
        relationRow.put("b", createNewPair("s", s));
        relationRow.put("c", createNewPair("1", ONE));
        relationRow.put("g", createNewPair("z", z));
        for(int i = 0; i < nWitnesses; ++i) {
            relationRow.put("a" + i, createNewPair("witness" + i, witnesses.get(i)));
        }
    }
}
