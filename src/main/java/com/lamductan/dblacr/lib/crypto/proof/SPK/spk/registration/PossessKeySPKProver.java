package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.registration;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;

public class PossessKeySPKProver extends SPKProverInterface implements Serializable {
    private static final long serialVersionUID = 6529685098267757685L;

    BigInteger r1;
    BigInteger r2;
    BigInteger a;

    public PossessKeySPKProver(SystemParameters _sp, GroupParameters _gp, PrivateKey _privateKey,
                               PublicKey _publicKey, BigInteger _nonce) {
        super(_sp, _gp, _privateKey, _publicKey, _nonce);
        //inputObjects();inputFreeVarsAndLengthConditions();createRelations();
        super.inputObjectsFreeVarsRelations();
    }


    @Override
    protected void inputNRelations() { nRelations = 5; }

    @Override
    protected void inputObjects() {
        // Compute List Objects
        // List objects: [g, C0^-1, h, C1^-1, C2^-1]
        r1 = Utils.computeRandomNumber(Modulus, sp);
        r2 = Utils.computeRandomNumber(Modulus, sp);
        a = q.multiply(r1);
        BigInteger capC0 = g.modPow(r1, Modulus);
        BigInteger capC1 = g.modPow(p, Modulus).multiply(h.modPow(r1, Modulus));
        BigInteger capC2 = g.modPow(q, Modulus).multiply(h.modPow(r2, Modulus));

        objects.put("g", g);
        objects.put("C0Inverse", capC0.modInverse(Modulus));
        objects.put("h", h);
        objects.put("C1Inverse", capC1.modInverse(Modulus));
        objects.put("C2Inverse", capC2.modInverse(Modulus));
    }

    @Override
    protected void inputFreeVars() {
        // Compute FreeVars
        // List freeVars: [r1, r2, p, q, a]
        freeVars.put("r1", r1);
        freeVars.put("r2", r2);
        freeVars.put("p", p);
        freeVars.put("q", q);
        freeVars.put("a", a);
    }

    @Override
    protected void inputLengthConditions() {
        int len = sp.getL_n()/2;
        bitLengthLowerBounds.put("p", len);
        bitLengthLowerBounds.put("q", len);
        bitLengthUpperBounds.put("p", len);
        bitLengthUpperBounds.put("q", len);
    }

    protected void createRelations() {
        super.createRelations(nRelations);
        TreeMap<String, Pair<String, BigInteger>> relationRow;

        // C0 = g^r1
        relationRow = relations.get(0);
        relationRow.put("g", createNewPair("r1", r1));
        relationRow.put("C0Inverse", createNewPair("1", ONE));

        // C1 = g^p.h^r1
        relationRow = relations.get(1);
        relationRow.put("g", createNewPair("p", p));
        relationRow.put("h", createNewPair("r1", r1));
        relationRow.put("C1Inverse", createNewPair("1", ONE));

        // C2 = g^q.h^r2
        relationRow = relations.get(2);
        relationRow.put("g", createNewPair("q", q));
        relationRow.put("h", createNewPair("r2", r2));
        relationRow.put("C2Inverse", createNewPair("1", ONE));

        // C0^q = g^a
        relationRow = relations.get(3);
        relationRow.put("g", createNewPair("a", a));
        relationRow.put("C0Inverse", createNewPair("q", q));

        // g^N.h^a = C1^q
        relationRow = relations.get(4);
        relationRow.put("g", createNewPair("n", N));
        relationRow.put("h", createNewPair("a", a));
        relationRow.put("C1Inverse", createNewPair("q", q));
    }
}
