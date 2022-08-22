package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.ticketValidation;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon.AuthenticationSPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class TicketValidateSPKProver extends AuthenticationSPKProver implements Serializable {
    private static final long serialVersionUID = 6529685098267757681L;

    BigInteger r;
    BigInteger a1;
    BigInteger a2;

    public TicketValidateSPKProver(SystemParameters _sp, GroupParameters _gp, PrivateKey _privateKey,
                                   PublicKey _publicKey, BigInteger _nonce, Ticket _tau,
                                   Requirement _requirement) {
        super(_sp, _gp, _privateKey, _publicKey, _nonce, _tau, _requirement);
    }

    @Override
    protected void inputNRelations() { nRelations = 8; }

    @Override
    protected void inputObjects() {
        // Compute List Objects
        // List objects: [g, h, y, z, s, T1^-1, T2^-1, T3^-1, T4^-1, T5^-1, v, t^-1, b]

        BigInteger y = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
        BigInteger z;
        BigInteger s;
        do {
            z = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
        } while (z.equals(y));
        do {
            s = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
        } while (s.equals(y) || s.equals(z));

        r = Utils.computeRandomNumber(Modulus, sp);
        a1 = r.multiply(N);
        a2 = r.multiply(q);
        BigInteger capT1 = g.modPow(r, Modulus);
        BigInteger capT2 = h.modPow(r, Modulus).multiply(g.modPow(N, Modulus)).mod(Modulus);
        BigInteger capT3 = s.modPow(r, Modulus).multiply(g.modPow(q, Modulus)).mod(Modulus);

        Vector<PublicKey> listPublicKey = requirement.getC();
        Vector<BigInteger> listN = AuxUtils.getListN(listPublicKey);
        BigInteger pv = Utils.product(listN);
        BigInteger v = g.modPow(pv, Modulus);
        BigInteger pw = ONE;
        for(int i = 0; i < listN.size(); ++i) {
            BigInteger x = listN.get(i);
            if (!x.equals(N)) pw = pw.multiply(x);
        }
        BigInteger w = g.modPow(pw, Modulus);

        BigInteger capT4 = w.multiply(y.modPow(r, Modulus)).mod(Modulus);
        BigInteger capT5 = z.modPow(r, Modulus).multiply(g.modPow(p, Modulus)).mod(Modulus);

        BigInteger t = tau.getT();
        BigInteger b = tau.getB();

        objects = new TreeMap<>();
        objects.put("g", g);
        objects.put("h", h);
        objects.put("y", y);
        objects.put("z", z);
        objects.put("s", s);
        objects.put("T1Inverse", capT1.modInverse(Modulus));
        objects.put("T2Inverse", capT2.modInverse(Modulus));
        objects.put("T3Inverse", capT3.modInverse(Modulus));
        objects.put("T4Inverse", capT4.modInverse(Modulus));
        objects.put("T5Inverse", capT5.modInverse(Modulus));
        objects.put("v", v);
        objects.put("tInverse", t.modInverse(Modulus));
        objects.put("b1", b);
        objects.put("b2", b);
    }

    @Override
    protected void inputFreeVars() {
        // Compute FreeVars
        freeVars.put("p", p);
        freeVars.put("q", q);
        freeVars.put("n", N);
        freeVars.put("r", r);
        freeVars.put("a1", a1);
        freeVars.put("a2", a2);
    }

    @Override
    protected void inputLengthConditions() {
        int len = sp.getL_n()/2;
        bitLengthLowerBounds.put("q", len);
        bitLengthUpperBounds.put("q", len);
    }

    @Override
    protected void createRelations() {
        super.createRelations(nRelations);
        TreeMap<String, Pair<String, BigInteger>> relationRow;

        // T1 = g^r <-> g^r.T1^-1 = 1
        relationRow = relations.get(0);
        relationRow.put("g", createNewPair("r", r));
        relationRow.put("T1Inverse", createNewPair("1", ONE));

        // T2 = h^r.g^n
        relationRow = relations.get(1);
        relationRow.put("g", createNewPair("n", N));
        relationRow.put("h", createNewPair("r", r));
        relationRow.put("T2Inverse", createNewPair("1", ONE));

        // T1^n = g^a1
        relationRow = relations.get(2);
        relationRow.put("g", createNewPair("a1", a1));
        relationRow.put("T1Inverse", createNewPair("n", N));

        // T3 = s^r.g^q
        relationRow = relations.get(3);
        relationRow.put("g", createNewPair("q", q));
        relationRow.put("s", createNewPair("r", r));
        relationRow.put("T3Inverse", createNewPair("1", ONE));

        // T1^q = g^a2
        relationRow = relations.get(4);
        relationRow.put("g", createNewPair("a2", a2));
        relationRow.put("T1Inverse", createNewPair("q", q));

        // T4^n = v.y^a1
        relationRow = relations.get(5);
        relationRow.put("y", createNewPair("a1", a1));
        relationRow.put("T4Inverse", createNewPair("n", N));
        relationRow.put("v", createNewPair("1", ONE));

        // T5^q = z^a2.g^n
        relationRow = relations.get(6);
        relationRow.put("g", createNewPair("n", N));
        relationRow.put("T5Inverse", createNewPair("q", q));
        relationRow.put("z", createNewPair("a2", a2));

        // t = b^p.b^q
        relationRow = relations.get(7);
        relationRow.put("tInverse", createNewPair("1", ONE));
        relationRow.put("b1", createNewPair("p", p));
        relationRow.put("b2", createNewPair("q", q));
    }
}
