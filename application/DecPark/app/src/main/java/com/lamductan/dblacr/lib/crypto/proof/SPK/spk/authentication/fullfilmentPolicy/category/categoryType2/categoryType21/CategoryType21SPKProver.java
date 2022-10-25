package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType21;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType1.CategoryType1SPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class CategoryType21SPKProver extends CategoryType1SPKProver {
    private BigInteger score;
    private BigInteger delta;
    private BigInteger keppa;

    private BigInteger alpha3;
    private BigInteger alpha4;
    private BigInteger beta3;

    private Vector<BigInteger> auxList;
    private Vector<BigInteger> gammaTildeList;

    public CategoryType21SPKProver(SystemParameters _sp, GroupParameters _gp,
                                   PrivateKey _privateKey, PublicKey _publicKey,
                                   Ticket _tau, Ticket _tau_i,
                                   BigInteger _g1, BigInteger _g2, int _score,
                                   BigInteger _delta, int _keppa, Vector<BigInteger> _auxList,
                                   Vector<BigInteger> _gammaTildeList) {
        super(_sp, _gp, _privateKey, _publicKey);
        super.inputTauAndG(_tau, _tau_i, _g1, _g2);
        score = BigInteger.valueOf(_score);
        delta = _delta;
        keppa = BigInteger.valueOf(_keppa + 1); // Order number = index + 1
        auxList = _auxList;
        gammaTildeList = _gammaTildeList;
        super.inputObjectsFreeVarsRelations();
    }

    private Vector<BigInteger> getAuxTildeList(Vector<BigInteger> auxList) {
        int n = auxList.size();
        Vector<BigInteger> auxTildeList = new Vector<>();
        for(int i = 1; i < n; i += 2) auxTildeList.add(auxList.get(i));
        return auxTildeList;
    }

    @Override
    protected void inputNRelations() {nRelations = 7;}

    @Override
    protected void inputObjects() {
        // Compute List Objects
        // List Objects: [t^-1, b, t_i^-1, b_i, g1, g2, C~^-1, D~^-1, C^-1, U3, U4^-1, U5^-1]
        alpha3 = Utils.computeRandomNumber(Modulus, sp);
        alpha4 = Utils.computeRandomNumber(Modulus, sp);
        gamma = Utils.computeRandomNumber(Modulus, sp);
        gammaTilde = Utils.computeRandomNumber(Modulus, sp);

        BigInteger capU3 = g1.modPow(score, Modulus);
        BigInteger capU4 = g1.modPow(keppa, Modulus)
                .multiply(g2.modPow(alpha3, Modulus)).mod(Modulus);
        BigInteger capU5 = g1.modPow(delta, Modulus)
                .multiply(g2.modPow(alpha4, Modulus)).mod(Modulus);

        capC = capU3.modPow(delta, Modulus).multiply(g2.modPow(gamma, Modulus)).mod(Modulus);
        capCTilde = g1.multiply(g2.modPow(gammaTilde, Modulus)).mod(Modulus);

        beta3 = AuxUtils.sum(gammaTildeList).add(gammaTilde);
        Vector<BigInteger> auxTildeList = getAuxTildeList(auxList);
        BigInteger capDTilde = Utils.product(auxTildeList).multiply(capCTilde);

        objects.put("tInverse", t.modInverse(Modulus));
        objects.put("b", b);
        objects.put("t_iInverse", t_i.modInverse(Modulus));
        objects.put("b_i", b_i);
        objects.put("g1", g1);
        objects.put("g2", g2);
        objects.put("CInverse", capC.modInverse(Modulus));
        objects.put("CTildeInverse", capCTilde.modInverse(Modulus));
        objects.put("DTildeInverse", capDTilde.modInverse(Modulus));
        objects.put("U3", capU3);
        objects.put("U4Inverse", capU4.modInverse(Modulus));
        objects.put("U5Inverse", capU5.modInverse(Modulus));
    }

    @Override
    protected void inputFreeVars() {
        // Compute FreeVars
        freeVars.put("x", x);
        freeVars.put("gamma", gamma);
        freeVars.put("gammaTilde", gammaTilde);
        freeVars.put("keppa", keppa);
        freeVars.put("beta3", beta3);
        freeVars.put("delta", delta);
        freeVars.put("alpha3", alpha3);
        freeVars.put("alpha4", alpha4);
    }

    @Override
    protected void inputLengthConditions() {
        int len = sp.getL_n()/2;
        bitLengthUpperBounds.put("x", len + 2);
    }

    @Override
    protected void createRelations() {
        super.createRelations(nRelations);
        TreeMap<String, Pair<String, BigInteger>> relationRow;

        // t = b^x <-> t^-1.b^x = 1
        relationRow = relations.get(0);
        relationRow.put("tInverse", createNewPair("1", ONE));
        relationRow.put("b", createNewPair("x", x));

        // t_i^-1.b_i^x = 1
        relationRow = relations.get(1);
        relationRow.put("t_iInverse", createNewPair("1", ONE));
        relationRow.put("b_i", createNewPair("x", x));

        // C~ = g1.g2^gammaTilde
        relationRow = relations.get(2);
        relationRow.put("CTildeInverse", createNewPair("1", ONE));
        relationRow.put("g1", createNewPair("1", ONE));
        relationRow.put("g2", createNewPair("gammaTilde", gammaTilde));

        // D~ = g1^keppa.g2^beta3
        relationRow = relations.get(3);
        relationRow.put("DTildeInverse", createNewPair("1", ONE));
        relationRow.put("g1", createNewPair("keppa", keppa));
        relationRow.put("g2", createNewPair("beta3", beta3));

        // C = U3^delta.g2^gamma
        relationRow = relations.get(4);
        relationRow.put("CInverse", createNewPair("1", ONE));
        relationRow.put("U3", createNewPair("delta", delta));
        relationRow.put("g2", createNewPair("gamma", gamma));

        // U4 = g1^keppa.g2^alpha3
        relationRow = relations.get(5);
        relationRow.put("U4Inverse", createNewPair("1", ONE));
        relationRow.put("g1", createNewPair("keppa", keppa));
        relationRow.put("g2", createNewPair("alpha3", alpha3));

        // U5 = g1^delta.g2^alpha4
        relationRow = relations.get(6);
        relationRow.put("U5Inverse", createNewPair("1", ONE));
        relationRow.put("g1", createNewPair("delta", keppa));
        relationRow.put("g2", createNewPair("alpha4", alpha4));
    }

    public BigInteger getAlpha3() {return alpha3;}
    public BigInteger getAlpha4() {return alpha4;}
}
