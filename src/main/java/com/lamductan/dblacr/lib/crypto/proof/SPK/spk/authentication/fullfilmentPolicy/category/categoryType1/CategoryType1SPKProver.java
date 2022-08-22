package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType1;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;

public class CategoryType1SPKProver extends SPKProverInterface {
    protected Ticket tau;
    protected Ticket tau_i;
    protected BigInteger g1;
    protected BigInteger g2;

    private BigInteger alpha1;
    private BigInteger alpha2;
    private BigInteger beta1;
    private BigInteger beta2;

    protected BigInteger gamma;
    protected BigInteger gammaTilde;
    protected BigInteger capC;
    protected BigInteger capCTilde;
    protected BigInteger x;
    protected BigInteger t;
    protected BigInteger b;
    protected BigInteger t_i;
    protected BigInteger b_i;

    public CategoryType1SPKProver(SystemParameters sp, GroupParameters gp,
                                  PrivateKey privateKey, PublicKey publicKey) {
        super(sp, gp, privateKey, publicKey, BigInteger.ONE);
    }

    public CategoryType1SPKProver(SystemParameters _sp, GroupParameters _gp,
                                  PrivateKey _privateKey, PublicKey _publicKey,
                                  Ticket _tau, Ticket _tau_i, BigInteger _g1, BigInteger _g2) {
        super(_sp, _gp, _privateKey, _publicKey, BigInteger.ONE);
        inputTauAndG(_tau, _tau_i, _g1, _g2);
        super.inputObjectsFreeVarsRelations();
    }

    protected void inputTauAndG(Ticket _tau, Ticket _tau_i, BigInteger _g1, BigInteger _g2) {
        tau = _tau;
        tau_i = _tau_i;
        g1 = _g1;
        g2 = _g2;
        x = privateKey.getP().add(privateKey.getQ());
        t = tau.getT();
        b = tau.getB();
        t_i = tau_i.getT();
        b_i = tau_i.getB();
    }

    public BigInteger getC() { return capC;}
    public BigInteger getCTilde() {return capCTilde;}
    public BigInteger getGamma() {return gamma;}
    public BigInteger getGammaTilde() {return gammaTilde;}

    @Override
    protected void inputNRelations() { nRelations = 6; }

    @Override
    protected void inputObjects() {
        // Compute List Objects
        // List Objects: [t^-1, b, g1, g2, U1^-1, U2^-1, C^-1, C~^-1, t_i, b_i^-1]
        alpha1 = Utils.computeRandomNumber(Modulus, sp);
        alpha2 = Utils.computeRandomNumber(Modulus, sp);
        gamma = Utils.computeRandomNumber(Modulus, sp);
        gammaTilde = Utils.computeRandomNumber(Modulus, sp);

        capC = g2.modPow(gamma, Modulus);
        capCTilde = g2.modPow(gammaTilde, Modulus);

        beta1 = alpha1.multiply(x);
        beta2 = alpha2.multiply(x);
        BigInteger capU1 = t_i.modPow(alpha1, Modulus).multiply(b_i.modPow(beta1.negate(), Modulus))
                .mod(Modulus);
        BigInteger capU2 = g1.modPow(alpha1, Modulus).multiply(g2.modPow(alpha2, Modulus)).mod(Modulus);

        objects.put("tInverse", t.modInverse(Modulus));
        objects.put("b", b);
        objects.put("g1", g1);
        objects.put("g2", g2);
        objects.put("U1Inverse", capU1.modInverse(Modulus));
        objects.put("U2Inverse", capU2.modInverse(Modulus));
        objects.put("CInverse", capC.modInverse(Modulus));
        objects.put("CTildeInverse", capCTilde.modInverse(Modulus));
        objects.put("t_i", t_i);
        objects.put("b_iInverse", b_i.modInverse(Modulus));
    }

    @Override
    protected void inputFreeVars() {
        // Compute FreeVars
        freeVars.put("x", x);
        freeVars.put("alpha1", alpha1);
        freeVars.put("alpha2", alpha2);
        freeVars.put("beta1", beta1);
        freeVars.put("beta2", beta2);
        freeVars.put("gamma", gamma);
        freeVars.put("gammaTilde", gammaTilde);
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

        // U2 = g1^alpha1.g2^alpha2
        relationRow = relations.get(1);
        relationRow.put("g1", createNewPair("alpha1", alpha1));
        relationRow.put("g2", createNewPair("alpha2", alpha2));
        relationRow.put("U2Inverse", createNewPair("1", ONE));

        // U2^(-x).g1^beta1.g2^beta2 = 1
        relationRow = relations.get(2);
        relationRow.put("g1", createNewPair("beta1", beta1));
        relationRow.put("g2", createNewPair("beta2", beta2));
        relationRow.put("U2Inverse", createNewPair("x", x));

        // U1^(-1).(t_i)^alpha1.(b_i^-1)^beta1 = 1
        relationRow = relations.get(3);
        relationRow.put("U1Inverse", createNewPair("1", ONE));
        relationRow.put("t_i", createNewPair("alpha1", alpha1));
        relationRow.put("b_iInverse", createNewPair("beta1", beta1));

        // C = g2^gamma
        relationRow = relations.get(4);
        relationRow.put("CInverse", createNewPair("1", ONE));
        relationRow.put("g2", createNewPair("gamma", gamma));

        // C~ = g2^gamma~
        relationRow = relations.get(5);
        relationRow.put("CTildeInverse", createNewPair("1", ONE));
        relationRow.put("g2", createNewPair("gammaTilde", gammaTilde));
    }
}
