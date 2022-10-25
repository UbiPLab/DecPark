package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23;

import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.IPrivateKey;
import com.lamductan.dblacr.lib.crypto.key.IPublicKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

public class CategoryType23SPKProver extends SPKProverInterface {
    BigInteger keppa, delta;
    BigInteger alpha3, alpha4, r1, r2;
    BigInteger r1Prime, r2Prime;

    BigInteger capU4Inverse, capU5Inverse;
    BigInteger capT1Inverse, capT2Inverse;
    BigInteger g1, g2;
    BigInteger n, y1, y2;
    BigInteger h1, h2, n1;
    Vector<BigInteger> listMod;

    public CategoryType23SPKProver(SystemParameters _sp, GroupParameters _gp, IPrivateKey _privateKey,
                                   IPublicKey _publicKey, TreeMap<String, BigInteger> input) {
        super(_sp, _gp, _privateKey, _publicKey, ONE);
        keppa = input.get("keppa");
        delta = input.get("delta");

        capU4Inverse = input.get("U4Inverse");
        capU5Inverse = input.get("U5Inverse");
        alpha3 = input.get("alpha3");
        alpha4 = input.get("alpha4");
        g1 = input.get("g1");
        g2 = input.get("g2");

        capT1Inverse = input.get("T1Inverse");
        capT2Inverse = input.get("T2Inverse");
        r1 = input.get("r1");
        r2 = input.get("r2");
        g = input.get("g");
        h = input.get("h");
        n = input.get("n");

        n1 = ((PublicKey) _publicKey).getN1();
        h1 = ((PublicKey) _publicKey).getH1();
        h2 = ((PublicKey) _publicKey).getH2();

        listMod = new Vector<>();
        super.inputObjectsFreeVarsRelations();
    }

    @Override
    protected void inputNRelations() {
        nRelations = 6;
    }

    @Override
    protected void inputObjects() {
        r1Prime = Utils.computeRandomNumber(Modulus, sp);
        r2Prime = Utils.computeRandomNumber(Modulus, sp);
        y1 = h1.modPow(r1Prime, n1).multiply(h2.modPow(keppa, n1)).mod(n1);
        y2 = h1.modPow(r2Prime, n1).multiply(h2.modPow(delta, n1)).mod(n1);

        objects.put("U4Inverse", capU4Inverse);
        objects.put("U5Inverse", capU5Inverse);
        objects.put("g1", g1);
        objects.put("g2", g2);
        objects.put("T1Inverse", capT1Inverse);
        objects.put("T2Inverse", capT2Inverse);
        objects.put("g", g);
        objects.put("h", h);
        objects.put("y1Inverse", y1.modInverse(n1));
        objects.put("y2Inverse", y2.modInverse(n1));
        objects.put("h1", h1);
        objects.put("h2", h2);
    }

    @Override
    protected void inputFreeVars() {
        freeVars.put("keppa", keppa);
        freeVars.put("delta", delta);
        freeVars.put("alpha3", alpha3);
        freeVars.put("alpha4", alpha4);
        freeVars.put("r1", r1);
        freeVars.put("r2", r2);
        freeVars.put("r1Prime", r1Prime);
        freeVars.put("r2Prime", r2Prime);
    }

    @Override
    protected void inputLengthConditions() {}

    @Override
    protected void createRelations() {
        super.createRelations(nRelations);
        TreeMap<String, Pair<String, BigInteger>> relationRow;

        // U4 = g1^keppa.g2^alpha3 (mod Modulus)
        relationRow = relations.get(0);
        relationRow.put("g1", createNewPair("keppa", keppa));
        relationRow.put("g2", createNewPair("alpha3", alpha3));
        relationRow.put("U4Inverse", createNewPair("1", ONE));
        listMod.add(Modulus);

        // U5 = g1^delta.g2^alpha4 (mod Modulus)
        relationRow = relations.get(1);
        relationRow.put("g1", createNewPair("delta", delta));
        relationRow.put("g2", createNewPair("alpha4", alpha4));
        relationRow.put("U5Inverse", createNewPair("1", ONE));
        listMod.add(Modulus);

        // T1 = g^keppa.h^r1 (mod n)
        relationRow = relations.get(2);
        relationRow.put("g", createNewPair("keppa", keppa));
        relationRow.put("h", createNewPair("r1", r1));
        relationRow.put("T1Inverse", createNewPair("1", ONE));
        listMod.add(n);

        // T2 = g^delta.h^r2 (mod n)
        relationRow = relations.get(3);
        relationRow.put("g", createNewPair("delta", delta));
        relationRow.put("h", createNewPair("r2", r2));
        relationRow.put("T2Inverse", createNewPair("1", ONE));
        listMod.add(n);

        // y1 = h1^r1Prime.h2^keppa (mod n1)
        relationRow = relations.get(4);
        relationRow.put("h1", createNewPair("r1Prime", r1Prime));
        relationRow.put("h2", createNewPair("keppa", keppa));
        relationRow.put("y1Inverse", createNewPair("1", ONE));
        listMod.add(n1);

        // y2 = h1^r2Prime.h2^delta (mod n1)
        relationRow = relations.get(5);
        relationRow.put("h1", createNewPair("r2Prime", r2Prime));
        relationRow.put("h2", createNewPair("delta", delta));
        relationRow.put("y2Inverse", createNewPair("1", ONE));
        listMod.add(n1);
    }

    protected boolean checkRelations() {
        BigInteger N = publicKey.getN();
        int i = 0;
        for(TreeMap<String, Pair<String, BigInteger>> row : relations) {
            BigInteger mod = listMod.get(i);
            BigInteger P = BigInteger.ONE;
            for(Map.Entry<String, Pair<String, BigInteger>> entry : row.entrySet()) {
                String objectName = entry.getKey();
                BigInteger Aj = objects.get(objectName);
                Pair<String, BigInteger> cell = entry.getValue();
                String freeVarName = cell.getKey();
                BigInteger value = cell.getValue();
                if (freeVars.containsKey(freeVarName) || !freeVarName.equals("")) {
                    P = P.multiply(Aj.modPow(value, mod)).mod(mod);
                }
            }
            if (!P.equals(BigInteger.ONE)) return false;
            ++i;
        }
        return true;
    }

    public CategoryType23Proof buildProof() {
        int nFreeVars = freeVars.size();
        int nRelations = relations.size();
        int nObjects = objects.size();

        // Compute random tw
        twList = new TreeMap<>();
        for(Map.Entry<String, BigInteger> entry : freeVars.entrySet()) {
            String freeVarName = entry.getKey();
            BigInteger tw;
            if (bitLengthLowerBounds.containsKey(freeVarName))
                tw = Utils.computeRandomNumber(bitLengthUpperBounds.get(freeVarName) - 2);
            else tw = Utils.computeRandomNumber(sp.getL_m());
            twList.put(freeVarName, tw);
        }

        // Compute tValues B[i]
        Vector<BigInteger> bList = new Vector<>();
        for(int i = 0; i < nRelations; ++i) {
            BigInteger mod = listMod.get(i);
            TreeMap<String, Pair<String, BigInteger>> relation = relations.get(i);
            BigInteger B = BigInteger.ONE;
            for(Map.Entry<String, Pair<String, BigInteger>> relationElem : relation.entrySet()) {
                String objectName = relationElem.getKey();
                BigInteger Aj = objects.get(objectName);
                Pair<String, BigInteger> tmp = relationElem.getValue();
                String freeVarName = tmp.getKey();
                if (twList.containsKey(freeVarName)) {
                    BigInteger tw = twList.get(freeVarName);
                    try {
                        B = B.multiply(Aj.modPow(tw, mod)).mod(mod);
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println(freeVarName);
                        System.out.println("tw = " + tw);
                        System.out.println("mod = " + mod);
                        System.out.println("object name = " + objectName);
                        System.out.println("Aj = " + Aj);
                    }
                }
            }
            bList.add(B);
        }

        // Compute challenge Fiat-Shamir Heuristic
        for(Map.Entry<String, BigInteger> entry : objects.entrySet()) {
            if (entry.getValue() == null) {
                System.out.println("object " + entry.getKey() + " null");
            }
        }
        BigInteger challenge = computeChallenge(sp, AuxUtils.treeMapToList(objects), bList, nonce);

        // Compute sValues
        for(Map.Entry<String, BigInteger> entry : twList.entrySet()) {
            String freeVarName = entry.getKey();
            BigInteger tw = entry.getValue();
            BigInteger xw = freeVars.get(freeVarName);
            BigInteger sw = tw.subtract(challenge.multiply(xw));
            if (bitLengthLowerBounds.containsKey(freeVarName)) {
                int lowerBoundBitLenght = bitLengthLowerBounds.get(freeVarName);
                sw = sw.add(challenge.shiftLeft(lowerBoundBitLenght));
            }
            sValues.put(freeVarName, sw);
        }

        // Build Proof
        CategoryType23Proof proof = new CategoryType23Proof(challenge, sValues, bList, objects, freeVarNames,
                bitLengthLowerBounds, bitLengthUpperBounds, commonRelations, listMod);
        //System.out.println("Created SPKProof");
        return proof;
    }
}
