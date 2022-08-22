package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

public class CategoryType23SPKVerifier extends SPKVerifierInterface {
    private Vector<BigInteger> listMod;

    public CategoryType23SPKVerifier(CategoryType23Proof _categoryType23Proof, SystemParameters _sp) {
        super(_categoryType23Proof, _sp, ONE);
        listMod = _categoryType23Proof.getListMod();
    }

    public boolean verify() {
        int nRelations = commonRelations.size();

        System.out.println("Check bit length"); // TODO: Implement check length
        //System.out.println("sValues: " + sValues);
        //System.out.println("bitlength: " + bitLengthUpperBounds);
        /*
        for(Map.Entry<String, BigInteger> entry : sValues.entrySet()) {
            if (entry.getValue().bitLength() > bitLengthUpperBounds.get(entry.getKey()) - 1) {
                System.out.println(entry.getKey() + " " + entry.getValue().bitLength());
                return false;
            }
        }
        */

        System.out.println("Check by equations");
        for(int i = 0; i < nRelations; ++i) {
            BigInteger mod = listMod.get(i);
            // Compute P1 = \Prod{A^sw}
            BigInteger P1 = BigInteger.ONE;
            TreeMap<String, Pair<String, BigInteger>> commonRelationRow = commonRelations.get(i);
            for(Map.Entry<String, Pair<String, BigInteger>> commonRelationElem : commonRelationRow.entrySet()) {
                String objectName = commonRelationElem.getKey();
                Pair<String, BigInteger> tmp = commonRelationElem.getValue();
                String freeVarName = tmp.getKey();
                if (freeVarNames.contains(freeVarName)) {
                    BigInteger Aj = objects.get(objectName);
                    BigInteger sw = sValues.get(freeVarName);
                    P1 = P1.multiply(Aj.modPow(sw, mod)).mod(mod);
                }
            }

            // Compute P2 = B.P^c
            BigInteger P2 = BigInteger.ONE;
            for(Map.Entry<String, Pair<String, BigInteger>> commonRelationElem : commonRelationRow.entrySet()) {
                String objectName = commonRelationElem.getKey();
                BigInteger Aj = objects.get(objectName);
                Pair<String, BigInteger> tmp = commonRelationElem.getValue();
                String freeVarName = tmp.getKey();
                if (bitLengthLowerBounds.containsKey(freeVarName)) {
                    int lw = bitLengthLowerBounds.get(freeVarName);
                    BigInteger twoPowLw = BigInteger.ONE.shiftLeft(lw);
                    P2 = P2.multiply(Aj.modPow(twoPowLw, mod)).mod(mod);
                } else {
                    BigInteger value = tmp.getValue();
                    if (!value.equals(ZERO)) {
                        P2 = P2.multiply(Aj.modPow(value, mod)).mod(mod);
                    }
                }
            }
            BigInteger B = bList.get(i);
            P2 = P2.modPow(challenge, mod).multiply(B).mod(mod);

            if (!P1.equals(P2)) {
                System.out.println("Proof23 false in relation " + i);
                return false;
            }
        }
        System.out.println("Proof 23 true");
        return true;
    }
}
