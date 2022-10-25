package com.lamductan.dblacr.lib.crypto.proof.SPK.common;

import android.util.Log;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import javafx.util.Pair;


import javax.xml.bind.SchemaOutputResolver;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

public class SPKVerifierInterface extends SPKProverVerifierInterface {
    public SPKVerifierInterface(IProof proof, SystemParameters _sp, BigInteger _nonce) {
        super(_sp, _nonce);
        Modulus = proof.getModulus();
        objects = ((TreeMapProof) proof).getObjectList();
        freeVarNames = ((TreeMapProof) proof).getFreeVarNames();
        bitLengthLowerBounds = ((TreeMapProof) proof).getBitLengthLowerBounds();
        bitLengthUpperBounds = ((TreeMapProof) proof).getBitLengthUpperBounds();
        commonRelations = ((TreeMapProof) proof).getCommonRelations();
        sValues = ((TreeMapProof) proof).getSValues();
        challenge = ((TreeMapProof) proof).getChallenge();
        bList = ((TreeMapProof) proof).getBList();
    }

    public boolean verify() {
        int nRelations = commonRelations.size();

        System.out.println("Check bit length"); // TODO: Implement check length
        System.out.println("Check by equations");
        for(int i = 0; i < nRelations; ++i) {
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
                    P1 = P1.multiply(Aj.modPow(sw, Modulus)).mod(Modulus);
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
                    P2 = P2.multiply(Aj.modPow(twoPowLw, Modulus)).mod(Modulus);
                } else {
                    BigInteger value = tmp.getValue();
                    if (!value.equals(ZERO)) {
                        P2 = P2.multiply(Aj.modPow(value, Modulus)).mod(Modulus);
                    }
                }
            }
            BigInteger B = bList.get(i);
            P2 = P2.modPow(challenge, Modulus).multiply(B).mod(Modulus);

            if (!P1.equals(P2)) {
                Log.e("verify result","relation " + i + " wrong");
                return false;
            }
        }
        return true;
    }
}
