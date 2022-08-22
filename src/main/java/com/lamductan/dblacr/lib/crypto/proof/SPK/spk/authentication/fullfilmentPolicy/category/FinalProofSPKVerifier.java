package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2Proof;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.Vector;

public class FinalProofSPKVerifier extends SPKVerifierInterface {
    private Vector<Pair<TreeMapProof, CategoryType2Proof>> proofMeritList;
    private Vector<Pair<TreeMapProof, CategoryType2Proof>> proofBlackList;

    //TODO: Paper 16: SPK(CLSignature in QRn, Commitment in QRN)

    public FinalProofSPKVerifier(IProof proof, SystemParameters _sp,
                                 Vector<Pair<TreeMapProof, CategoryType2Proof>> _proofMeritList,
                                 Vector<Pair<TreeMapProof, CategoryType2Proof>> _proofBlackList) {
        super(proof, _sp, ONE);
        proofMeritList = _proofMeritList;
        proofBlackList = _proofBlackList;
    }

    @Override
    public boolean verify() {
        /*
        BigInteger capC = ONE;
        for(int i = 0; i < proofMeritList.size(); ++i) {
            capC = capC.multiply(
                    proofMeritList.get(i).getValue().getObjectList().get("CInverse")).mod(Modulus);
        }
        for(int i = 0; i < proofBlackList.size(); ++i) {
            capC = capC.multiply(
                    proofBlackList.get(i).getValue().getObjectList().get("CInverse")).mod(Modulus);
        }
        BigInteger capCPrime = objects.get("T0Inverse");
        if (!capC.equals(capCPrime)) {
            System.out.println("Wrong total commit");
            return false;
        }
        */
        return super.verify();
    }
}
