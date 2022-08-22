package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType1.CategoryType1SPKVerifier;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2Proof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2SPKVerifier;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.Vector;

public class CategorySPKVerifier {
    CategoryProof categoryProof;
    SystemParameters sp;
    Vector<Pair<TreeMapProof, CategoryType2Proof>> proofMeritList;
    Vector<Pair<TreeMapProof, CategoryType2Proof>> proofBlackList;

    public CategorySPKVerifier(CategoryProof _categoryProof, SystemParameters _sp) {
        categoryProof = _categoryProof;
        sp = _sp;
    }

    public Boolean verify() {
        Vector<BigInteger> auxMeritList = categoryProof.getAuxMeritList();
        Vector<BigInteger> auxBlackList = categoryProof.getAuxBlackList();
        proofMeritList = categoryProof.getProofMeritList();
        proofBlackList = categoryProof.getProofBlackList();
        TreeMapProof finalProof = categoryProof.getProofFinal();

        System.out.println("Proof MeritList");
        boolean verifyMeritListProofResult = verifyList(auxMeritList, proofMeritList);
        System.out.println("Proof BlackList");
        boolean verifyBlackListProofResult = verifyList(auxBlackList, proofBlackList);
        boolean verifyFinalProofResult = verifyFinalProof(finalProof);
        if (!verifyFinalProofResult) {
            System.out.println("Final Proof False");
        } else {
            System.out.println("Final Proof True");
        }

        return (verifyMeritListProofResult & verifyBlackListProofResult & verifyFinalProofResult);
    }

    private boolean verifyList(Vector<BigInteger> auxList,
                               Vector<Pair<TreeMapProof, CategoryType2Proof>> proofList) {
        int l = proofList.size();
        boolean result = true;
        for(int i = 0; i < l; ++i) {
            Pair<TreeMapProof, CategoryType2Proof> proof = proofList.get(i);
            TreeMapProof categoryType1Proof = proof.getKey();
            CategoryType2Proof categoryType2Proof = proof.getValue();
            SPKVerifierInterface categoryType1SPKVerifier = new CategoryType1SPKVerifier(
                    categoryType1Proof, sp);
            CategoryType2SPKVerifier categoryType2SPKVerifier = new CategoryType2SPKVerifier(
                    categoryType2Proof, sp);

            System.out.println();
            System.out.println("score " + i);
            System.out.println("type1");
            boolean res;
            boolean res1 = categoryType1SPKVerifier.verify();
            if (res1) {
                res = res1;
            }
            else {
                System.out.println("type2");
                boolean res2 = categoryType2SPKVerifier.verify();
                if (res2) {
                    System.out.println("Type2 true");
                }
                else {
                    System.out.println("Type2 false");
                }
                System.out.println();
                res = res2;
            }
            result &= res;
        }
        return result;
    }

    private boolean verifyFinalProof(TreeMapProof finalProof) {
        FinalProofSPKVerifier finalProofSPKVerifier = new FinalProofSPKVerifier(
                finalProof, sp, proofMeritList, proofBlackList);
        return finalProofSPKVerifier.verify();
    }
}
