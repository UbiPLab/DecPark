package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23.CategoryType23Proof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23.CategoryType23SPKVerifier;

import java.math.BigInteger;

public class CategoryType2SPKVerifier {
    private SPKVerifierInterface categoryType21SPKVerifier;
    private SPKVerifierInterface categoryType22SPKVerifier;
    private CategoryType23SPKVerifier categoryType23SPKVerifier;
    private SystemParameters sp;

    public CategoryType2SPKVerifier(CategoryType2Proof proof, SystemParameters _sp) {
        sp = _sp;
        TreeMapProof categoryType21Proof = proof.getCategoryType21Proof();
        categoryType21SPKVerifier = new SPKVerifierInterface(categoryType21Proof, sp, BigInteger.ONE);
        TreeMapProof categoryType22Proof = proof.getCategoryType22Proof();
        categoryType22SPKVerifier = new SPKVerifierInterface(categoryType22Proof, sp, BigInteger.ONE);
        CategoryType23Proof categoryType23Proof = proof.getCategoryType23Proof();
        categoryType23SPKVerifier = new CategoryType23SPKVerifier(categoryType23Proof, sp);
    }

    public boolean verify() {
        System.out.println("Verify CategoryType1");
        boolean type1 = categoryType21SPKVerifier.verify();
        System.out.println("Verify CategoryType2");
        boolean type2 = categoryType22SPKVerifier.verify();
        System.out.println("Verify CategoryType3");
        boolean type3 = categoryType23SPKVerifier.verify();
        return (type1 & type2 & type3);
    }
}
