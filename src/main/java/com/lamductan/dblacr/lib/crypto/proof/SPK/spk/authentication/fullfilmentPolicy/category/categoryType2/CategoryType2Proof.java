package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2;

import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23.CategoryType23Proof;

import java.io.Serializable;
import java.math.BigInteger;

public class CategoryType2Proof implements IProof, Serializable {
    private static final long serialVersionUID = 65296850982677569L;

    private TreeMapProof categoryType21Proof;
    private TreeMapProof categoryType22Proof;
    private CategoryType23Proof categoryType23Proof;

    public CategoryType2Proof(TreeMapProof _categoryType21Proof,
                              TreeMapProof _categoryType22Proof,
                              CategoryType23Proof _categoryType23Proof) {
        categoryType21Proof = _categoryType21Proof;
        categoryType22Proof = _categoryType22Proof;
        categoryType23Proof = _categoryType23Proof;
    }

    public TreeMapProof getCategoryType21Proof() {
        return categoryType21Proof;
    }
    public TreeMapProof getCategoryType22Proof() {
        return categoryType22Proof;
    }

    public CategoryType23Proof getCategoryType23Proof() {
        return categoryType23Proof;
    }

    public BigInteger getModulus() {
        return null;
    }
}
