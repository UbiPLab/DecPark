package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy;

import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.CategoryProof;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

public class FullFilmentPolicyProof implements IProof, Serializable {
    private static final long serialVersionUID = 6529685098267757670L;

    private Vector<CategoryProof> categoryProofs;

    public FullFilmentPolicyProof() {
        categoryProofs = new Vector<>();
    }

    public FullFilmentPolicyProof(Vector<CategoryProof> _categoryProofs) {
        categoryProofs = _categoryProofs;
    }

    public Vector<CategoryProof> getCategoryProofs() {return categoryProofs;}


    @Override
    public BigInteger getModulus() {
        return null;
    }
}
