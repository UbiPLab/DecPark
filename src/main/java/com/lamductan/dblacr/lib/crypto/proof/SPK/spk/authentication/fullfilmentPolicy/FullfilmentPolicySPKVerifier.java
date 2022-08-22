package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.CategoryProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.CategorySPKVerifier;

import java.util.Vector;

public class FullfilmentPolicySPKVerifier {
    Vector<CategoryProof> categoryProofs;
    SystemParameters sp;

    public FullfilmentPolicySPKVerifier(IProof _fullfilmentPolicyProof, SystemParameters _sp) {
        categoryProofs = ((FullFilmentPolicyProof) _fullfilmentPolicyProof).getCategoryProofs();
        sp = _sp;
    }

    public Vector<Boolean> verify() {
        Vector<Boolean> results = new Vector<>();
        for(CategoryProof categoryProof : categoryProofs) {
            CategorySPKVerifier categorySPKVerifier = new CategorySPKVerifier(categoryProof, sp);
            results.add(categorySPKVerifier.verify());
        }
        return results;
    }
}
