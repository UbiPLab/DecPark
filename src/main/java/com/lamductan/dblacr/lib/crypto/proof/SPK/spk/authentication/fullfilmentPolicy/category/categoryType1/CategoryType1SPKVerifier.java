package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType1;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;

import java.math.BigInteger;

public class CategoryType1SPKVerifier extends SPKVerifierInterface {

    public CategoryType1SPKVerifier(IProof proof, SystemParameters _sp) {
        super(proof, _sp, ONE);
    }

    @Override
    public boolean verify() {
        BigInteger capU1Inverse = objects.get("U1Inverse");
        if (capU1Inverse.equals(ONE)) {
            System.out.println("Type1 false: t_i == b_i^x");
            return false;
        }
        else {
            System.out.println("Type1 true: t_i != b_i^x" );
            return super.verify();
        }
    }
}
