package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignatureVerifier;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType22.CategoryType22SPKProver;

import java.math.BigInteger;
import java.util.Vector;

public class FinalProofSPKProver extends CategoryType22SPKProver {

    //TODO: Paper 16: SPK(CLSignature in QRn, Commitment in QRN)

    public FinalProofSPKProver(SystemParameters sp, Vector<BigInteger> _witnesses, CLSignature _clSignature,
                               BigInteger _g1, BigInteger _g2, BigInteger _r) {
        super(sp, _witnesses, _clSignature);
        System.out.println("Score = " + witnesses.get(0));

        CLSignatureVerifier clSignatureVerifier = new CLSignatureVerifier(clSignature, sp);
        System.out.println("Score satisfies threshold: " + clSignatureVerifier.verify(witnesses.get(0)));
    }
}
