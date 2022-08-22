package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.registration;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;

import java.math.BigInteger;

public class PossessKeySPKVerifier extends SPKVerifierInterface {
    private PublicKey publicKey;

    public PossessKeySPKVerifier(IProof proof,
                                 SystemParameters _sp,
                                 BigInteger _nonce, PublicKey _publicKey) {
        super(proof, _sp, _nonce);
        publicKey = _publicKey;
    }

    public PublicKey getPublicKey() {return publicKey;}

    public boolean verify() {
        BigInteger N = publicKey.getN();
        BigInteger NPrime = commonRelations.get(4).get("g").getValue();
        if (!N.equals(NPrime) && !N.equals(NPrime.negate())) return false;
        return super.verify();
    }
}
