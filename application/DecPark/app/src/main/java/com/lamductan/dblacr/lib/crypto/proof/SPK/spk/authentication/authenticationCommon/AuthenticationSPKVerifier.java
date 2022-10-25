package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;

import java.math.BigInteger;

public class AuthenticationSPKVerifier extends SPKVerifierInterface {
    public AuthenticationSPKVerifier(IProof proof, SystemParameters _sp, BigInteger _nonce) {
        super(proof, _sp, _nonce);
    }
}
