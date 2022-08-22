package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.ticketValidation;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.math.BigInteger;
import java.util.Vector;

public class TicketValidateSPKVerifier extends SPKVerifierInterface {
    private Vector<BigInteger> listPublicKey;
    private BigInteger g;

    public TicketValidateSPKVerifier(IProof proof,
                                     SystemParameters _sp,
                                     BigInteger _nonce, Vector<BigInteger> _listPublicKey) {
        super(proof, _sp, _nonce);
        listPublicKey = _listPublicKey;
        g = ((TreeMapProof) proof).getG();
    }

    public boolean verify() {
        System.out.println("Verify Ticket");
        BigInteger v = g.modPow(Utils.product(listPublicKey), Modulus);
        BigInteger vPrime = objects.get("v");
        if (!v.equals(vPrime)) {
            System.out.println("v  = " + v);
            System.out.println("v' = " + vPrime);
            System.out.println("Wrong v");
            return false;
        }
        return super.verify();
    }
}
