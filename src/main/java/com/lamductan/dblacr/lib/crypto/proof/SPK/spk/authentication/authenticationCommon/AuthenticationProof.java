package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon;

import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullFilmentPolicyProof;

import java.io.Serializable;
import java.math.BigInteger;

public class AuthenticationProof implements IProof, Serializable {
    private static final long serialVersionUID = 6529685098267757679L;

    private TreeMapProof ticketValidateProof;
    private FullFilmentPolicyProof fullfilmentPolicyProof;
    public AuthenticationProof(TreeMapProof _ticketValidateProof, FullFilmentPolicyProof _fullfilmentPolicyProof) {
        ticketValidateProof = _ticketValidateProof;
        fullfilmentPolicyProof = _fullfilmentPolicyProof;
    }

    public TreeMapProof getTicketValidateProof() { return ticketValidateProof; }
    public FullFilmentPolicyProof getFullfilmentPolicyProof() {return fullfilmentPolicyProof;}

    @Override
    public BigInteger getModulus() {
        return ticketValidateProof.getModulus();
    }
}
