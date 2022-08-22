package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKProverInterface;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;

import java.math.BigInteger;

public abstract class AuthenticationSPKProver extends SPKProverInterface {
    protected Ticket tau;
    protected Requirement requirement;

    public AuthenticationSPKProver(SystemParameters _sp, GroupParameters _gp,
                                   PrivateKey _privateKey, PublicKey _publicKey,
                                   BigInteger _nonce, Ticket _tau, Requirement _requirement) {
        super(_sp, _gp, _privateKey, _publicKey, _nonce);
        tau = _tau;
        requirement = _requirement;
        super.inputObjectsFreeVarsRelations();
    }

    public Ticket getTau() {return tau;}
    public Requirement getRequirement() {return requirement;}
}
