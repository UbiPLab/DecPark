package com.lamductan.dblacr.lib.blockchain;

import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;

import java.io.Serializable;

public class AuthenticationRecord extends BlockchainObject implements Serializable {
    private static final long serialVersionUID = 6529685098267757681L;

    private int tid;
    private int sid;
    private Ticket tau;
    private PublicKey publicKey;
    private IProof authenticationProof;

    public AuthenticationRecord(int _tid, int _sid, Ticket _tau, PublicKey _publicKey, IProof _authenticationProof) {
        tid = _tid;
        sid = _sid;
        tau = _tau;
        publicKey = _publicKey;
        authenticationProof = _authenticationProof;
    }

    public int getTid() {return tid;}
    public int getSid() {return sid;}
    public Ticket getTau() {return tau;}
    public IProof getProof() {return authenticationProof;}

    @Override
    public String getType() {return "AuthenticationRecord";}
}
