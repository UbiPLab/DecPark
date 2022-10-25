package com.lamductan.dblacr.lib.blockchain;

import com.ibm.zurich.idmx.dm.Nym;
import com.lamductan.dblacr.lib.crypto.proof.IProof;

import com.lamductan.dblacr.lib.crypto.key.PublicKey;

import java.io.Serializable;

public class RegistrationRecord extends BlockchainObject implements Serializable {
    private static final long serialVersionUID = 6529685098267757691L;

    private Nym nym;
    private PublicKey pk;
    private IProof proof;

    public RegistrationRecord(Nym _nym, PublicKey _pk, IProof _proof) {
        nym = _nym;
        pk = _pk;
        proof = _proof;
    }

    public Nym getNym() {return nym;}
    public PublicKey getPublicKey() {return pk;}
    public IProof getProof() {return proof;}

    public String toString() {
        return nym.toString();
    }

    @Override
    public String getType() {return "RegistrationRecord";}
}
