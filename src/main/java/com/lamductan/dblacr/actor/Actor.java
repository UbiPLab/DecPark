package com.lamductan.dblacr.actor;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.RegistrationRecord;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.SPKVerifierInterface;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon.AuthenticationProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullFilmentPolicyProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullfilmentPolicySPKVerifier;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.registration.PossessKeySPKVerifier;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.ticketValidation.TicketValidateSPKVerifier;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

public abstract class Actor implements Serializable {
    private static final long serialVersionUID = 6529685098267757699L;
    protected DBLACRSystem dblacrSystem;
    protected SystemParameters sp;

    public Actor() {
        dblacrSystem = DBLACRSystem.getInstance();
        sp = dblacrSystem.getSystemParameters();
    }

    protected void pushToSystem(BlockchainObject blockchainObject) {
        dblacrSystem.receiveRecord(blockchainObject);
    }

    protected boolean verifyRegistrationProof(BlockchainObject registrationRecord, BigInteger nonce) {
        IProof proof = ((RegistrationRecord) registrationRecord).getProof();
        PublicKey pk = ((RegistrationRecord) registrationRecord).getPublicKey();
        SPKVerifierInterface possessKeySPKVerifier = new PossessKeySPKVerifier(proof, sp, nonce, pk);
        long start = System.currentTimeMillis();
        boolean res = possessKeySPKVerifier.verify();
        long end = System.currentTimeMillis();
        System.out.println("Verify registration record: " + res+"Verify registration time"+(end-start)+"ms");
        return res;
    }

    protected boolean verifyAuthenticationRecord(BlockchainObject authenticationRecord,
                                               BigInteger nonce, Requirement requirement) {
        long startTime = System.currentTimeMillis();
        AuthenticationProof authenticationProof =
                (AuthenticationProof) ((AuthenticationRecord) authenticationRecord).getProof();
        Vector<PublicKey> C = requirement.getC();
        Vector<BigInteger> listPublicKey = AuxUtils.getListN(C);

        IProof ticketValidateProof = authenticationProof.getTicketValidateProof();
        SPKVerifierInterface ticketValidateSPKVerifier = new TicketValidateSPKVerifier(
                ticketValidateProof, sp, nonce, listPublicKey);
        boolean ticketValidateResult = ticketValidateSPKVerifier.verify();
        System.out.println("Verify ticket: " + ticketValidateResult);

        if (ticketValidateResult) {
            FullFilmentPolicyProof fullfilmentPolicyProof = authenticationProof.getFullfilmentPolicyProof();
            FullfilmentPolicySPKVerifier fullfilmentPolicySPKVerifier = new FullfilmentPolicySPKVerifier(
                    fullfilmentPolicyProof, sp);
            Vector<Boolean> fullfilmentPolicyResults = fullfilmentPolicySPKVerifier.verify();
            System.out.println("Verify fullfilment policy: " + fullfilmentPolicyResults);

            boolean fullfilmentResult = true;
            for (boolean fullfilmentPolicyResult : fullfilmentPolicyResults)
                fullfilmentResult |= fullfilmentPolicyResult;

            long endTime = System.currentTimeMillis();
            System.out.println("Verify Authenticate Proof in " + (endTime - startTime) * 1.0 / 1000 + "s");
            return fullfilmentResult;
        } else {
            return false;
        }
    }
}
