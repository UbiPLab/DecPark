package com.lamductan.dblacr.actor.user;

import com.carrotsearch.sizeof.RamUsageEstimator;
import com.ibm.zurich.idmx.dm.Nym;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.actor.Actor;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.RegistrationRecord;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon.AuthenticationProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullFilmentPolicyProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullfilmentPolicySPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.registration.PossessKeySPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.actor.sp.ServiceProvider;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.ticketValidation.TicketValidateSPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.io.Serializable;
import java.math.BigInteger;

public class User extends Actor implements Serializable {
    private static final long serialVersionUID = 6529685098267757697L;

    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    SystemParameters sp = DBLACRSystem.getInstance().getSystemParameters();
    GroupParameters gp = DBLACRSystem.getInstance().getGroupParamters();
    BigInteger context = DBLACRSystem.getInstance().getContext();

    public PublicKey getPublicKey() {return publicKey;}
    public PrivateKey getPrivateKey() {return privateKey;} //TODO: remove this function for security

    public User() {super();}


    /** Register Phase **/
    public boolean register() {
        if (privateKey == null || publicKey == null) {
            long startTime = System.currentTimeMillis();
            privateKey = new PrivateKey(sp);
            long endPrivKeyGen = System.currentTimeMillis();
            System.out.println("Generate privkey in " +
                    1.0 * (endPrivKeyGen - startTime)  + "ms");
            publicKey = new PublicKey(sp, gp, privateKey, 1, 0);
            privateKey.setPublicKey(publicKey);
//            System.out.println("Generate pubkey in " +
//                    1.0 * (endTime - endPrivKeyGen) / 1000 + "s");
        }
        //用户生成假名
        System.out.println("生成证据pi_1");
        long start = System.currentTimeMillis();
        Nym nym = new Nym(gp, publicKey.getN(), "nym");
        BigInteger nonce = Utils.computeRandomNumberSymmetric(sp.getL_m());
        IProof proof = createRegistrationProof(nonce);
        long end = System.currentTimeMillis();
        System.out.println("Generate pi_1 in " +
                1.0 * (end - start)  + "ms");
        BlockchainObject registrationRecord = new RegistrationRecord(nym, publicKey, proof);
        pushRegistrationRecord(registrationRecord);
        //验证用户证据
//        start = System.currentTimeMillis();
//        boolean b = verifyRegistrationProof(registrationRecord, nonce);
//        end = System.currentTimeMillis();
//        System.out.println("Verify pi_1 in " + 1.0 * (end - start)  + "ms");
        return verifyRegistrationProof(registrationRecord, nonce);
    }
    //用户生成注册证据
    public IProof createRegistrationProof(BigInteger nonce) {
        PossessKeySPKProver possessKeySPK = new PossessKeySPKProver(
                sp, gp, privateKey, publicKey, nonce);
        TreeMapProof proof = possessKeySPK.buildProof();
        return proof;
    }

    public void pushRegistrationRecord(BlockchainObject registrationRecord) {
        super.pushToSystem(registrationRecord);
        dblacrSystem.getUsers().add(this);
    }

    /** End Register Phase **/


    /** Authentication Phase **/
    public boolean authenticate(int sid) {
        ServiceProvider sp = dblacrSystem.getServiceProviderBySid(sid);
        Requirement requirement = sp.putRequirement();
        boolean checkRequirementResult = checkRequirement(requirement);
        //第一步先检查满足Requirement
        if (!checkRequirementResult) {
            System.out.println("User not satisfy requirement.");
            return false;
        }
        //第二步检查满足challenge
        BigInteger challenge = sp.computeChallenge();
        if (!checkChallenge(challenge, sid)) {
            System.out.println("Invalid challenge");
            return false;
        }
        //用户生成证据
        long start = System.currentTimeMillis();
        Ticket tau1 = new Ticket(privateKey);
        long end = System.currentTimeMillis();
        System.out.println("产生 tk 时间："+(end-start)+"ms");
        start = System.currentTimeMillis();
        IProof authenticationProof = createAuthenticationProof(tau1, requirement, challenge);
        end = System.currentTimeMillis();
        System.out.println("产生 pi_2 时间："+(end-start)+"ms");
        int newAuthenticationId = dblacrSystem.getNewAuthenticationId();
        BlockchainObject authenticationRecord = new AuthenticationRecord(
                newAuthenticationId, sid, tau1, publicKey, authenticationProof);
        pushToSystem(authenticationRecord);
        //第三步验证证据
        return verifyAuthenticationRecord(authenticationRecord, challenge, requirement);
    }

    private boolean checkChallenge(BigInteger challenge, int sid) {
        return true;
    }
    private boolean checkRequirement(Requirement requirement) {
        return true;
    }


    private IProof createAuthenticationProof(Ticket tau1, Requirement requirement, BigInteger challenge) {
        long startTime = System.currentTimeMillis();
        //生成Ticket有效性的SPK证据
        TicketValidateSPKProver ticketValidateSPK = new TicketValidateSPKProver(
                sp, gp, privateKey, publicKey, challenge, tau1, requirement);
        System.out.println("下面是pi_2生成过程");
        System.out.println("生成Ticket有效性的SPK证据:");
        TreeMapProof ticketValidateProof = ticketValidateSPK.buildProof();
        //生成满足Policy的SPK证据
        FullfilmentPolicySPKProver fullfilmentPolicySPKProver = new FullfilmentPolicySPKProver(
                sp, gp, privateKey, publicKey, tau1, requirement);
        System.out.println("生成fullfilment有效性的SPK证据:");
        FullFilmentPolicyProof fullfilmentPolicyProof = fullfilmentPolicySPKProver
                .buildFullFilmentPolicyProof();
        AuthenticationProof authenticationProof = new AuthenticationProof(
                ticketValidateProof, fullfilmentPolicyProof);
        long endTime = System.currentTimeMillis();
        System.out.println("Generate Authenticate Proof in " + (endTime - startTime)*1.0/1000 + "s");
        return authenticationProof;
    }
    /** End Authentication Phase **/
}
