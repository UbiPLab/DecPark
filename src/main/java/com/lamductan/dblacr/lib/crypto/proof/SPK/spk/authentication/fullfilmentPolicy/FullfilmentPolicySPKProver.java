package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.CategoryProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.CategorySPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class FullfilmentPolicySPKProver{
    private SystemParameters sp;
    private GroupParameters gp;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Ticket tau;
    private Requirement requirement;
    private int nCategories;
    private Vector<CategorySPKProver> categorySPKProvers;
    private Vector<Vector<ScoreRecord>> scoreRecordByCategories;
    private BigInteger g1;
    private BigInteger g2;

    public FullfilmentPolicySPKProver(SystemParameters _sp, GroupParameters _gp, PrivateKey _privateKey,
                                      PublicKey _publicKey, Ticket _tau, Requirement _requirement) {
        sp = _sp;
        gp = _gp;
        privateKey = _privateKey;
        publicKey = _publicKey;
        tau = _tau;
        requirement = _requirement;
        nCategories = requirement.getNCategories();
        g1 = Utils.computeGeneratorQuadraticResidue(publicKey.getModulus(), sp);
        g2 = Utils.computeGeneratorQuadraticResidue(publicKey.getModulus(), sp);
        createScoreRecordByCategories();
        createCategorySPKProvers();
    }

    private void createScoreRecordByCategories() {
        scoreRecordByCategories = new Vector<>();
        for(int i = 0; i < nCategories; ++i) {
            scoreRecordByCategories.add(new Vector<>());
        }
        for(ScoreRecord scoreRecord : requirement.getScoreRecords()) {
            int sid = scoreRecord.getSid();
            int tid = scoreRecord.getTid();
            Ticket tau = scoreRecord.getTicket();
            Vector<Pair<Integer, Integer>> s = scoreRecord.getS();
            for(int i = 0; i < nCategories; ++i) {
                Vector<Pair<Integer, Integer>> scoreOfCategory = new Vector<>();
                scoreOfCategory.add(s.get(i));
                ScoreRecord scoreRecordByCategory = new ScoreRecord(sid, tid, tau, scoreOfCategory);
                scoreRecordByCategories.elementAt(i).add(scoreRecordByCategory);
            }
        }
    }

    private void createCategorySPKProvers() {
        categorySPKProvers = new Vector<>();
        Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorMeritList =
                requirement.getAdjustingFactorMeritList();
        Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorBlackList =
                requirement.getAdjustingFactorBlackList();
        Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> thresholdList = requirement.getThresholdList();
        Vector<Pair<String, Integer>> thresholdLimit = requirement.getThresholdLimit();
        for(int i = 0; i < nCategories; ++i) {
            Vector<ScoreRecord> scoreRecordByCategory = scoreRecordByCategories.elementAt(i);
            CategorySPKProver categorySPKProver = new CategorySPKProver(
                    sp, gp, privateKey, publicKey, tau, scoreRecordByCategory,
                    adjustingFactorMeritList.get(i), adjustingFactorBlackList.get(i),
                    thresholdList.get(i), thresholdLimit.get(i), g1, g2);

            categorySPKProvers.add(categorySPKProver);
        }
    }

    public FullFilmentPolicyProof buildFullFilmentPolicyProof() {
        Vector<CategoryProof> categoryProofs = new Vector<>();
        for(CategorySPKProver categorySPKProver : categorySPKProvers)
            categoryProofs.add(categorySPKProver.buildProof());

        FullFilmentPolicyProof fullFilmentPolicyProof = new FullFilmentPolicyProof(categoryProofs);
        return fullFilmentPolicyProof;
    }
}
