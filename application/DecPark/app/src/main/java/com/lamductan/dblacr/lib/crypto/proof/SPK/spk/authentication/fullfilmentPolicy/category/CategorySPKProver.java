package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignaturePublicKey;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType1.CategoryType1SPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2Proof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2SPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.system.DBLACRSystem;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class CategorySPKProver {
    SystemParameters sp;
    GroupParameters gp;
    PrivateKey privateKey;
    PublicKey publicKey;
    Ticket tau;
    Vector<ScoreRecord> scoreRecords;
    Vector<ScoreRecord> scoreMeritList;
    Vector<ScoreRecord> scoreBlackList;
    Vector<BigInteger> auxMeritList;
    Vector<BigInteger> auxBlackList;
    Vector<Pair<BigInteger, CLSignature>> adjustingFactorMeritList;
    Vector<Pair<BigInteger, CLSignature>> adjustingFactorBlackList;
    Pair<Integer, TreeMap<Integer, CLSignature>> threshold;
    Pair<String, Integer> thresholdLimit;
    BigInteger g1;
    BigInteger g2;
    BigInteger Modulus;
    CLSignature sampleClSignature;

    public CategorySPKProver(SystemParameters _sp, GroupParameters _gp,
                             PrivateKey _privateKey, PublicKey _publicKey, Ticket _tau,
                             Vector<ScoreRecord> _scoreRecords,
                             Vector<Pair<BigInteger, CLSignature>> _adjustingFactorMeritList,
                             Vector<Pair<BigInteger, CLSignature>> _adjustingFactorBlackList,
                             Pair<Integer, TreeMap<Integer, CLSignature>> _threshold,
                             Pair<String, Integer> _thresholdLimit,
                             BigInteger _g1, BigInteger _g2) {
        sp = _sp;
        gp = _gp;
        privateKey = _privateKey;
        publicKey = _publicKey;
        Modulus = publicKey.getModulus();
        tau = _tau;
        scoreRecords = _scoreRecords;
        adjustingFactorMeritList = _adjustingFactorMeritList;
        adjustingFactorBlackList = _adjustingFactorBlackList;
        threshold = _threshold;
        thresholdLimit = _thresholdLimit;
        g1 = _g1;
        g2 = _g2;

        splitScoreList(scoreRecords);
        auxMeritList = new Vector<>();
        auxBlackList = new Vector<>();

        sampleClSignature = createSampleCLSignature();
    }

    private void splitScoreList(Vector<ScoreRecord> scoreRecordByCategory) {
        scoreMeritList = new Vector<>();
        scoreBlackList = new Vector<>();
        for(ScoreRecord scoreRecord : scoreRecordByCategory) {
            int score = scoreRecord.getS().get(0).getValue();
            if (score >= 0) scoreMeritList.add(scoreRecord);
            else scoreBlackList.add(scoreRecord);
        }
    }


    public Pair<Vector<Pair<TreeMapProof, CategoryType2Proof>>,
            Pair<Vector<BigInteger>, Pair<Integer, BigInteger>>> buildMeritOrBlackListProof(
            Vector<ScoreRecord> scoreList,
            Vector<Pair<BigInteger, CLSignature>> adjustingFactorList) {

        Vector<Pair<TreeMapProof, CategoryType2Proof>> listProofs = new Vector<>();
        Vector<BigInteger> auxList = new Vector<>();
        int scoreTotal = 0;
        BigInteger sumGamma = BigInteger.ZERO;
        Vector<BigInteger> gammaTildeList = new Vector<>();
        int l = scoreList.size();
        int k = 0;
        for(int i = 0; i < l; ++i) {
            ScoreRecord scoreRecord = scoreList.get(i);
            int score = scoreRecord.getS().get(0).getValue();
            Ticket tau_i = scoreRecord.getTicket();
            BigInteger delta = BigInteger.ZERO;
            CLSignature clSignature = sampleClSignature;
            boolean checktau_i = tau_i.verify(privateKey);
            if (checktau_i) {
                //System.out.println("Check tau_i");
                Pair<BigInteger, CLSignature> deltaAndSignature = adjustingFactorList.get(k);
                delta = deltaAndSignature.getKey();
                clSignature = deltaAndSignature.getValue();
                scoreTotal += delta.intValue()*score;
            }
            CategoryType1SPKProver categoryType1SPKProver = new CategoryType1SPKProver(
                    sp, gp, privateKey, publicKey, tau, tau_i, g1, g2);
            TreeMapProof type1Proof = categoryType1SPKProver.buildProof();

            CategoryType2SPKProver categoryType2SPKProver = new CategoryType2SPKProver(
                    sp, gp, privateKey, publicKey, tau, tau_i, g1, g2,
                    score, delta, k, clSignature, auxList, gammaTildeList,
                    threshold, thresholdLimit);
            CategoryType2Proof type2Proof = (CategoryType2Proof) categoryType2SPKProver.buildProof();
            listProofs.add(new Pair<>(type1Proof, type2Proof));

            BigInteger c, cTilde, gamma, gammaTilde;
            if (!checktau_i) {
                c = categoryType1SPKProver.getC();
                cTilde = categoryType1SPKProver.getCTilde();
                gamma = categoryType1SPKProver.getGamma();
                gammaTilde = categoryType1SPKProver.getGammaTilde();
            } else {
                c = categoryType2SPKProver.getC();
                cTilde = categoryType2SPKProver.getCTilde();
                gamma = categoryType2SPKProver.getGamma();
                gammaTilde = categoryType2SPKProver.getGammaTilde();
                ++k;
            }
            auxList.add(c);
            auxList.add(cTilde);
            sumGamma = sumGamma.add(gamma);
            gammaTildeList.add(gammaTilde);
        }
        return new Pair<>(listProofs, new Pair(auxList, new Pair(scoreTotal, sumGamma)));
    }


    private CLSignature createSampleCLSignature() {
        Vector<BigInteger> A = new Vector<>();
        A.add(BigInteger.ONE);
        A.add(BigInteger.ONE);
        CLSignaturePublicKey clSignaturePublicKey = new CLSignaturePublicKey(DBLACRSystem.getModulus(), A,
                BigInteger.ONE, BigInteger.ZERO);
        CLSignature clSignature = new CLSignature(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE,
                clSignaturePublicKey);
        return clSignature;
    }


    public CategoryProof buildProof() {
        Pair<Vector<Pair<TreeMapProof, CategoryType2Proof>>,
                Pair<Vector<BigInteger>, Pair<Integer, BigInteger>>> tmp;
        tmp = buildMeritOrBlackListProof(
                scoreMeritList, adjustingFactorMeritList);
        Vector<Pair<TreeMapProof, CategoryType2Proof>> proofMeritList = tmp.getKey();
        auxMeritList = tmp.getValue().getKey();
        int meritScore = tmp.getValue().getValue().getKey();
        BigInteger sumGammaMerit = tmp.getValue().getValue().getValue();

        tmp = buildMeritOrBlackListProof(
                scoreBlackList, adjustingFactorBlackList);
        Vector<Pair<TreeMapProof, CategoryType2Proof>> proofBlackList = tmp.getKey();
        auxBlackList = tmp.getValue().getKey();
        int blackScore = tmp.getValue().getValue().getKey();
        BigInteger sumGammaBlack = tmp.getValue().getValue().getValue();
        BigInteger sumGamma = sumGammaMerit.add(sumGammaBlack);

        TreeMapProof proofFinal = buildProofFinal(proofMeritList, proofBlackList,
                meritScore, blackScore, sumGamma);

        return new CategoryProof(auxMeritList, auxBlackList, proofMeritList, proofBlackList, proofFinal);
    }


    private TreeMapProof buildProofFinal(Vector<Pair<TreeMapProof, CategoryType2Proof>> proofMeritList,
                                         Vector<Pair<TreeMapProof, CategoryType2Proof>> proofBlackList,
                                         int meritScore, int blackScore, BigInteger sumGamma) {
        int totalScore = meritScore + blackScore;
        Vector<BigInteger> witness = new Vector<>();
        witness.add(BigInteger.valueOf(totalScore));

        CLSignature clSignature = sampleClSignature;
        if (threshold.getValue().containsKey(totalScore)) {
            clSignature = threshold.getValue().get(totalScore);
        }
        FinalProofSPKProver finalSPKProver = new FinalProofSPKProver(
                sp, witness, clSignature, g1, g2, sumGamma);
        return finalSPKProver.buildProof();
    }
}
