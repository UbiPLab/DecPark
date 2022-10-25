package com.lamductan.dblacr.actor.sp;

import com.lamductan.dblacr.actor.Actor;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSigner;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ServiceProvider extends Actor implements Serializable {
    private static final long serialVersionUID = 6529685098267757683L;

    private int sid;
    private int nCategories = 2;
    private CLSigner clSigner;
    private Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorMeritList;
    private Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorBlackList;
    private Vector<Pair<String, Integer>> thresholdLimit;
    private Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> thresholdList;

    public ServiceProvider(int _nCategories) {
        super();
        sid = -1;
        nCategories = _nCategories;
        init();
    }

    public ServiceProvider(int _sid, int _nCategories) {
        super();
        sid = _sid;
        nCategories = _nCategories;
        init();
    }

    public ServiceProvider() {
        sid = dblacrSystem.getServiceProviders().size();
        nCategories = 2;
        init();
    }

    private void init() {
        long startTime = System.currentTimeMillis();
        clSigner = new CLSigner(dblacrSystem.getSystemParameters());
        adjustingFactorMeritList = initAdjustingFactor();
        adjustingFactorBlackList = initAdjustingFactor();
        initThreshold();
        long endTime = System.currentTimeMillis();
        System.out.println("Init a new Service Provider in " + 1.0 * (endTime - startTime) / 1000 + "s");
    }

    public void joinToSystem() {
        int newSid = dblacrSystem.addNewServiceProvider(this);
    }

    public Requirement putRequirement() {
        Vector<PublicKey> C = collectListPublicKeys();
        Vector<ScoreRecord> scoreRecords = collectScoreRecords();
        Requirement requirement = new Requirement(C, scoreRecords,
                adjustingFactorMeritList, adjustingFactorBlackList,
                thresholdList, thresholdLimit, nCategories);
        System.out.println("nCategories = " + nCategories);
        return requirement;
    }

    public Vector<ScoreRecord> collectScoreRecords() {
        return dblacrSystem.getListScores();
    }
    public Vector<PublicKey> collectListPublicKeys() {
        return dblacrSystem.getListPublicKey();
    }
    public int getSid() {return sid;}
    public int getNCategories() {return nCategories;}
    public Vector<Vector<Pair<BigInteger, CLSignature>>> getAdjustingFactorMeritList() {
        return adjustingFactorMeritList;}
    public Vector<Vector<Pair<BigInteger, CLSignature>>> getAdjustingFactorBlackList() {
        return adjustingFactorBlackList;}
    public Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> getThresholdList() {return thresholdList;}
    public Vector<Pair<String, Integer>> getThresholdLimit() {return thresholdLimit;}


    private Vector<Vector<Pair<BigInteger, CLSignature>>> initAdjustingFactor() {
        Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactors = new Vector<>();
        for(int i = 0; i < nCategories; ++i) {
            Vector<Integer> adjustingFactorListValue = new Vector<>(IntStream.rangeClosed(1, 20)
                    .boxed().collect(Collectors.toList()));
            Vector<Pair<BigInteger, CLSignature>> adjustingFactorOfCategory = new Vector<>();
            for(int j = 0; j < adjustingFactorListValue.size(); ++j) {
                int adjustingFactor = adjustingFactorListValue.get(j);
                BigInteger delta = BigInteger.valueOf(adjustingFactor);
                CLSignature clSignature = clSigner.sign(BigInteger.valueOf(j), delta);
                Pair<BigInteger, CLSignature> tmp = new Pair(delta, clSignature);
                adjustingFactorOfCategory.add(tmp);
            }
            adjustingFactors.add(adjustingFactorOfCategory);
        }
        return adjustingFactors;
    }

    private void initThreshold() {
        thresholdList = new Vector<>();
        thresholdLimit = new Vector<>();
        for(int i = 0; i < nCategories; ++i) {
            int limit = 100;
            int threshold = 0;
            String op = ">=";
            TreeMap<Integer, CLSignature> clSignatures =
                    createCLSignatureRangeIntegers(threshold, limit, op);
            thresholdLimit.add(new Pair<>(op, limit));
            thresholdList.add(new Pair<>(threshold, clSignatures));
        }
    }

    private TreeMap<Integer, CLSignature> createCLSignatureRangeIntegers(
            int threshold, int limit, String op) {
        TreeMap<Integer, CLSignature> clSignatures = new TreeMap<>();
        int start, end;
        if (op.equals(">=")) {
            start = threshold;
            end = limit;
        } else {
            start = limit;
            end = threshold - 1;
        }
        for(int i = start; i <= end; ++i) {
            CLSignature clSignature = clSigner.sign(BigInteger.valueOf(i));
            clSignatures.put(i, clSignature);
        }
        return clSignatures;
    }

    public void setAdjustingFactorMeritList(
            Vector<Vector<Pair<BigInteger, CLSignature>>> newAdjustingFactorMeritList) {
        adjustingFactorMeritList = newAdjustingFactorMeritList;
    }

    public void setAdjustingFactorBlackList(
            Vector<Vector<Pair<BigInteger, CLSignature>>> newAdjustingFactorBlackList) {
        adjustingFactorBlackList = newAdjustingFactorBlackList;
    }

    public void setThresholdList(Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> newThresholdList) {
        thresholdList = newThresholdList;
    }

    public BigInteger computeChallenge() {
        return BigInteger.ONE;
    }
}
