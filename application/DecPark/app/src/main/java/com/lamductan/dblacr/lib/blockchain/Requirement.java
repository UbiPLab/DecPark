package com.lamductan.dblacr.lib.blockchain;

import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import javafx.util.Pair;


import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class Requirement extends BlockchainObject implements Serializable {
    private static final long serialVersionUID = 6529685098267757689L;

    private Vector<PublicKey> C;
    private Vector<ScoreRecord> scoreRecords;
    private int nCategories;
    private Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorMeritList;
    private Vector<Vector<Pair<BigInteger, CLSignature>>> adjustingFactorBlackList;
    private Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> thresholdList;
    private Vector<Pair<String, Integer>> thresholdLimit;

    public Requirement(Vector<PublicKey> _C, Vector<ScoreRecord> _scoreRecords,
                       Vector<Vector<Pair<BigInteger, CLSignature>>> _adjustingFactorMeritList,
                       Vector<Vector<Pair<BigInteger, CLSignature>>> _adjustingFactorBlackList,
                       Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> _thresholdList,
                       Vector<Pair<String, Integer>> _thresholdLimit, int _nCategories) {
        C = _C;
        scoreRecords = _scoreRecords;
        nCategories = _nCategories;
        adjustingFactorMeritList = _adjustingFactorMeritList;
        adjustingFactorBlackList = _adjustingFactorBlackList;
        thresholdList = _thresholdList;
        thresholdLimit = _thresholdLimit;
        nCategories = _nCategories;
    }

    public Vector<PublicKey> getC() {return C;}
    public int getNCategories() {return nCategories;}
    public Vector<ScoreRecord> getScoreRecords() {return scoreRecords;}
    public Vector<Vector<Pair<BigInteger, CLSignature>>> getAdjustingFactorMeritList() {
        return adjustingFactorMeritList;
    }
    public Vector<Vector<Pair<BigInteger, CLSignature>>> getAdjustingFactorBlackList() {
        return adjustingFactorBlackList;
    }
    public Vector<Pair<Integer, TreeMap<Integer, CLSignature>>> getThresholdList() {return thresholdList;}
    public Vector<Pair<String, Integer>> getThresholdLimit() {return thresholdLimit;}

    @Override
    public String getType() {return "Requirement";}
}
