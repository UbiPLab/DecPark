package com.lamductan.dblacr.lib.crypto.proof.SPK.common;

import com.lamductan.dblacr.lib.crypto.proof.IProof;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;

public class TreeMapProof implements Serializable, IProof {
    private static final long serialVersionUID = 6529685098267757698L;

    /** Challenge. */
    protected BigInteger challenge;
    /** S-values of the proof. */
    protected TreeMap<String, BigInteger> sValues;
    /** T-values of the proof. */
    protected Vector<BigInteger> bList;

    /** List of common values. */
    protected TreeMap<String, BigInteger> objects;
    protected TreeSet<String> freeVarNames;
    protected TreeMap<String, Integer> bitLengthLowerBounds;
    protected TreeMap<String, Integer> bitLengthUpperBounds;
    protected Vector<TreeMap<String, Pair<String, BigInteger>>> commonRelations;
    protected BigInteger Modulus;

    public TreeMapProof(final BigInteger theChallenge,
                        TreeMap<String, BigInteger> sValues,
                        Vector<BigInteger> _bList,
                        TreeMap<String, BigInteger> _objects,
                        TreeSet<String> _freeVarNames,
                        TreeMap<String, Integer> _bitLengthLowerBounds,
                        TreeMap<String, Integer> _bitLengthUpperBounds,
                        Vector<TreeMap<String, Pair<String, BigInteger>>> _commonRelations,
                        BigInteger _Modulus) {
        challenge = theChallenge;
        this.sValues = sValues;
        bList = _bList;
        objects = _objects;
        bitLengthLowerBounds = _bitLengthLowerBounds;
        bitLengthUpperBounds = _bitLengthUpperBounds;
        commonRelations = _commonRelations;
        Modulus = _Modulus;
        freeVarNames = _freeVarNames;
    }

    public TreeMapProof(final BigInteger theChallenge,
                        TreeMap<String, BigInteger> sValues,
                        Vector<BigInteger> _bList,
                        TreeMap<String, BigInteger> _objects,
                        TreeSet<String> _freeVarNames,
                        TreeMap<String, Integer> _bitLengthLowerBounds,
                        TreeMap<String, Integer> _bitLengthUpperBounds,
                        Vector<TreeMap<String, Pair<String, BigInteger>>> _commonRelations) {
        challenge = theChallenge;
        this.sValues = sValues;
        bList = _bList;
        objects = _objects;
        bitLengthLowerBounds = _bitLengthLowerBounds;
        bitLengthUpperBounds = _bitLengthUpperBounds;
        commonRelations = _commonRelations;
        freeVarNames = _freeVarNames;
    }

    public TreeMapProof() {}

    /**
     * @return Challenge.
     */
    public final BigInteger getChallenge() {
        return challenge;
    }

    /**
     * Serialisation method.
     */
    public final TreeMap<String, BigInteger> getSValues() {
        return sValues;
    }

    public Vector<BigInteger> getBList() { return bList; }

    @Override
    public String toString() {
        return "Proof [challenge=" + challenge + ", sValues=" + sValues + ", tValues=" + bList
                + ", objectsList=" + objects + "]";
    }


    public TreeMap<String, BigInteger> getObjectList() {return objects;}
    public TreeMap<String, Integer> getBitLengthLowerBounds() {return bitLengthLowerBounds;}
    public TreeMap<String, Integer> getBitLengthUpperBounds() {return bitLengthUpperBounds;}
    public Vector<TreeMap<String, Pair<String, BigInteger>>> getCommonRelations() {return commonRelations;}
    public BigInteger getModulus() {return Modulus;}
    public BigInteger getG() {
        if (objects.containsKey("g")) {
            return objects.get("g");
        } else return null;
    }

    public TreeSet<String> getFreeVarNames() { return freeVarNames; }

    public BigInteger getH() {
        if (objects.containsKey("g")) {
            return objects.get("g");
        } else return null;
    }
}
