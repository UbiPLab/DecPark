package com.lamductan.dblacr.lib.crypto.proof.SPK.common;

import com.ibm.zurich.idmx.utils.SystemParameters;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;

public class SPKProverVerifierInterface {
    protected static final BigInteger ZERO = BigInteger.ZERO;
    protected static final BigInteger ONE = BigInteger.ONE;

    protected TreeMap<String, BigInteger> objects;
    protected TreeSet<String> listObjectNames;
    protected TreeSet<String> freeVarNames;
    protected TreeMap<String, Integer> bitLengthLowerBounds;
    protected TreeMap<String, Integer> bitLengthUpperBounds;
    protected TreeMap<String, BigInteger> sValues;
    protected Vector<TreeMap<String, Pair<String, BigInteger>>> commonRelations;
    protected SystemParameters sp;
    protected BigInteger challenge;
    protected Vector<BigInteger> bList;
    protected BigInteger Modulus;
    protected BigInteger nonce;
    protected int nRelations;

    public SPKProverVerifierInterface(SystemParameters _sp, BigInteger _nonce) {
        sp = _sp;
        nonce = _nonce;

        objects = new TreeMap<>();
        bitLengthLowerBounds = new TreeMap<>();
        bitLengthUpperBounds = new TreeMap<>();
        sValues = new TreeMap<>();
        bList = new Vector<>();
    }

    public TreeMap<String, BigInteger> getObjects() {return objects;}
    public TreeSet<String> getListObjectNames() {
        if (listObjectNames == null) listObjectNames = new TreeSet<>(objects.keySet());
        return listObjectNames;
    }
    public TreeSet<String> getFreeVarNames() {return freeVarNames;}
    public TreeMap<String, Integer> getBitLengthLowerBounds() {return bitLengthLowerBounds;}
    public TreeMap<String, Integer> getBitLengthUpperBounds() {return bitLengthUpperBounds;}
    public Vector<TreeMap<String, Pair<String, BigInteger>>> getCommonRelations() {return commonRelations;}
    public SystemParameters getSystemParameters() {return sp;}
    public BigInteger getNonce() {return nonce;}

}
