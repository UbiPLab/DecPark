//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;

/**
 * Data structure for a proof.
 */
public class Proof {

    /** Challenge. */
    private final BigInteger challenge;
    /** S-values of the proof. */
    private final Map<String, SValue> sValues;
    /** T-values of the proof. */
    private final Vector<BigInteger> tValues;

    /** List of common values. */
    private final TreeMap<String, BigInteger> commonList;
    /** List of verifiable encryptions. */
    private final TreeMap<String, VerifiableEncryption> verEncs;
    /** Nonce for smartcard */
    private final byte[] smartcardNonce;

    /**
     * Convenience constructor.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> sValues,
            /*nullable*/ final Vector<BigInteger> tValues,
            byte[] smartcardNonce) {
        this(theChallenge, sValues, tValues, new TreeMap<String, BigInteger>(),
                new TreeMap<String, VerifiableEncryption>(), smartcardNonce);
    }

    /**
     * Convenience constructor.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> sValues,
            /*nullable*/ final Vector<BigInteger> tValues,
            final TreeMap<String, BigInteger> theCommonList,
            byte[] smartcardNonce) {
        this(theChallenge, sValues, tValues, theCommonList,
                new TreeMap<String, VerifiableEncryption>(), smartcardNonce);
    }

    /**
     * @param theChallenge
     *            Challenge.
     * @param sValues
     *            S-values of the proof.
     * @param theCommonList
     *            List of common values.
     * @param theVerEncs
     *            List of verifiable encryptions.
     */
    public Proof(final BigInteger theChallenge,
            final Map<String, SValue> sValues,
            /*nullable*/ final Vector<BigInteger> tValues,
            final TreeMap<String, BigInteger> theCommonList,
            final TreeMap<String, VerifiableEncryption> theVerEncs,
            byte[] smartcardNonce) {
        challenge = theChallenge;
        this.sValues = sValues;
        commonList = theCommonList;
        verEncs = theVerEncs;
        this.smartcardNonce = smartcardNonce;
        
        if( tValues == null) {
          this.tValues = new Vector<BigInteger>();
        } else {
          this.tValues = tValues;
        }
    }

    /**
     * @param name
     *            Identifying name of the s-value.
     * @return S-value corresponding to the given <code>identifier</code>.
     */
    public final SValue getSValue(final String name) {
        return sValues.get(name);
    }

    /**
     * @return Challenge.
     */
    public final BigInteger getChallenge() {
        return challenge;
    }

    /**
     * @return List of common values.
     */
    public final TreeMap<String, BigInteger> getCommonList() {
        return commonList;
    }

    /**
     * @param name
     *            Name of the common value.
     * @return Common value with the given name.
     */
    public final BigInteger getCommonValue(final String name) {
        return commonList.get(name);
    }

    /**
     * Find the verifiable encryption associated to the verifiable encryption
     * predicate named "name".
     * 
     * @param name
     *            Name of the verifiable encryption.
     * @return the encryption object called "name" or null if not found.
     */
    public final VerifiableEncryption getVerEnc(final String name) {
        VerifiableEncryption enc = verEncs.get(name);
        if (verEncs == null || enc == null) {
            throw new RuntimeException("Verifiable encryption: " + name
                    + " not found.");
        }
        return enc;
    }

    /**
     * Serialisation method.
     */
    public final Map<String, SValue> getSValues() {
        return sValues;
    }
    
    public Vector<BigInteger> getTValues() {
      return tValues;
    }

    /**
     * Serialisation method.
     */
    public final TreeMap<String, VerifiableEncryption> getVerEncs() {
        return verEncs;
    }

    public byte[] getSmartcardNonce() {
      return smartcardNonce;
    }

    @Override
    public String toString() {
      return "Proof [challenge=" + challenge + ", sValues=" + sValues + ", tValues=" + tValues
          + ", commonList=" + commonList + ", verEncs=" + verEncs + ", smartcardNonce="
          + Arrays.toString(smartcardNonce) + "]";
    }
    
    /**
     * Remove T-values from proof (this saves some space)
     */
    public void clearTValues() {
      tValues.clear();
    }
}
