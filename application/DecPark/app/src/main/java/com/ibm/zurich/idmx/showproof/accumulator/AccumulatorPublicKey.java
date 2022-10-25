//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.accumulator;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * This class defines the public key and group parameters for an accumulator.
 * The revocation authority should use only one accumulator per public key, since the public
 * key fixes the initial value of the accumulator.
 * @author enr
 *
 */
public class AccumulatorPublicKey implements Serializable{
  private static final long serialVersionUID = -6004897750946747866L;
  
  private final URI systemParametersUri;
  private final URI publicKeyUri;

  private final BigInteger n;
  private final BigInteger baseG;
  private final BigInteger baseH;

  @Override
  public String toString() {
    return "AccumulatorPublicKey [systemParametersUri=" + systemParametersUri + ", publicKeyUri="
        + publicKeyUri + ", n=" + n + ", baseG=" + baseG + ", baseH=" + baseH + "]";
  }

  /**
   * Construct public key based on XML.
   * @param systemParametersUri
   * @param n
   * @param baseG
   * @param baseH
   * @param primeBaseG
   * @param primeBaseH
   * @param primeGroupModulus
   * @param primeGroupOrder
   * @param logA
   */
  public AccumulatorPublicKey(URI systemParametersUri,
                              BigInteger n,
                              BigInteger baseG,
                              BigInteger baseH,
                              URI publicKeyUri) {
    this.systemParametersUri = systemParametersUri;
    this.n = n;
    this.baseG = baseG;
    this.baseH = baseH;
    this.publicKeyUri = publicKeyUri;
  }
  
  /**
   * Generate a public key
   * @param n A safe RSA modulus
   * @param systemParametersUri
   * @return
   */
  public static AccumulatorPublicKey generatePublicKey(BigInteger n, URI systemParametersUri,
                                                       URI publicKeyUri) {
    SystemParameters sp = (SystemParameters)StructureStore.getInstance().get(systemParametersUri);
    
    BigInteger baseG = Utils.computeGeneratorQuadraticResidue(n, sp);
    BigInteger baseH = Utils.computeGeneratorQuadraticResidue(n, sp);

    return new AccumulatorPublicKey(systemParametersUri, n, baseG, baseH, publicKeyUri);
  }
  
  public URI getSystemParametersUri() {
    return systemParametersUri;
  }

  /**
   * A safe RSA modulus used when computing the accumulator
   * @return
   */
  public BigInteger getN() {
    return n;
  }

  /**
   * A random generator of the quadratic residues mod n.
   * Also the initial value of the accumulator.
   * @return
   */
  public BigInteger getBaseG() {
    return baseG;
  }

  /**
   * Another random generator of the quadratic residues mod n,
   * such that its discrete logarithm relative to baseG is unknown.
   * Used only in the proof of knowledge.
   * @return
   */
  public BigInteger getBaseH() {
    return baseH;
  }
  
  /**
   * Returns the URI of this public key.
   * @return
   */
  public URI getUri() {
    return publicKeyUri;
  }
  
  /**
   * Generate a prime number suitable for adding to the accumulator.
   * This function assigns the prime numbers sequentially.
   * @param lastPrime The last value that was output by this function, or null
   * if this is the first event.
   * @return The next prime after lastPrime, or 3 if lastPrime is null
   */
  public BigInteger getNextPrime(/*Nullable*/ BigInteger lastPrime) {
    if (lastPrime == null) {
      return BigInteger.valueOf(3);
    } else if (lastPrime.mod(BigInteger.valueOf(2)).longValue() == 0) {
      throw new RuntimeException("lastPrime is an even number; epected an odd number.");
    } else {
      SystemParameters sp = (SystemParameters)StructureStore.getInstance().get(systemParametersUri);
      BigInteger TWO = BigInteger.valueOf(2);
      do {
        lastPrime = lastPrime.add(TWO);
      }
      while(!lastPrime.isProbablePrime(sp.getL_pt()));
      return lastPrime;
    }
  }
  
  /**
   * Generate a random prime number suitable for adding to the accumulator.
   */
  public BigInteger getRandomPrime() {
    SystemParameters sp = (SystemParameters)StructureStore.getInstance().get(systemParametersUri);
    return Utils.genPrime(sp.getL_m(), sp.getL_pt());
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((baseG == null) ? 0 : baseG.hashCode());
    result = prime * result + ((baseH == null) ? 0 : baseH.hashCode());
    result = prime * result + ((n == null) ? 0 : n.hashCode());
    result = prime * result + ((publicKeyUri == null) ? 0 : publicKeyUri.hashCode());
    result = prime * result + ((systemParametersUri == null) ? 0 : systemParametersUri.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorPublicKey other = (AccumulatorPublicKey) obj;
    if (baseG == null) {
      if (other.baseG != null) return false;
    } else if (!baseG.equals(other.baseG)) return false;
    if (baseH == null) {
      if (other.baseH != null) return false;
    } else if (!baseH.equals(other.baseH)) return false;
    if (n == null) {
      if (other.n != null) return false;
    } else if (!n.equals(other.n)) return false;
    if (publicKeyUri == null) {
      if (other.publicKeyUri != null) return false;
    } else if (!publicKeyUri.equals(other.publicKeyUri)) return false;
    if (systemParametersUri == null) {
      if (other.systemParametersUri != null) return false;
    } else if (!systemParametersUri.equals(other.systemParametersUri)) return false;
    return true;
  }
  
  
}
