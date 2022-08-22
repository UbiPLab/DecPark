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

import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.key.Npq;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;

/**
 * This class represents the secret key of the accumulator.
 * The secret key is needed only for removing a prime from the accumulator, and extracting a
 * witness. Both these operations
 * @author enr
 *
 */
public class AccumulatorSecretKey implements Serializable {
  private static final long serialVersionUID = -963270816896233744L;
  
  private final AccumulatorPublicKey apk;
  private final BigInteger order;
  private final URI publicKeyUri;
  
  /**
   * Construct secret key based on XML
   * @param apk
   * @param order
   */
  public AccumulatorSecretKey(AccumulatorPublicKey apk,
                              BigInteger order,
                              URI publicKeyUri) {
    this.apk = apk;
    this.order = order;
    this.publicKeyUri = publicKeyUri;
  }
  
  /**
   * Construct secret key based on XML.
   * The public key is loaded from the structure store.
   * @param order
   * @param publicKeyUri
   */
  public AccumulatorSecretKey(BigInteger order, URI publicKeyUri) {
    this.apk = (AccumulatorPublicKey)StructureStore.getInstance().get(publicKeyUri);
    this.order = order;
    this.publicKeyUri = publicKeyUri;
  }
  
  /**
   * Get the corresponding public key
   * @return
   */
  public AccumulatorPublicKey getPublicKey() {
    return apk;
  }
  
  /**
   * Returns the order of the group mod n:  lcm(p-1, q-1) = 2*pPrime*qPrime
   * @return
   */
  public BigInteger getOrder() {
    return order;
  }
  
  /**
   * Returns the URI of the public key.
   */
  public URI getPublicKeyUri() {
    return publicKeyUri;
  }
  
  /**
   * Generate a new private key.
   * @param systemParametersUri
   * @return
   */
  public static AccumulatorSecretKey generatePrivateKey(URI systemParametersUri, URI publicKeyUri) {
    SystemParameters sp = (SystemParameters)StructureStore.getInstance().get(systemParametersUri);
    final Npq theNpq = IssuerPrivateKey.getNPQ(sp.getL_n(), sp.getL_pt());
    
    final BigInteger pPrime = theNpq.getP().subtract(BigInteger.ONE).shiftRight(1);
    final BigInteger qPrime = theNpq.getQ().subtract(BigInteger.ONE).shiftRight(1);
    final BigInteger order = pPrime.multiply(qPrime).shiftLeft(1);
    final BigInteger n = theNpq.getN();
    
    AccumulatorPublicKey apk = AccumulatorPublicKey.generatePublicKey(n, systemParametersUri, publicKeyUri);
    AccumulatorSecretKey ask = new AccumulatorSecretKey(apk, order, publicKeyUri);
    return ask;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((apk == null) ? 0 : apk.hashCode());
    result = prime * result + ((order == null) ? 0 : order.hashCode());
    result = prime * result + ((publicKeyUri == null) ? 0 : publicKeyUri.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorSecretKey other = (AccumulatorSecretKey) obj;
    if (apk == null) {
      if (other.apk != null) return false;
    } else if (!apk.equals(other.apk)) return false;
    if (order == null) {
      if (other.order != null) return false;
    } else if (!order.equals(other.order)) return false;
    if (publicKeyUri == null) {
      if (other.publicKeyUri != null) return false;
    } else if (!publicKeyUri.equals(other.publicKeyUri)) return false;
    return true;
  }
}
