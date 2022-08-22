//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.utils.Utils;

public class AccumulatorPredicate extends Predicate {

  private final int epoch;
  private final URI publicKey;
  private final String tempName;
  private final Identifier value;

  public AccumulatorPredicate(String tempName, URI publicKey, int epoch, Identifier value) {
    super(PredicateType.ACCUMULATOR);
    this.tempName = tempName;
    this.publicKey = publicKey;
    this.epoch = epoch;
    this.value = value;
  }
  
  public int getEpoch() {
    return epoch;
  }

  public URI getPublicKey() {
    return publicKey;
  }

  public String getTempName() {
    return tempName;
  }
  
  public String getValueName() {
    return value.getName();
  }
  
  public Identifier getValue() {
    return value;
  }

  @Override
  public String toString() {
    return "AccumulatorPredicate [epoch=" + epoch + ", publicKey=" + publicKey + ", tempName="
        + tempName + ", value=" + value + ", getValueName()=" + getValueName() + "]";
  }
  
  @Override
  public String toStringPretty() {
    return toString();
  }

  @Override
  public BigInteger generateHash() {
    BigInteger items[] = new BigInteger[4];
    items[0] = BigInteger.valueOf(epoch);
    items[1] = Utils.hashString(getPublicKey().toString(), 256);
    items[2] = Utils.hashString(getTempName(), 256);
    items[3] = Utils.hashString(getValueName(), 256);
    return Utils.hashOf(256, items);
  }

}
