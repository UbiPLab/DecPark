//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;

import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.utils.Constants;

/**
 * Predicate for proving that  lhs != rhs (mod gp.Gamma).
 */
public class NotEqualPredicate extends Predicate {

  private final Identifier lhs;
  private final Identifier rhsAsId;
  private final BigInteger rhsAsConstant;
  
  public NotEqualPredicate(Identifier lhs, Identifier rhs) {
    super(PredicateType.NOTEQUAL);
    this.lhs = lhs;
    this.rhsAsId = rhs;
    this.rhsAsConstant = null;
  }
  
  public NotEqualPredicate(Identifier lhs, BigInteger rhs) {
    super(PredicateType.NOTEQUAL);
    this.lhs = lhs;
    this.rhsAsConstant = rhs;
    this.rhsAsId = null;
  }
  
  public String getName() {
    return String.format("%s%sNEQ%s%s", lhs.getName(), Constants.DELIMITER, Constants.DELIMITER, getRhsString());
  }

  public Identifier getLhs() {
    return lhs;
  }

  public BigInteger getRhs() {
    if (rhsAsConstant != null) {
      return rhsAsConstant;
    } else {
      return rhsAsId.getValue();
    }
  }
  
  public BigInteger getRhs(Proof p) {
    if (rhsAsConstant != null) {
      return rhsAsConstant;
    } else {
      return (BigInteger)p.getSValue(rhsAsId.getName()).getValue();
    }
  }
  
  @Override
  public String toStringPretty() {
    return String.format("NotEqualPredicate(%s, %s != %s)", getName(), lhs.getName(), getRhsString());
  }
  
  private String getRhsString() {
    if (rhsAsConstant != null) {
        return rhsAsConstant.toString();
    } else {
        return rhsAsId.getName();
    }
  }

}
