//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;

/**
 * Abstract class to inherited by the various predicate types.
 */
public abstract class Predicate {

    /**
     * Defines the different predicates.
     */
    public enum PredicateType {
        /** Camenisch-Lysyanskaya Predicate (proof of knowledge). */
        CL,
        /** Camenisch-Lysyanskaya Commitment Predicate (for advanced issuance). */
        CLCOM,
        /** Commitment predicate. */
        COMMITMENT,
        /** Domain pseudonym predicate. */
        DOMAINNYM,
        /** Pseudonym predicate. */
        PSEUDONYM,
        /** Verifiable encryption predicate. */
        VERENC,
        /** Inequality predicate. */
        INEQUALITY,
        /** Not-equal predicate */
        NOTEQUAL,
        /** Epoch predicate. */
        EPOCH,
        /** Representation predicate. */
        REPRESENTATION,
        /** Message predicate. */
        MESSAGE,
        /** Prime encoding predicate. */
        ENUMERATION,
        /** Accumulator predicate */
        ACCUMULATOR,
    };

    /** PredicateType of this predicate. **/
    private final PredicateType predicateType;

    /**
     * Constructor.
     * 
     * @param thePredicateType
     *            Type of the predicate.
     */
    public Predicate(final PredicateType thePredicateType) {
        predicateType = thePredicateType;
    }

    /**
     * Returns the predicateType of the predicate.
     * 
     * @return PredicateType of the predicate.
     */
    public final PredicateType getPredicateType() {
        return predicateType;
    }

    /**
     * @return Human-readable description of the predicate.
     */
    public abstract String toStringPretty();

    public BigInteger generateHash() {
      return BigInteger.ZERO;
    }
}
