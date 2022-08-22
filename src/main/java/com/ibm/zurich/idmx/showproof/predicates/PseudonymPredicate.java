//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

/**
 * Predicate for proving a domain pseudonym.
 */
public class PseudonymPredicate extends Predicate {

    /** Reference to the stored pseudonym. */
    private final String name;
    private final String secretName;

    /**
     * Constructor.
     * 
     * @param theName
     *            String that refers to the pseudonym.
     */
    public PseudonymPredicate(final String theName, final String secretName) {
        super(PredicateType.PSEUDONYM);
        name = theName;
        this.secretName = secretName;
    }

    /**
     * @return Human-readable representation of the pseudonym predicate.
     */
    public final String toStringPretty() {
        String s = "PseudonymPredicate(" + name + ")";
        return s;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }
    
    public final String getSecretName() {
      return secretName;
    }

}
