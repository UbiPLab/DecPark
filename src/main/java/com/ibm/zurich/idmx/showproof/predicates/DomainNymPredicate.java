//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.net.URI;

/**
 * This predicate proves knowledge of a domain pseudonym. The base is computed
 * from the given domain and as exponent we use the master secret.
 */
public final class DomainNymPredicate extends Predicate {

    /** Name of the domain (used for the creation of the base). */
    private final URI domain;
    /** Name of the temporary secret */
    private final String tempSecretName;
    private final String tempName;

    /**
     * Constructor.
     * 
     * @param theDomain
     *            String representing the domain.
     */
    public DomainNymPredicate(final String tempName, final URI theDomain, final String tempSecretName) {
        super(PredicateType.DOMAINNYM);
        if (theDomain == null) {
            throw new IllegalArgumentException("Domain not specified.");
        }
        domain = theDomain;
        this.tempSecretName = tempSecretName;
        this.tempName = tempName;
    }

    /**
     * @return Name of the domain.
     */
    public URI getDomain() {
        return domain;
    }
    
    public String getTempName() {
      return tempName;
    }
    
    public String getTempSecretName() {
      return tempSecretName;
    }

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String s = "DomainNymPredicate( " + domain + " )";
        return s;
    }

}
