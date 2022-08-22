//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.net.URI;
import java.util.HashMap;

import com.ibm.zurich.idmx.showproof.Identifier;

/**
 * This predicate expresses proofs of knowledge about credentials. It uses a
 * credential and a map from attribute names to identifiers to determine over
 * which attributes it should issue equality proofs.
 */
public class CLComPredicate extends CredentialPredicate {

    /**
     * Constructor.
     * 
     * @param ipkId
     *            Identifier of the issuer public key associated to this
     *            predicate.
     * @param theCredStructId
     *            Location of the credential structure associated to this
     *            predicate.
     * @param theCredName
     *            Temporary name of the credential as used in the proof
     *            specification.
     * @param attToIds
     *            Map from attribute names to identifiers used in this
     *            predicate.
     */
    public CLComPredicate(final URI ipkId, final URI theCredStructId,
            final String theCredName, final String theSecretTempName,
            final HashMap<String, Identifier> attToIds) {
      super(ipkId, theCredStructId, theCredName, theSecretTempName, attToIds, PredicateType.CLCOM);
    }

    protected String getNameForStringPretty() {
      return "CLComPredicate";
    }
    
    public String getTempCredName() {
      return credName;
  }
}
