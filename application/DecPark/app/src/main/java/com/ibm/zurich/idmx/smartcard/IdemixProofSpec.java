//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.smartcard;

import java.net.URI;

public interface IdemixProofSpec {
  // smartcardUri is also the ID of the secret
  public void addCredentialProof(URI smartcardUri, URI credentialUri);
  public void addScopeExclusivePseudonymProof(URI smartcardUri, URI scope);
  public void addPublicKeyProof(URI smartcardUri);
}
