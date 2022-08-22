//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.smartcard;

import java.math.BigInteger;
import java.net.URI;

public interface IdemixProofResponse {
  public BigInteger responseForCredentialRandomizer(URI smartcardUri, URI credentialUri);
  public BigInteger responseForDeviceSecretKey(URI smartcardUri);
}
