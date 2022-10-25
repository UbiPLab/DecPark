//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.smartcard;

import java.math.BigInteger;
import java.net.URI;

public interface IdemixSmartcardHelper {
  // Convenience methods to make sure Idemix uses the same algorithms as the cards
  public BigInteger computeBaseForScopeExclusivePseudonym(URI scope, BigInteger modulus, BigInteger order);
  public BigInteger computeChallenge(byte[] hashPreimage, byte[] nonce);
}
