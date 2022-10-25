//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;

public class StoredPseudonym {
  private final URI smartcardUri;
  private final GroupParameters gp;
  private final URI groupParameters;
  private final BigInteger randomizer;

  public URI getSmartcardUri() {
    return smartcardUri;
  }
  

  public BigInteger getRandomizer() {
    return randomizer;
  }

  public GroupParameters getGroupParameters() {
    return gp;
  }

  public URI getGroupParametersLocations() {
    return groupParameters;
  }

  public StoredPseudonym(URI smartcardUri, URI groupParameters, BigInteger randomizer) {
    this.smartcardUri = smartcardUri;
    this.groupParameters = groupParameters;
    this.randomizer = randomizer;
    this.gp = (GroupParameters) StructureStore.getInstance().get(groupParameters);
  }

}
