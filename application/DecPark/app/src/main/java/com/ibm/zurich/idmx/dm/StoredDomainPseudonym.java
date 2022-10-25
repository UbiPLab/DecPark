//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm;

import java.net.URI;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;

public class StoredDomainPseudonym {
  
  private final URI scope;
  private final URI smartcardUri;
  private final GroupParameters gp;
  private final URI groupParameters;

  public URI getScope() {
    return scope;
  }

  public URI getSmartcardUri() {
    return smartcardUri;
  }

  public GroupParameters getGroupParameters() {
    return gp;
  }

  public URI getGroupParametersLocation() {
    return groupParameters;
  }

  public StoredDomainPseudonym(URI scope, URI smartcardUri, URI groupParameters) {
    this.scope = scope;
    this.smartcardUri = smartcardUri;
    this.groupParameters = groupParameters;
    this.gp = (GroupParameters) StructureStore.getInstance().get(groupParameters);
  }

}
