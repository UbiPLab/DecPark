//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.Representation;
import com.ibm.zurich.idmx.showproof.accumulator.AccumulatorState;
import com.ibm.zurich.idmx.smartcard.IdemixSmartcardHelper;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;

public class VerifierInput {
  public TreeMap<String, MessageToSign> messages;
  public Map<String, Commitment> commitments;
  public Map<String, Representation> representations;
  public Map<String, AccumulatorState> accumulatorStates;
  public IdemixSmartcardHelper smartcardHelper;
  
  public VerifierInput() {
    messages = new TreeMap<String, MessageToSign>();
    commitments = new HashMap<String, Commitment>();
    representations = new TreeMap<String, Representation>();
    accumulatorStates = new HashMap<String, AccumulatorState>();
    smartcardHelper = null;
  }
}
