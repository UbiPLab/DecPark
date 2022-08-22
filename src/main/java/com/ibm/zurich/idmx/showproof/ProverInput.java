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

import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.CredentialCommitment;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.RepresentationOpening;
import com.ibm.zurich.idmx.dm.StoredDomainPseudonym;
import com.ibm.zurich.idmx.dm.StoredPseudonym;
import com.ibm.zurich.idmx.showproof.accumulator.AccumulatorWitness;
import com.ibm.zurich.idmx.smartcard.IdemixSmartcardManager;
import com.ibm.zurich.idmx.ve.VerifiableEncryptionOpening;

public class ProverInput {
  public IdemixSmartcardManager smartcardManager;
  public Map<String, Credential> credentials;
  public TreeMap<String, MessageToSign> messages;
  public Map<String, CommitmentOpening> commitmentOpenings;
  public Map<String, RepresentationOpening> representationOpenings;
  public Map<String, VerifiableEncryptionOpening> verifiableEncryptions;
  public Map<String, StoredDomainPseudonym> domainPseudonyms;
  public Map<String, StoredPseudonym> pseudonyms;
  public Map<String, CredentialCommitment> credentialCommitments;
  public Map<String, AccumulatorWitness> accumulatorWitnesses;
  
  public ProverInput() {
    smartcardManager = null;
    credentials = new HashMap<String, Credential>();
    messages = new TreeMap<String, MessageToSign>();
    commitmentOpenings = new HashMap<String, CommitmentOpening>();
    representationOpenings = new HashMap<String, RepresentationOpening>();
    verifiableEncryptions = new HashMap<String, VerifiableEncryptionOpening>();
    domainPseudonyms = new HashMap<String, StoredDomainPseudonym>();
    pseudonyms = new HashMap<String, StoredPseudonym>();
    credentialCommitments = new HashMap<String, CredentialCommitment>();
    accumulatorWitnesses = new HashMap<String, AccumulatorWitness>();
  }
}
