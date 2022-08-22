//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.smartcard;

import java.math.BigInteger;
import java.net.URI;

public interface IdemixSmartcardManager {
  
  // Test if smartcard and credentials are present
  public boolean smartcardLoaded(URI smartcardUri);
  public boolean credentialExists(URI smartcardUri, URI credentialUri);
  
  // Get the public parameters of card/credential
  public BigInteger getPseudonymBaseOfCard(URI smartcardUri);
  public BigInteger getPseudonymModulusOfCard(URI smartcardUri);
  public BigInteger getPseudonymSubgroupOrderOfCard(URI smartcardUri);
  public BigInteger getR0OfCredential(URI smartcardUri, URI credentialUri);
  public BigInteger getSOfCredential(URI smartcardUri, URI credentialUri);
  public BigInteger getNOfCredential(URI smartcardUri, URI credentialUri);
  public int getChallengeSizeBytes();
  public int getStatisticalHidingSizeBytes();
  
  // Compute values that depend on the card secret
  public BigInteger computePublicKeyOfCard(URI smartcardUri);
  public BigInteger computeCredentialFragment(URI smartcardUri, URI credentialUri);
  public BigInteger computeScopeExclusivePseudonym(URI smartcardUri, URI scope);
  
  // Convenience methods to make sure Idemix uses the same algorithms as the cards
  public BigInteger computeBaseForScopeExclusivePseudonym(URI scope, BigInteger modulus, BigInteger order);
  public BigInteger computeBaseForScopeExclusivePseudonym(URI smartcardUri, URI scope);
  public BigInteger computeChallenge(byte[] hashPreimage, byte[] nonce);
  
  // Proofs
  public IdemixProofCommitment prepareProof(IdemixProofSpec spec);
  public byte[] prepareNonce(IdemixProofCommitment com);
  public IdemixProofResponse finalizeZkProof(IdemixProofCommitment com, byte[] hashPreimage, byte[] nonce);
  
  // Factory for IdemixProofSpec
  public IdemixProofSpec idemixProofSpecFactory();
}
