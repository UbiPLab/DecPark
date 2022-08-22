//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.issuance;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.showproof.ProverInput;
import com.ibm.zurich.idmx.smartcard.IdemixSmartcardManager;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * The credential recipient (or user) for the CL credential issuance.
 * 
 * @see Issuer
 */
public class AdvancedRecipient {

  /** Logger. */
  private static Logger log = Logger.getLogger(AdvancedRecipient.class.getName());

  /** Common value for the proof in the first round. */
  private BigInteger capU;
  /** Credential structure. */
  private final CredentialStructure credStruct;

  /** Convenience: Group parameters. */
  private final GroupParameters gp;

  /** Convenience: Issuer public key. */
  private final IssuerPublicKey ipk;

  /** Nonce generated by the recipient (for the proof of the verifier). */
  private BigInteger n2;
  private int nextAction;
  private final ProverInput proverInput;

  /** Smartcard manager */
  private final IdemixSmartcardManager smartcardManager;
  /** Convenience: System parameters. */
  private final SystemParameters sp;
  /** Issuance specification for the credential that is retrieved. */
  private final AdvancedIssuanceSpec spec;

  /** Values needed during the issuance protocol. */
  private final Values values;

  /** Randomization value for the signature (Recipient's contribution). */
  private BigInteger vPrime;


  public AdvancedRecipient(final AdvancedIssuanceSpec issuanceSpec, final ProverInput proverInput,
      final Values values) {
    super();

    if (issuanceSpec == null) {
      throw new RuntimeException("Recipient instantiated without the " + "necessary values.");
    }

    spec = issuanceSpec;
    this.proverInput = proverInput;

    ipk = issuanceSpec.getPublicKey();
    gp = ipk.getGroupParams();
    sp = gp.getSystemParams();

    this.smartcardManager = proverInput.smartcardManager;

    credStruct = issuanceSpec.getCredentialStructure();
    this.values = values;

    // adding masterSecret value to values
    credStruct.verifyRecipientValues(values);

    nextAction = 1;
  }

  private BigInteger computeFragment(URI nameOfSmartcard, URI credNameOnSmartcard) {
    if (nameOfSmartcard != null) {
      return smartcardManager.computeCredentialFragment(nameOfSmartcard, credNameOnSmartcard);
    } else {
      return BigInteger.ONE;
    }
  }

  public final Message round1(final Message message0) {
    if (nextAction != 1) {
      throw new RuntimeException("Cannot call round1 at this point.");
    }
    nextAction = 3;
    BigInteger nonce = message0.getIssuanceElement(IssuanceProtocolValues.nonce);

    Prover prover = new Prover(proverInput, spec.getSpec(), nonce);
    Proof p = prover.buildProof();
    vPrime = prover.getVPrimeForCLCom(spec.getTempNameOfCredInProof());
    assert (null != vPrime);

    n2 = Utils.computeRandomNumber(sp.getL_Phi());

    HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues =
        new HashMap<IssuanceProtocolValues, BigInteger>();
    issuanceProtocolValues.put(IssuanceProtocolValues.nonce, n2);

    Message msg;
    msg = new Message(issuanceProtocolValues, p, 1);

    return msg;
  }

  /**
   * 
   * @see com.ibm.zurich.idmx.issuance.RecipientInterface#round3(com.ibm.zurich
   *      .idmx.issuance.Message)
   */
  public final Credential round3(final Message msg, URI nameOfSmartcard, URI credNameOnSmartcard) {
    if (nextAction != 3) {
      throw new RuntimeException("Cannot call round3 at this point.");
    }
    nextAction = -1;

    final BigInteger v = msg.getIssuanceElement(IssuanceProtocolValues.vPrimePrime).add(vPrime);
    BigInteger e = msg.getIssuanceElement(IssuanceProtocolValues.e);
    final BigInteger n = ipk.getN();

    // [spec: IssueCertificateProtocol 3.1.0]
    if (!e.isProbablePrime(sp.getL_pt())) {
      log.log(Level.SEVERE, "e is not prime");
      return null;
    }
    final BigInteger lower = BigInteger.ONE.shiftLeft(sp.getL_e() - 1);
    final BigInteger upper = lower.add(BigInteger.ONE.shiftLeft(sp.getL_ePrime() - 1));
    if (!Utils.isInInterval(e, lower, upper)) {
      log.log(Level.SEVERE, "e not in proper interval");
      return null;
    }

    // Add values given by issuer
    for (AttributeStructure as : credStruct.getAttributeStructs(IssuanceMode.ISSUER)) {
      String name = as.getName();
      BigInteger exponent = msg.getRevealedAttribute(name);
      values.add(name, exponent);
    }

    // [spec: IssueCertificateProtocol 3.1.1]
    final BigInteger fragment = computeFragment(nameOfSmartcard, credNameOnSmartcard);
    final BigInteger capQ =
        AdvancedIssuer.computeQ(ipk.getCapS(), fragment, ipk.getCapZ(), ipk.getCapR(), v,
            ipk.getN(), credStruct.getAttributeStructs(), values);

    // generated by Issuer and passed via appropriate message.
    final BigInteger capA = msg.getIssuanceElement(IssuanceProtocolValues.capA);
    // [spec: IssueCertificateProtocol 3.1.2]
    final BigInteger capQHat = capA.modPow(e, n);
    // [spec: IssueCertificateProtocol 3.1.3]
    if (!capQ.equals(capQHat)) {
      log.log(Level.SEVERE, "Q from issuer does not match the Q " + "computed by recipient.");
      System.err.println("Recipient: " + capQ);
      System.err.println("Issuer:    " + capQHat);
      return null;
    }

    // [spec: IssueCertificateProtocol 3.2]
    final Vector<Exponentiation> expos = new Vector<Exponentiation>();
    expos.add(new Exponentiation(capA, msg.getProof().getChallenge(), n));
    expos.add(new Exponentiation(capQ, (BigInteger) msg.getProof().getSValue(IssuanceSpec.s_e)
        .getValue(), n));
    final BigInteger capAHat = Utils.multiExpMul(expos, n);

    Vector<BigInteger> proofContext = new Vector<BigInteger>();
    proofContext.add(spec.getContext());
    proofContext.add(capQ);
    proofContext.add(capA);
    proofContext.add(n2);
    proofContext.add(capAHat);
    final BigInteger cHat = Utils.hashOf(sp.getL_H(), proofContext);

    if (!cHat.equals(msg.getProof().getChallenge())) {
      throw new RuntimeException("Verification failure! " + "Mismatching cPrime, cHat");
    }

    Credential cred =
        new Credential(spec.getIssuerPublicKeyId(), spec.getCredStructureLocation(), capA, e, v,
            values, smartcardManager, credNameOnSmartcard, nameOfSmartcard);

    // set update location
    URI updateLocation = msg.getUpdateLocation();
    if (updateLocation != null) {
      cred.new UpdateInformation(capU, vPrime, updateLocation, n2, spec.getContext());
    }
    
    if(!cred.verifySignature(smartcardManager)) {
      throw new RuntimeException("Signature on newly issued credential is wrong. " + cred.toStringPretty());
    } else {
      System.out.println("Signature on new credential is OK.");
    }

    return cred;
  }
}