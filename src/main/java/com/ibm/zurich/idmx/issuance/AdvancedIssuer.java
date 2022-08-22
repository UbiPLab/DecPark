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
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.issuance.Message.IssuanceProtocolValues;
import com.ibm.zurich.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zurich.idmx.issuance.update.UpdateSpecification;
import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.IssuerPrivateKey;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.showproof.VerifierInput;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Class implementing the Issuer, an authority who can issue credentials and update them.
 * 
 * @see Recipient
 */
public class AdvancedIssuer {

  /** Logger. */
  private static Logger log = Logger.getLogger(AdvancedIssuer.class.getName());

  private static Proof computeATildeProof(Vector<BigInteger> proofContext,
      final SystemParameters sp, final BigInteger n, final BigInteger pPrime_qPrime,
      final BigInteger eInverse, final BigInteger capQ) {
    HashMap<String, SValue> sValues;
    final BigInteger r =
        Utils.computeRandomNumber(pPrime_qPrime.subtract(BigInteger.ONE), sp).add(BigInteger.ONE);
    final BigInteger capATilde = capQ.modPow(r, n);

    proofContext.add(capATilde);

    final BigInteger cPrime = Utils.hashOf(sp.getL_H(), proofContext);

    final BigInteger s_e = r.subtract(cPrime.multiply(eInverse)).mod(pPrime_qPrime);

    // creating new s-value map
    sValues = new HashMap<String, SValue>();
    sValues.put(IssuanceSpec.s_e, new SValue(s_e));
    Vector<BigInteger> tValues = new Vector<BigInteger>();
    final Proof p2 = new Proof(cPrime, sValues, tValues, null);
    return p2;
  }
  /**
   * Computation of capQ.
   * 
   * @param capS
   * @param capU
   * @param capZ
   * @param capR
   * @param vPrimePrime
   * @param n
   * @return capQ
   */
  public static BigInteger computeQ(final BigInteger capS, final BigInteger capU,
      final BigInteger capZ, final BigInteger[] capR, final BigInteger vPrimePrime,
      final BigInteger n, Vector<AttributeStructure> attStructs, Values values) {

    BigInteger capQ;

    final Vector<Exponentiation> e = new Vector<Exponentiation>();

    for (AttributeStructure attStruct : attStructs) {
      e.add(new Exponentiation(capR[attStruct.getKeyIndex()], (BigInteger) values
          .getValue(attStruct), n));
    }
    e.add(new Exponentiation(capS, vPrimePrime, n));

    capQ = Utils.multiExpMul(capU, e, n);
    capQ = capQ.modInverse(n);
    capQ = (capZ.multiply(capQ)).mod(n);

    return capQ;
  }
  /**
   * Updates a credential to the given values using the information from the issuer record.
   * 
   * @param issuerKeyPair Key pair to be used.
   * @param values New values of known attributes (only a subset of the known attributes might be
   *        updated).
   * @param issuerRecord Issuer record containing the old attribute values as well as the required
   *        signature elements to update the signature.
   */
  public static Message updateCredential(final IssuerKeyPair issuerKeyPair, final Values values,
      final IssuerUpdateInformation issuerRecord) {
    IssuerPublicKey publicKey = issuerKeyPair.getPublicKey();
    IssuerPrivateKey privateKey = issuerKeyPair.getPrivateKey();
    SystemParameters sp = publicKey.getGroupParams().getSystemParams();

    BigInteger e, vTilde, vBarPrimePrime;

    log.log(Level.INFO, issuerRecord.toStringPretty());

    // [spec: UpdateCredential 1.2] choose values to update the signature
    e = Utils.chooseE(sp);
    vTilde = Utils.computeRandomNumber(sp.getL_v() - 1);
    vBarPrimePrime = vTilde.add(BigInteger.ONE.shiftLeft(sp.getL_v() - 1));
    BigInteger deltaVPrimePrime = vBarPrimePrime.subtract(issuerRecord.getVPrimePrime());
    BigInteger n = publicKey.getN();

    Values newValues = new Values(sp);
    Vector<Exponentiation> expos = new Vector<Exponentiation>();
    expos.add(new Exponentiation(publicKey.getCapS(), deltaVPrimePrime, n));

    // get update specification to know which values should be updated
    Vector<AttributeStructure> attStructs =
        issuerRecord.getCredStruct().getAttributeStructs(IssuanceMode.KNOWN);
    UpdateSpecification updateSpec =
        (UpdateSpecification) StructureStore.getInstance().get(
            issuerRecord.getCredStruct().getUpdateSpecLocation());
    // check if all updated values are defined to be updateable
    updateSpec.verifyValues(values);
    attStructs = updateSpec.getCompliantAttributeSpecVector(attStructs);

    for (AttributeStructure attStruct : attStructs) {
      final String name = attStruct.getName();
      if (newValues.containsKey(name)) {
        throw new RuntimeException("Value: " + name + " is updated "
            + "twice within one update run. Please only provide "
            + "one update value per attribute.");
      }
      final BigInteger mBar_i = (BigInteger) values.getValue(attStruct);
      BigInteger deltaM_i = mBar_i.subtract(issuerRecord.getValue(name));
      expos.add(new Exponentiation(publicKey.getCapR()[attStruct.getKeyIndex()], deltaM_i, n));
      newValues.add(name, mBar_i);
    }
    BigInteger divisor = Utils.multiExpMul(expos, n).modInverse(n);
    BigInteger capQBar = issuerRecord.getCapQ().multiply(divisor).mod(n);

    BigInteger pPrime_qPrime = privateKey.computeQPrimePPrime();
    BigInteger eInverse = e.modInverse(pPrime_qPrime);
    BigInteger capABar = capQBar.modPow(eInverse, n);

    // [spec: UpdateCredential 1.3] create the proof.
    Vector<BigInteger> proofContext = new Vector<BigInteger>();
    proofContext.add(issuerRecord.getContext());
    proofContext.add(capQBar);
    proofContext.add(capABar);
    proofContext.add(issuerRecord.getNonce());

    final Proof p2 = computeATildeProof(proofContext, sp, n, pPrime_qPrime, eInverse, capQBar);

    issuerRecord.update(capQBar, vBarPrimePrime, newValues);

    log.log(Level.INFO, issuerRecord.toStringPretty());

    HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
    issuanceProtocolValues = new HashMap<IssuanceProtocolValues, BigInteger>();
    issuanceProtocolValues.put(IssuanceProtocolValues.capA, capABar);
    issuanceProtocolValues.put(IssuanceProtocolValues.e, e);
    issuanceProtocolValues.put(IssuanceProtocolValues.vPrimePrime, vBarPrimePrime);
    // issuanceProtocolValues.put(IssuanceProtocolValues.capQ, capQBar);

    return new Message(issuanceProtocolValues, p2);
  }
  /** Credential structure used for the issuing process. */
  private CredentialStructure certStruct;

  /** Convenience: Group parameters. */
  private final GroupParameters gp;

  /** Key pair of the issuer. */
  private final IssuerKeyPair issuerKeyPair;
  /** Data that allows to update a credential. */
  private IssuerUpdateInformation issuerUpdateInformation;
  /** Nonce. */
  private BigInteger nonce1;
  /** Revealed value in verifier in round 2 */
  private HashMap<String, BigInteger> revealedValues;
  /** Convenience: System parameters. */
  private final SystemParameters sp;

  /** Specification of the issuing process. */
  private AdvancedIssuanceSpec spec;

  private int state;

  /** Values for the issuance process (i.e., known attribute values). */
  private Values values;

  /**
   * Create an Issuer, to issue a credential to a Recipient.
   * 
   * @param issuerKey The issuer's public and private key.
   * @param issuanceSpec Issuance specification, describing what will be in the credential and how
   *        it will be issued.
   * @param pseudonym Pseudonym (optional).
   * @param theDomNym Domain pseudonym (optional).
   * @param theValues Values known to the issuer.
   */
  public AdvancedIssuer(final IssuerKeyPair issuerKey) {
    super();

    gp = issuerKey.getPublicKey().getGroupParams();
    sp = gp.getSystemParams();

    issuerKeyPair = issuerKey;
    state = 0;
  }

  /**
   * @return Update location for the credential that is about to be issued.
   */
  private URI getIndividualUpdateLocation(URI baseUri) {
    return baseUri.resolve("Update_" + Utils.getRandomString(20) + ".xml");
  }

  /**
   * @return Issuer update information, which contains all information (values and location
   *         information) that will allow issuing updates to this credential in the future.
   */
  public final IssuerUpdateInformation getIssuerUpdateInformation() {
    if (state != -1) {
      throw new RuntimeException("Cannot call getIssuerUpdateInformation at this point");
    }
    return issuerUpdateInformation;
  }

  /**
   * @return Random nonce n1.
   */
  private final BigInteger getNonce1() {
    // choose a random nonce n1 \in {0,1}^l_Phi.
    nonce1 = Utils.computeRandomNumber(sp.getL_Phi());
    return nonce1;
  }

  public final BigInteger getRevealedDomNymValue(String predicateName) {
    if (state != -1) {
      throw new RuntimeException("Cannot call getRevealedDomNymValue at this point");
    }
    String key = "DomainPseudonym" + Constants.DELIMITER + predicateName;
    return revealedValues.get(key);
  }

  public final BigInteger getRevealedPseudonymValue(String predicateName) {
    if (state != -1) {
      throw new RuntimeException("Cannot call getRevealedPseudonymValue at this point");
    }
    String key = "Pseudonym" + Constants.DELIMITER + predicateName;
    return revealedValues.get(key);
  }

  /**
   * Returns the map of revealed values of the verifier in round 2.
   * 
   * @return
   */
  public final HashMap<String, BigInteger> getRevealedValues() {
    if (state != -1) {
      throw new RuntimeException("Cannot call getRevealedValues at this point");
    }
    return revealedValues;
  }

  /**
   * To correctly initiate the Issuer it requires to create a nonce. This nonce guarantees the
   * freshness of the proof created by the Recipient.
   * 
   * @return a response to the Recipient containing the nonce.
   */
  public final Message round0() {
    if (state != 0) {
      throw new RuntimeException("Cannot call round 0 at this point");
    }
    state = 2;

    HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
    issuanceProtocolValues = new HashMap<IssuanceProtocolValues, BigInteger>();
    issuanceProtocolValues.put(IssuanceProtocolValues.nonce, getNonce1());
    return new Message(issuanceProtocolValues, null, null);

  }

  public final Message round2(final Message msg, final AdvancedIssuanceSpec issuanceSpec,
      final Values theValues, VerifierInput verifierInput) {

    if (state != 2) {
      throw new RuntimeException("Cannot call round 2 at this point");
    }
    state = -1;

    spec = issuanceSpec;
    certStruct = spec.getCredentialStructure();
    values = theValues;
    if (!certStruct.verifyIssuerValues(values)) {
      throw new IllegalArgumentException("Values given to the "
          + "issuer do not correspond to the credential " + "structure.");
    }

    Verifier verifier = new Verifier(spec.getSpec(), msg.getProof(), nonce1, verifierInput);

    if (!verifier.verify()) {
      String error = "Proof does not verify";
      System.err.println(error);
      throw new RuntimeException(error);
    }
    revealedValues = verifier.getRevealedValues();

    final BigInteger n = issuerKeyPair.getPublicKey().getN();
    BigInteger toSign = msg.getProof().getCommonValue(spec.getTempNameOfCredInProof());

    // Check all revealed values
    for (AttributeStructure as : certStruct.getAttributeStructs(IssuanceMode.KNOWN)) {
      String name = as.getName();
      BigInteger expected = (BigInteger) values.get(name).getContent();
      String longname = spec.getTempNameOfCredInProof() + ";" + name;
      BigInteger actual = verifier.getRevealedValues().get(longname);
      if (!expected.equals(actual)) {
        String error =
            "For attribute " + name + " - " + longname + "   Expected: " + expected + "  Actual: "
                + actual;
        System.err.println(error);
        throw new RuntimeException(error);
      }
    }

    // Add "issuer" attributes
    Map<String, BigInteger> issuerValues = new HashMap<String, BigInteger>();
    for (AttributeStructure as : certStruct.getAttributeStructs(IssuanceMode.ISSUER)) {
      String name = as.getName();
      int keyIndex = as.getKeyIndex();
      BigInteger exponent = (BigInteger) values.get(name).getContent();
      BigInteger base = issuerKeyPair.getPublicKey().getCapR()[keyIndex];
      toSign = toSign.multiply(base.modPow(exponent, n)).mod(n);
      issuerValues.put(name, exponent);
    }


    Vector<AttributeStructure> attStructs = certStruct.getAttributeStructs();

    // we can now start generating the signature.
    final BigInteger e = Utils.chooseE(sp);

    final BigInteger vTilde = Utils.computeRandomNumber(sp.getL_v() - 1);
    final BigInteger vPrimePrime = vTilde.add(BigInteger.ONE.shiftLeft(sp.getL_v() - 1));

    final IssuerPrivateKey privKey = issuerKeyPair.getPrivateKey();
    // p = 2*p' + 1, q = 2*q' + 1
    final BigInteger pPrime_qPrime = privKey.computeQPrimePPrime();
    // getPPrime().multiply( privKey.getQPrime());
    BigInteger eInverse = e.modInverse(pPrime_qPrime);
    /**
     * Due to a bug in the IBM JVM, we serialize and deserialize eInverse
     * here. I couldn't find the root cause. (rre)
     */
    eInverse = new BigInteger(eInverse.toString());

    final IssuerPublicKey pubKey = issuerKeyPair.getPublicKey();
    final BigInteger capQ =
        computeQ(pubKey.getCapS(), toSign, pubKey.getCapZ(), pubKey.getCapR(), vPrimePrime,
            pubKey.getN(), new Vector<AttributeStructure>(), values);
    log.log(Level.INFO, "capQ: " + Utils.logBigInt(capQ));

    final BigInteger capA = capQ.modPow(eInverse, n);

    // [spec: IssueCredentialProtocol 2.2]
    BigInteger context = spec.getContext();
    BigInteger nonce_recipient = msg.getIssuanceElement(IssuanceProtocolValues.nonce);
    Vector<BigInteger> proofContext = new Vector<BigInteger>();
    proofContext.add(context);
    proofContext.add(capQ);
    proofContext.add(capA);
    proofContext.add(nonce_recipient);

    final Proof p2 = computeATildeProof(proofContext, sp, n, pPrime_qPrime, eInverse, capQ);

    Message response;
    HashMap<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
    issuanceProtocolValues = new HashMap<IssuanceProtocolValues, BigInteger>();
    issuanceProtocolValues.put(IssuanceProtocolValues.capA, capA);
    issuanceProtocolValues.put(IssuanceProtocolValues.e, e);
    issuanceProtocolValues.put(IssuanceProtocolValues.vPrimePrime, vPrimePrime);

    URI updateSpecLocation = spec.getCredentialStructure().getUpdateSpecLocation();
    URI updateLocation = null;

    if (updateSpecLocation != null) {

      UpdateSpecification updateSpec =
          (UpdateSpecification) StructureStore.getInstance().get(updateSpecLocation);

      // note, the attStructs will not be needed for any other purpose, so
      // we re-use it
      attStructs = updateSpec.getCompliantAttributeSpecVector(attStructs);

      Values updatedValues = new Values(sp);
      for (AttributeStructure attStruct : attStructs) {
        if (attStruct.getIssuanceMode() != IssuanceMode.KNOWN) {
          throw new RuntimeException("Only values that are known to "
              + "the ISSUER can be updated.");
        }
        final String name = attStruct.getName();
        updatedValues.add(name, values.get(name).getContent());
      }
      updateLocation = getIndividualUpdateLocation(updateSpec.getBaseLocation());
      issuerUpdateInformation =
          new IssuerUpdateInformation(spec.getIssuerPublicKeyId(), spec.getCredStructureLocation(),
              capQ, vPrimePrime, updatedValues, updateLocation, nonce_recipient, context);

      log.log(Level.INFO, issuerUpdateInformation.toStringPretty());

      response = new Message(issuanceProtocolValues, p2, updateLocation, 2, issuerValues);
    } else {
      response = new Message(issuanceProtocolValues, p2, null, 2, issuerValues);
    }
    return response;
  }
}
