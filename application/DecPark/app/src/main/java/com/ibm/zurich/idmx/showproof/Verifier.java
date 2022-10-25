//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.dm.Commitment;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.Representation;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.accumulator.AccumulatorState;
import com.ibm.zurich.idmx.showproof.accumulator.AccumulatorWitness;
import com.ibm.zurich.idmx.showproof.ip.InequalityVerifier;
import com.ibm.zurich.idmx.showproof.pe.PrimeEncodeVerifier;
import com.ibm.zurich.idmx.showproof.predicates.AccumulatorPredicate;
import com.ibm.zurich.idmx.showproof.predicates.CLComPredicate;
import com.ibm.zurich.idmx.showproof.predicates.CLPredicate;
import com.ibm.zurich.idmx.showproof.predicates.CommitmentPredicate;
import com.ibm.zurich.idmx.showproof.predicates.DomainNymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.InequalityPredicate;
import com.ibm.zurich.idmx.showproof.predicates.MessagePredicate;
import com.ibm.zurich.idmx.showproof.predicates.NotEqualPredicate;
import com.ibm.zurich.idmx.showproof.predicates.Predicate;
import com.ibm.zurich.idmx.showproof.predicates.PrimeEncodePredicate;
import com.ibm.zurich.idmx.showproof.predicates.PseudonymPredicate;
import com.ibm.zurich.idmx.showproof.predicates.RepresentationPredicate;
import com.ibm.zurich.idmx.showproof.predicates.VerEncPredicate;
import com.ibm.zurich.idmx.showproof.sval.SValue;
import com.ibm.zurich.idmx.showproof.sval.SValuesIP;
import com.ibm.zurich.idmx.showproof.sval.SValuesProveCL;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;

/**
 * The Idemix show-proof verification side. This class runs the various sub-proofs after getting the
 * proof data from the prover.
 * 
 * @see Prover
 */
public class Verifier {

  /** Logger. */
  private static Logger log = Logger.getLogger(Verifier.class.getName());

  private static final int LOWER = 0;
  private static final int UPPER = 1;

  /**
   * @param sp System parameters.
   * @return Verifier's nonce.
   */
  public static BigInteger generateNonce(final SystemParameters sp) {
    return Utils.computeRandomNumberSymmetric(sp.getL_m());
  }

  private static void getMHatBounds(final SystemParameters sp, final BigInteger bounds[]) {
    assert (bounds.length == 2);
    // compute the lower & upper bounds for length checks for mHat
    // we do this outside the loop to save a few big-int ops...
    int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H() + 1;

    BigInteger upper = BigInteger.ONE.shiftLeft(bitlength);
    BigInteger lower = upper.negate();
    upper = upper.subtract(BigInteger.ONE);
    lower = lower.add(BigInteger.ONE);

    bounds[LOWER] = lower;
    bounds[UPPER] = upper;
  }

  /** Computed value of Fiat-Shamir challenge. */
  private BigInteger challengeHat = null;
  /** Group parameters. */
  private final GroupParameters gp;

  private final VerifierInput input;

  /** nonce value. */
  private final BigInteger n1;

  /**
   * negative value of proof's challenge (c, Fiat-Shamir challenge) value. Is used a lot, hence we
   * keep it available as instance variable to save negations.
   */
  private BigInteger negC;

  /** the proof as built by the prover. */
  private final Proof proof;

  /** Stores values that are revealed during the proof. */
  private HashMap<String, BigInteger> revealedValues;

  /** System parameters in use. */
  private final SystemParameters sp;

  /** the proof-spec we're trying to verify. */
  private final ProofSpec spec;
  /** List of re-computed t-values (t-Hat-values). */
  private final Vector<BigInteger> tHatList;

  public Verifier(final ProofSpec proofSpec, final Proof theProof, final BigInteger theN1) {
    this(proofSpec, theProof, theN1, new VerifierInput());
  }
  public Verifier(final ProofSpec proofSpec, final Proof theProof, final BigInteger theN1,
      final VerifierInput input) {

    n1 = theN1;
    spec = proofSpec;

    gp = proofSpec.getGroupParams();
    sp = gp.getSystemParams();

    proof = theProof;
    this.input = input;

    tHatList = new Vector<BigInteger>();
    revealedValues = new HashMap<String, BigInteger>();

    validateSpec();
  }

  private boolean checkLength_eHat(final BigInteger eHat) {
    int bitlength = sp.getL_ePrime() + sp.getL_Phi() + sp.getL_H() + 1;
    return Utils.isInInterval(eHat, bitlength);
  }

  /**
   * @return FS challenge value.
   */
  private BigInteger computeChallengeHat() {
    Vector<BigInteger> list = new Vector<BigInteger>();
    // TODO (pbi) define how the common list and messages should be ordered
    // (cf. Prover.java)
    list.addAll(proof.getCommonList().values());
    list.addAll(tHatList);

    if (input.messages == null) {
      input.messages = new TreeMap<String, MessageToSign>();
    }
    BigInteger challenge =
        Utils.computeChallenge(sp, spec.getContext(), list, n1, input.messages.values());

    return challenge;
  }

  /**
   * Convenience method.
   * 
   * @param aPrime Value of <tt>A'</tt>.
   * @param n Modulus.
   * @return <tt>A'^(2^(l_e - 1)) mod n</tt>.
   */
  private BigInteger get_APrime_powered_2_le_minus_1(final BigInteger aPrime, final BigInteger n) {
    int expOf2 = sp.getL_e() - 1;
    final BigInteger exp = BigInteger.ONE.shiftLeft(expOf2);
    return aPrime.modPow(exp, n);
  }

  /**
   * To retrieve the common value for a range proof predicate.
   * 
   * @param tag range proof tag.
   * @return common value or null.
   */
  public BigInteger getCommonValRP(final String tag) {
    return proof.getCommonValue(tag);
  }

  public BigInteger getNegC() {
    return negC;
  }

  public final BigInteger getRevealedDomNymValue(String predicateName) {
    String key = "DomainPseudonym" + Constants.DELIMITER + predicateName;
    return revealedValues.get(key);
  }

  public final BigInteger getRevealedPseudonymValue(String predicateName) {
    String key = "Pseudonym" + Constants.DELIMITER + predicateName;
    return revealedValues.get(key);
  }

  public final HashMap<String, BigInteger> getRevealedValues() {
    return revealedValues;
  }

  /**
   * Validate the proof specification.
   */
  private void validateSpec() {
    Iterator<Predicate> predicates = spec.getPredicates().iterator();
    while (predicates.hasNext()) {
      Predicate predicate = predicates.next();
      switch (predicate.getPredicateType()) {
        case CL:
          // TODO (pbi) verify that all credential structures are
          // available
          break;
        case CLCOM:
          break;
        case COMMITMENT:
          String name = ((CommitmentPredicate) predicate).getName();
          if (input.commitments.get(name) == null) {
            throw new RuntimeException("Missing commitment with " + "temporary name: " + name);
          }
          // TODO (pbi) verify that all commitments are used (i.e., all
          // elements in commitments are referred to by a predicate?
          break;
        case DOMAINNYM:
          break;
        case PSEUDONYM:
          break;
        case INEQUALITY:
          // TODO (pbi) verify that inequality holds?
          break;
        case NOTEQUAL:
          break;
        case VERENC:
          // TODO (pbi) verify that all verifiable encryptions are
          // available
          break;
        case REPRESENTATION:
          // TODO (pbi) verify that all required representations are
          // available
          // TODO (pbi) verify that bases in the spec == bases in the
          // object
          break;
        case MESSAGE:
          break;
        case ENUMERATION:
          break;
        case ACCUMULATOR:
        {
          AccumulatorPredicate accPred = (AccumulatorPredicate)predicate;
          AccumulatorState accState = input.accumulatorStates.get(accPred.getTempName());
          if(accState == null) {
            throw new RuntimeException("Missing accumulator witness for: " + accPred.getTempName());
          }
          if(accState.getEpoch() != accPred.getEpoch()) {
            throw new RuntimeException("Invalid accumulator epoch for: " + accPred.getTempName());
          }
          if(! accState.getPublicKey().getUri().equals(accPred.getPublicKey())) {
            throw new RuntimeException("Invalid accumulator public key for: " + accPred.getTempName());
          }
          break;
        }
        default:
          throw new RuntimeException("Wrong predicate type.");
      }
    }
  }

  /**
   * The verification routine.
   * 
   * @return success or failure.
   */
  public final boolean verify() {
    boolean usingSmartcard = false;
    // compute -c, used in sub-verifications.
    negC = proof.getChallenge().negate();
    
    System.out.println("Verifying proof (Idemix "+Constants.getVersion()+")");

    if(!checkGroupParameters(gp, sp)) {
      log.log(Level.SEVERE, "Incompatible system/group parameters.");
      return false;
    }
    if(!checkProofSpec(spec)) {
      log.log(Level.SEVERE, "Incompatible proof spec.");
      return false;
    }
    
    // Iterate over predicates, calling corresponding sub-verifiers
    Iterator<Predicate> predicates = spec.getPredicates().iterator();
    while (predicates.hasNext()) {
      Predicate predicate = predicates.next();
      switch (predicate.getPredicateType()) {
        case CL: {
          CLPredicate pred = (CLPredicate) predicate;
          CredentialStructure credStruct =
              (CredentialStructure) StructureStore.getInstance().get(pred.getCredStructLocation());
          verifyCL(credStruct, pred);
          if (credStruct.isOnSmartcard()) {
            usingSmartcard = true;
          }
        }
          break;
        case CLCOM: {
          CLComPredicate pred = (CLComPredicate) predicate;
          CredentialStructure credStruct =
              (CredentialStructure) StructureStore.getInstance().get(pred.getCredStructLocation());
          verifyCLCom(credStruct, pred);
          if (credStruct.isOnSmartcard()) {
            usingSmartcard = true;
          }
        }
          break;
        case ENUMERATION:
          addRecomputedTValues(verifyPrimeEncode((PrimeEncodePredicate) predicate));
          break;
        case INEQUALITY:
          verifyInequality((InequalityPredicate) predicate);
          break;
        case NOTEQUAL:
          verifyNotEqual((NotEqualPredicate) predicate);
          break;
        case COMMITMENT:
          CommitmentPredicate predComm = (CommitmentPredicate) predicate;
          Commitment comm = input.commitments.get(predComm.getName());
          verifyCommitment(comm, predComm);
          break;
        case REPRESENTATION:
          verifyRepresentation((RepresentationPredicate) predicate);
          break;
        case PSEUDONYM: {
          verifyPseudonym((PseudonymPredicate) predicate);
          usingSmartcard = true;
        }
          break;
        case DOMAINNYM: {
          verifyDomainNym((DomainNymPredicate) predicate);
          usingSmartcard = true;
        }
          break;
        case VERENC:
          verifyVerEnc((VerEncPredicate) predicate);
          break;
        case MESSAGE:
          verifyMessage((MessagePredicate) predicate);
          break;
        case ACCUMULATOR:
          verifyAccumulator((AccumulatorPredicate) predicate);
          break;
        default:
          throw new RuntimeException("Unimplemented predicate.");
      }
    }

    // [spec: verifyProof 2.] Compute the challenge and compare it:
    challengeHat = computeChallengeHat();
    if (usingSmartcard) {
      log.log(Level.INFO, "on smartcard: hashing twice...");
      byte[] preimage = challengeHat.toByteArray();
      challengeHat = input.smartcardHelper.computeChallenge(preimage, proof.getSmartcardNonce());
    }

    // [spec: verifyProof 3.]
    if (!challengeHat.equals(proof.getChallenge())) {
      log.log(Level.SEVERE, "mismatch c, cHat");
      return false;
    } else {
      log.log(Level.INFO, "c == cHat!");
    }

    return true;

  }

  private boolean checkGroupParameters(GroupParameters gp2, SystemParameters sp2) {
    BigInteger gphash = proof.getCommonValue("gp");
    BigInteger sphash = proof.getCommonValue("sp");
    if(sphash != null) {
      if(!sphash.equals(sp2.generateHash())) {
        log.severe("Incompatible system parameters");
        return false;
      }
    } else {
      log.warning("Did not check for compatibility of system parameters");
    }
    if(gphash != null) {
      if(!gphash.equals(gp2.generateHash())) {
        log.severe("Incompatible group parameters");
        return false;
      }
    } else {
      log.warning("Did not check for compatibility of group parameters");
    }
    return true;
  }
  
  private boolean checkProofSpec(ProofSpec ps) {
    BigInteger proofSpecHash = proof.getCommonValue("proofSpecHash");
    if(proofSpecHash != null) {
      if(!proofSpecHash.equals(ps.generateHash())) {
        log.severe("Incompatible proof specifications");
        return false;
      }
    } else {
      log.warning("Did not check for compatibility of proof specifications.");
    }
    return true;
  }

  private void verifyAccumulator(AccumulatorPredicate predicate) {
    final BigInteger s_e = (BigInteger) proof.getSValue(predicate.getValue().getName()).getValue();
    
    AccumulatorState state = input.accumulatorStates.get(predicate.getTempName());
    if (predicate.getValue().isRevealed()) {
      String commonName = predicate.getTempName() + Constants.DELIMITER + "W";
      final BigInteger witness = proof.getCommonValue(commonName);
      
      AccumulatorWitness w = new AccumulatorWitness(state, s_e, witness);
      if (! w.isConsistent()) {
        throw new RuntimeException("Revealed witness for accumulator predicate " + predicate.getTempName() + " is wrong.");
      }
    } else {
      BigInteger v = state.getAccumulatorValue();
      BigInteger n = state.getPublicKey().getN();
      BigInteger g = state.getPublicKey().getBaseG();
      BigInteger h = state.getPublicKey().getBaseH();
      
      // Get common values
      String prefix = predicate.getTempName() + Constants.DELIMITER;
      BigInteger Ce = proof.getCommonValue(prefix + "Ce");
      BigInteger Cu = proof.getCommonValue(prefix + "Cu");
      BigInteger Cr = proof.getCommonValue(prefix + "Cr");
      
      // Get S-values
      BigInteger s_r1 = (BigInteger) proof.getSValue(prefix + "s_r1").getValue();
      BigInteger s_r2 = (BigInteger) proof.getSValue(prefix + "s_r2").getValue();
      BigInteger s_r3 = (BigInteger) proof.getSValue(prefix + "s_r3").getValue();
      BigInteger s_r2e = (BigInteger) proof.getSValue(prefix + "s_r2e").getValue();
      BigInteger s_r3e = (BigInteger) proof.getSValue(prefix + "s_r3e").getValue();
      
      // Ce = g^e * h^r1
      BigInteger t_Ce = Ce.modPow(negC, n).multiply(g.modPow(s_e, n).multiply(h.modPow(s_r1, n))).mod(n);
      // Cr = g^r2 * h^r3
      BigInteger t_Cr = Cr.modPow(negC, n).multiply(g.modPow(s_r2, n).multiply(h.modPow(s_r3, n))).mod(n);
      // v = Cu^e * h^r2e
      BigInteger t_v = v.modPow(negC, n).multiply(Cu.modPow(s_e, n).multiply(h.modPow(s_r2e, n))).mod(n);
      // 1 = Cr^e * g^r2e * h^r3e
      BigInteger t_1 = Cr.modPow(s_e, n).multiply(g.modPow(s_r2e, n)).multiply(h.modPow(s_r3e, n)).mod(n);
      
      addRecomputedTValue(t_Ce);
      addRecomputedTValue(t_Cr);
      addRecomputedTValue(t_v);
      addRecomputedTValue(t_1);
    }
  }

  /**
   * Verify the CL signature for this predicate.
   * 
   * @param credStruct Credential structure.
   * @param pred CL predicate.
   * 
   * @return success or failure.
   */
  private boolean verifyCL(final CredentialStructure credStruct, final CLPredicate pred) {

    final SValue clSVal = proof.getSValue(pred.getTempCredName());
    log.log(Level.FINE, pred.getTempCredName());
    assert (clSVal != null);

    final IssuerPublicKey pubKey = pred.getIssuerPublicKey();
    final BigInteger n = pubKey.getN();
    
    checkIssuerPublicKey(pubKey, pred.getTempCredName());

    // get the blinded signature
    final BigInteger capAPrime = proof.getCommonValue(pred.getTempCredName());

    SValuesProveCL sValsProveCL = (SValuesProveCL) clSVal.getValue();
    final BigInteger eHat = sValsProveCL.getEHat();
    final BigInteger vHatPrime = sValsProveCL.getVHatPrime();
    // check length of eHat
    if (!checkLength_eHat(eHat)) {
      log.log(Level.SEVERE, "length check on eHat failed");
      throw new RuntimeException("[Verifier:verifyCL()] Proof of "
          + "Knowledge of the CL signature failed.");
    }

    // Compute tHat
    Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
    Vector<Exponentiation> productNotRevealed = new Vector<Exponentiation>();

    productNotRevealed.add(new Exponentiation(capAPrime, eHat, n));

    if (credStruct.isOnSmartcard()) {
      String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getTempSecretName();
      BigInteger sx = (BigInteger) proof.getSValue(scName).getValue();
      BigInteger R0 = pubKey.getCapR()[IssuanceSpec.SMARTCARD_SECRET_INDEX];
      productNotRevealed.add(new Exponentiation(R0, sx, n));
    }

    // setup the bounds for length checks on s-values
    final BigInteger[] bounds = {BigInteger.ZERO, BigInteger.ZERO};
    getMHatBounds(sp, bounds);

    // [spec: VerifyCL 1.] Iterate over the identifiers: if it's a hidden
    // value, get the s-value,
    // if it's revealed, get the value: prepare the products we need to
    // compute tHat
    Iterator<AttributeStructure> atts = credStruct.getAttributeStructs().iterator();
    while (atts.hasNext()) {
      int keyIndex;
      AttributeStructure att = atts.next();
      Identifier id = pred.getIdentifier(att.getName());

      BigInteger sValue = (BigInteger) proof.getSValue(id.getName()).getValue();
      keyIndex = att.getKeyIndex();
      assert (sValue != null);

      if (!id.isRevealed()) {
        // add it to the unrevealed product
        productNotRevealed.add(new Exponentiation(pubKey.getCapR()[keyIndex], sValue, n));
        // [spec: VerifyCL 2.]
        if (!Utils.isInInterval(sValue, bounds[LOWER], bounds[UPPER])) {
          throw new RuntimeException("[Verifier:verifyCL()] " + "Length check failed.");
        }
      } else {
        // add revealed value to list
        revealedValues.put(pred.getTempCredName() + Constants.DELIMITER + att.getName(), sValue);

        // add it to the revealed product
        productRevealed.add(new Exponentiation(pubKey.getCapR()[keyIndex], sValue, n));
      }
    }

    BigInteger divisor = BigInteger.ONE;
    divisor = Utils.multiExpMul(divisor, productRevealed, n);

    divisor = divisor.multiply(get_APrime_powered_2_le_minus_1(capAPrime, n)).mod(n);
    // take the modular inverse of divisor
    divisor = divisor.modInverse(n);

    // initial value
    BigInteger tHat = pubKey.getCapZ();
    tHat = tHat.multiply(divisor).mod(n);
    tHat = tHat.modPow(negC, n);

    productNotRevealed.add(new Exponentiation(pubKey.getCapS(), vHatPrime, n));
    tHat = Utils.multiExpMul(tHat, productNotRevealed, n);

    addRecomputedTValue(tHat);
    return true;
  }

  private void checkIssuerPublicKey(IssuerPublicKey pubKey, String tempCredName) {
    String commonName = tempCredName + Constants.DELIMITER + "issuerPk";
    BigInteger pkhash = proof.getCommonValue(commonName);
    if (pkhash != null) {
      if (!pkhash.equals(pubKey.generateHash())) {
        throw new RuntimeException("Incorrect issuer public key for " + tempCredName);
      }
      // System.err.println("Checked " + tempCredName);
    } else {
      log.warning("Did not check issuer public key for " + tempCredName);
    }
  }

  private void verifyCLCom(CredentialStructure credStruct, CLComPredicate pred) {

    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# verifier start");
    
    final IssuerPublicKey pubKey = pred.getIssuerPublicKey();
    final BigInteger n = pubKey.getN();
    
    checkIssuerPublicKey(pubKey, pred.getTempCredName());

    // prepare the products of revealed and hidden values in the commitment
    Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
    Vector<Exponentiation> productHidden = new Vector<Exponentiation>();

    if (credStruct.isOnSmartcard()) {
      String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getTempSecretName();
      BigInteger sx = (BigInteger) proof.getSValue(scName).getValue();
      BigInteger R0 = pubKey.getCapR()[IssuanceSpec.SMARTCARD_SECRET_INDEX];
      productHidden.add(new Exponentiation(R0, sx, n));
    }

    final BigInteger[] bounds = {BigInteger.ZERO, BigInteger.ZERO};
    getMHatBounds(sp, bounds);

    Iterator<AttributeStructure> atts = credStruct.getAttributeStructs().iterator();
    while (atts.hasNext()) {
      int keyIndex;
      AttributeStructure att = atts.next();
      if (att.getIssuanceMode() == IssuanceMode.ISSUER) {
        if (!pred.containsIdentifier(att.getName())) {
          continue;
        }
      }
      Identifier id = pred.getIdentifier(att.getName());

      BigInteger sValue = (BigInteger) proof.getSValue(id.getName()).getValue();
      keyIndex = att.getKeyIndex();
      assert (sValue != null);

      if (!id.isRevealed()) {
        productHidden.add(new Exponentiation(pubKey.getCapR()[keyIndex], sValue, n));
        if (!Utils.isInInterval(sValue, bounds[LOWER], bounds[UPPER])) {
          throw new RuntimeException("[Verifier:verifyCLCom()] " + "Length check failed.");
        }
      } else {
        revealedValues.put(pred.getTempCredName() + Constants.DELIMITER + att.getName(), sValue);
        productRevealed.add(new Exponentiation(pubKey.getCapR()[keyIndex], sValue, n));
      }
    }

    BigInteger cPrime = proof.getCommonValue(pred.getTempCredName());
    if (productRevealed.size() > 0) {
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# product-revealed:");
      BigInteger denom = Utils.multiExpMul(productRevealed, n);
      denom = denom.modInverse(n);
      cPrime = cPrime.multiply(denom).mod(n);
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# cPrime: " + cPrime);
    }

    productHidden.add(new Exponentiation(cPrime, negC, n));
    productHidden.add(new Exponentiation(pubKey.getCapS(), ((BigInteger) proof.getSValue(
        pred.getTempCredName()).getValue()), n));
    assert (productHidden != null && n != null);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# product-hidden:");
    BigInteger cHat = Utils.multiExpMul(productHidden, n);

    // output cHat
    addRecomputedTValue(cHat);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# verifier end");
  }

  /**
   * Verification of commitments.
   * 
   * @param comm Commitment.
   * @param pred Commitment predicate.
   */
  private void verifyCommitment(final Commitment comm, final CommitmentPredicate pred) {
    assert (comm != null);

    BigInteger n = comm.getN();

    // prepare the products of revealed and hidden values in the commitment
    Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
    Vector<Exponentiation> productHidden = new Vector<Exponentiation>();

    Vector<Identifier> identifiers = pred.getIdentifiers();
    for (int i = 0; i < identifiers.size(); i++) {
      Identifier identifier = identifiers.get(i);
      BigInteger m = (BigInteger) proof.getSValue(identifier.getName()).getValue();
      Exponentiation e = new Exponentiation(comm.getMsgBase(i), m, n);
      if (identifier.isRevealed()) {
        productRevealed.add(e);
      } else {
        productHidden.add(e);
      }
    }

    BigInteger cPrime = comm.getCommitment();
    if (productRevealed.size() > 0) {
      BigInteger denom = Utils.multiExpMul(productRevealed, n);
      denom = denom.modInverse(n);
      cPrime = cPrime.multiply(denom).mod(n);
    }

    productHidden.add(new Exponentiation(cPrime, negC, n));
    productHidden.add(new Exponentiation(comm.getCapS(), ((BigInteger) proof.getSValue(
        pred.getName()).getValue()), n));
    assert (productHidden != null && n != null);
    BigInteger cHat = Utils.multiExpMul(productHidden, n);

    // output cHat
    addRecomputedTValue(cHat);
  }

  /**
   * Verification of domain nym.
   * 
   * @param pred Domain pseudonym predicate.
   */
  private void verifyDomainNym(final DomainNymPredicate pred) {
    String name = pred.getTempName();
    BigInteger proverDomNym = proof.getCommonValue(name);

    // add domNym to list of revealed values
    revealedValues.put("DomainPseudonym" + Constants.DELIMITER + name, proverDomNym);

    String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getTempSecretName();
    BigInteger mHat_1 = (BigInteger) proof.getSValue(scName).getValue();

    final BigInteger gamma = gp.getCapGamma();
    final BigInteger rho = gp.getRho();
    final URI scope = pred.getDomain();

    BigInteger base =
        input.smartcardHelper.computeBaseForScopeExclusivePseudonym(scope, gamma, rho);
    BigInteger base2 = proof.getCommonValue(pred.getTempName() + Constants.DELIMITER + "base");
    if(base2 != null) {
      if(!base.equals(base2)) {
        throw new RuntimeException("Incompatible base for scope exclusive pseudonym.");
      }
    } else {
      log.log(Level.WARNING, "Did not check base for pseudonym " + pred.getTempName());
    }

    Vector<Exponentiation> product = new Vector<Exponentiation>();
    product.add(new Exponentiation(proverDomNym, negC, gamma));
    product.add(new Exponentiation(base, mHat_1, gamma));

    BigInteger dNymHat = Utils.multiExpMul(product, gamma);
    addRecomputedTValue(dNymHat);
    

  }

  /**
   * Verification of inequalities.
   * 
   * @param pred Inequality predicate.
   */
  private void verifyInequality(final InequalityPredicate pred) {
    if (pred.getSecondArgument() == null) {
      Identifier id = pred.getSecondArgumentIdentifier();
      id.setValue((BigInteger) proof.getSValue(id.getName()).getValue());
    }
    checkIssuerPublicKey(pred.getKey(), pred.getName());
    final InequalityVerifier rv = new InequalityVerifier(this, pred);
    final SValue sVals = proof.getSValue(pred.getName());

    SValuesIP sValuesIP;
    // adding the mHat from the CL proof!
    if (sVals.getValue() instanceof SValuesIP) {
      sValuesIP = (SValuesIP) sVals.getValue();
      sValuesIP.addMHat((BigInteger) proof.getSValue(pred.getFirstArgumentIdentifier().getName())
          .getValue());
    } else {
      throw new RuntimeException("Wrong type of s-values. " + "'SValuesIP' would be expected.");
    }
    addRecomputedTValues(rv.computeTHatValues((SValuesIP) sVals.getValue()));
  }

  /**
   * @param pred Message predicate.
   */
  private void verifyMessage(final MessagePredicate pred) {
    assert (input.messages != null);
    assert (!input.messages.isEmpty());
    MessageToSign msg = input.messages.get(pred.getName());
    assert (msg != null);

    Validation.validateMessage(pred, msg);
  }

  private void verifyNotEqual(NotEqualPredicate predicate) {
    final BigInteger gamma = gp.getCapGamma();
    final BigInteger g = gp.getG();
    final BigInteger h = gp.getH();
    final BigInteger rhs = predicate.getRhs(proof);
    final BigInteger challenge = negC;

    final BigInteger s_l = (BigInteger) proof.getSValue(predicate.getLhs().getName()).getValue();
    String prefix = predicate.getName() + Constants.DELIMITER;

    if (predicate.getLhs().isRevealed()) {
      BigInteger lhs = s_l;
      if (lhs.equals(rhs)) {
        throw new RuntimeException("Invalid revealed not-equal predicate");
      }
      // trivial
      System.out.println("Trivial not-equal predicate: " + lhs + " != " + rhs);
    } else {
      BigInteger C = proof.getCommonValue(predicate.getName() + Constants.DELIMITER + "C");
      // compute Chat = C * g^{-rhs}
      BigInteger Chat = C.multiply(g.modPow(rhs.negate(), gamma)).mod(gamma);
  
      // Recover s-values
      BigInteger s_a = (BigInteger) proof.getSValue(prefix + "s_a").getValue();
      BigInteger s_b = (BigInteger) proof.getSValue(prefix + "s_b").getValue();
      BigInteger s_r = (BigInteger) proof.getSValue(prefix + "s_r").getValue();
  
      // Prove C = g^lhs * h^r
      BigInteger t_C =
          C.modPow(challenge, gamma).multiply(g.modPow(s_l, gamma).multiply(h.modPow(s_r, gamma)))
              .mod(gamma);
  
      // Prove that g = Chat^a * h^b
      BigInteger t_g =
          g.modPow(challenge, gamma).multiply(Chat.modPow(s_a, gamma).multiply(h.modPow(s_b, gamma)))
              .mod(gamma);
  
      addRecomputedTValue(t_C);
      addRecomputedTValue(t_g);
    }
  }

  /**
   * @param pred Prime encode predicate.
   * @return <tt>tHat</tt> value.
   */
  private Vector<BigInteger> verifyPrimeEncode(final PrimeEncodePredicate pred) {
    IssuerPublicKey ipk = Utils.getPrimeEncodingConstants(pred);
    PrimeEncodeVerifier pev = new PrimeEncodeVerifier(pred, proof, ipk, negC);
    return pev.computeTHatValues();
  }

  /**
   * @param pred Pseudonym predicate.
   */
  private void verifyPseudonym(final PseudonymPredicate pred) {
    String name = pred.getName();
    BigInteger proverNym = proof.getCommonValue(name);

    // add domNym to list of revealed values
    revealedValues.put("Pseudonym" + Constants.DELIMITER + name, proverNym);

    String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getSecretName();
    BigInteger mHat_1 = (BigInteger) proof.getSValue(scName).getValue();
    BigInteger rHat = (BigInteger) proof.getSValue(name).getValue();

    final BigInteger gamma = gp.getCapGamma();

    Vector<Exponentiation> product = new Vector<Exponentiation>();
    product.add(new Exponentiation(proverNym, negC, gamma));
    product.add(new Exponentiation(gp.getG(), mHat_1, gamma));
    product.add(new Exponentiation(gp.getH(), rHat, gamma));

    BigInteger nymHat = Utils.multiExpMul(product, gamma);
    addRecomputedTValue(nymHat);
  }

  /**
   * @param pred Representation predicate.
   */
  private void verifyRepresentation(final RepresentationPredicate pred) {
    Representation rep = null;
    String name = pred.getName();

    rep = input.representations.get(name);
    assert (rep != null);

    // validate the bases in the proof spec vs. the representation object
    Validation.validateRepresentation(pred, rep);

    // [spec: VerifyRepresentation 1.]
    BigInteger modulus = rep.getModulus();

    // prepare the products of revealed and hidden values in the
    // Representation
    Vector<Exponentiation> productRevealed = new Vector<Exponentiation>();
    Vector<Exponentiation> productHidden = new Vector<Exponentiation>();
    for (int i = 0; i < pred.getIdentifiers().size(); i++) {
      Identifier id = pred.getIdentifier(i);
      BigInteger m;
      Exponentiation e;
      if (id.isRevealed()) {
        m = (BigInteger) proof.getSValue(id.getName()).getValue();
        e = new Exponentiation(rep.getBase(i), m, modulus);
        productRevealed.add(e);
      } else {
        m = (BigInteger) proof.getSValue(id.getName()).getValue();
        e = new Exponentiation(rep.getBase(i), m, modulus);
        productHidden.add(e);

      }
    }

    BigInteger rPrime = rep.getRepresentation();
    if (productRevealed.size() > 0) {
      BigInteger denom = Utils.multiExpMul(productRevealed, modulus);
      denom = denom.modInverse(modulus);
      rPrime = rPrime.multiply(denom).mod(modulus);
    }
    productHidden.add(new Exponentiation(rPrime, negC, modulus));

    // [spec: VerifyRepresentation 2.]
    BigInteger rHat = Utils.multiExpMul(productHidden, modulus);

    // output cHat
    addRecomputedTValue(rHat);
  }

  /**
   * @param pred Verifiable encryption predicate.
   */
  private void verifyVerEnc(final VerEncPredicate pred) {
    // get the s-values
    BigInteger mHat = null;
    mHat = (BigInteger) proof.getSValue(pred.getIdentifier().getName()).getValue();

    assert (mHat != null);

    SValue sv = proof.getSValue(pred.getName());
    assert (sv != null);
    BigInteger rHat = (BigInteger) sv.getValue();

    // find the right Encryption object
    VerifiableEncryption ve = null;
    ve = proof.getVerEnc(pred.getName());
    if (ve == null) {
      ve = proof.getVerEnc(pred.getName());
    }
    assert (ve != null);

    VEPublicKey pk = pred.getPublicKey();
    BigInteger n2 = pk.getN2();
    BigInteger twoNegC = negC.multiply(Utils.TWO);
    BigInteger twoRHat = rHat.multiply(Utils.TWO);
    BigInteger twoMHat = mHat.multiply(Utils.TWO);

    Vector<Exponentiation> v = new Vector<Exponentiation>();
    v.add(new Exponentiation(ve.getU(), twoNegC, n2));
    v.add(new Exponentiation(pk.getG(), twoRHat, n2));
    BigInteger uHat = Utils.multiExpMul(v, n2);

    v = new Vector<Exponentiation>();
    v.add(new Exponentiation(ve.getE(), twoNegC, n2));
    v.add(new Exponentiation(pk.getY1(), twoRHat, n2));
    v.add(new Exponentiation(pk.getH(), twoMHat, n2));
    BigInteger eHat = Utils.multiExpMul(v, n2);

    v = new Vector<Exponentiation>();
    v.add(new Exponentiation(ve.getV(), twoNegC, n2));
    v.add(new Exponentiation(pk.getY2(), twoRHat, n2));
    v.add(new Exponentiation(pk.getY3(), twoRHat.multiply(ve.getHash()), n2));
    BigInteger vHat = Utils.multiExpMul(v, n2);

    log.log(Level.FINE, " uHat: " + Utils.logBigInt(uHat));
    log.log(Level.FINE, " eHat: " + Utils.logBigInt(eHat));
    log.log(Level.FINE, " vHat: " + Utils.logBigInt(vHat));

    addRecomputedTValue(uHat);
    addRecomputedTValue(eHat);
    addRecomputedTValue(vHat);
  }
  
  /**
   * Add a T-value to the list, and check if it corresponds to the T-value in the proof.
   * (If the proof does not contain T-values, then ignore)
   * @param tValue
   */
  private void addRecomputedTValue(BigInteger tValue) {
    tHatList.add(tValue);
    if (proof.getTValues() != null && proof.getTValues().size() != 0) {
      int index = tHatList.size() - 1;
      if (proof.getTValues().size() <= index) {
        throw new RuntimeException("Too many T-values were added in the proof.");
      } else if (! tHatList.get(index).equals(proof.getTValues().get(index))) {
        log.log(Level.SEVERE, "Incorrect T-value at position " + index + " expected " +
            proof.getTValues().get(index) + " got " + tHatList.get(index));
        throw new RuntimeException("Incorrect T-value at position " + index + " expected " +
            Utils.logBigInt(proof.getTValues().get(index)) + " got " + 
            Utils.logBigInt(tHatList.get(index)));
      }
    }
  }
  private void addRecomputedTValues(Vector<BigInteger> tValues) {
    for(BigInteger tValue: tValues) {
      addRecomputedTValue(tValue);
    }
  }
}
