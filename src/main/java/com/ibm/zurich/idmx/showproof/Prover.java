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

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.CredentialCommitment;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.dm.RepresentationOpening;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.showproof.accumulator.AccumulatorWitness;
import com.ibm.zurich.idmx.showproof.ip.InequalityProver;
import com.ibm.zurich.idmx.showproof.pe.PrimeEncodeProver;
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
import com.ibm.zurich.idmx.showproof.sval.SValuesProveCL;
import com.ibm.zurich.idmx.smartcard.IdemixProofCommitment;
import com.ibm.zurich.idmx.smartcard.IdemixProofResponse;
import com.ibm.zurich.idmx.smartcard.IdemixProofSpec;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;
import com.ibm.zurich.idmx.ve.VerifiableEncryption;
import com.ibm.zurich.idmx.ve.VerifiableEncryptionOpening;

/**
 * The Idemix prover abstraction.
 * 
 * @see Verifier
 */
public class Prover {

  /**
   * Helper class to capture the state of a proof between first and second round.
   */
  private class ProofState {

    /** Values recorded between the rounds. */
    private final HashMap<String, BigInteger> valueList;

    /**
     * Constructor.
     */
    ProofState() {
      valueList = new HashMap<String, BigInteger>();
    }

    /**
     * @param name Identifying name of the value.
     * @return Value registered under the given name.
     */
    public BigInteger get(final String name) {
      if (!valueList.containsKey(name)) {
        throw new RuntimeException("State does not contain the value: " + name);
      }
      return valueList.get(name);
    }

    /**
     * Adds a value to the list of values.
     * 
     * @param name Identifying name for the value.
     * @param value Value.
     */
    public final void put(final String name, final BigInteger value) {
      valueList.put(name, value);
    }
  }

  private class ProverState {
    public final TreeMap<String, BigInteger> commonList;
    public final Vector<InequalityProver> inequalityProvers;
    public final Vector<PrimeEncodeProver> primeEncodingProvers;
    public final HashMap<String, ProofState> states;
    public final HashMap<String, SValue> sValues;
    public final Vector<BigInteger> tList;
    public final TreeMap<String, VerifiableEncryption> verEncsSend;

    public ProverState() {
      verEncsSend = new TreeMap<String, VerifiableEncryption>();
      primeEncodingProvers = new Vector<PrimeEncodeProver>();
      inequalityProvers = new Vector<InequalityProver>();

      tList = new Vector<BigInteger>();
      commonList = new TreeMap<String, BigInteger>();
      sValues = new HashMap<String, SValue>();

      states = new HashMap<String, ProofState>();
    }
  }

  /** Logger. */
  private static Logger log = Logger.getLogger(Prover.class.getName());
  /** Convenience: Group parameters. */
  private final GroupParameters gp;
  private final ProverInput input;

  private final BigInteger nonce;

  /** Convenience: System parameters. */
  private final SystemParameters sp;
  private final ProofSpec spec;
  private final ProverState state;

  public Prover(ProverInput input, ProofSpec spec, BigInteger nonce) {
    this.input = input;
    this.state = new ProverState();
    this.spec = spec;
    this.gp = spec.getGroupParams();
    this.sp = gp.getSystemParams();
    this.nonce = nonce;
  }

  /**
   * Adds a value to the list of common values (used by sub-prover, e.g., the inequality prover).
   * 
   * @param name Name of the common value.
   * @param c Challenge.
   */
  public final void appendCommonValue(final String name, final BigInteger c) {
    state.commonList.put(name, c);
  }

  private void addIssuerPublicKeyCheck(IssuerPublicKey pubKey, String tempCredName) {
    String commonName = tempCredName + Constants.DELIMITER + "issuerPk";
    appendCommonValue(commonName, pubKey.generateHash());
  }
  private void addGroupParametersCheck(GroupParameters gp2, SystemParameters sp2) {
    appendCommonValue("gp", gp2.generateHash());
    appendCommonValue("sp", sp2.generateHash());
  }
  private void addProofSpecCheck(ProofSpec ps) {
    appendCommonValue("proofSpecHash", ps.generateHash());
  }
  
  public final Proof buildProof() {

    validateSpec();
    System.out.println("Starting to build proof (Idemix "+Constants.getVersion()+")");

    IdemixProofSpec scSpec = null;
    boolean usingSmartcard = false;
    if (input.smartcardManager != null) {
      scSpec = input.smartcardManager.idemixProofSpecFactory();
    }
    // Check smartcard
    for (Predicate predicate : spec.getPredicates()) {
      switch (predicate.getPredicateType()) {
        case CL: {
          CLPredicate pred = ((CLPredicate) predicate);
          Credential cred = input.credentials.get(pred.getTempCredName());
          if (cred.onSmartcard()) {
            if (scSpec == null) {
              throw new RuntimeException("Missing credential manager.");
            }
            if (!input.smartcardManager.credentialExists(cred.getSmartcardName(),
                cred.getNameOnSmartcard())) {
              throw new RuntimeException(
                  "Credential manager does not know about this credential/smartcard.");
            }
            scSpec.addCredentialProof(cred.getSmartcardName(), cred.getNameOnSmartcard());
            usingSmartcard = true;
          }
        }
          break;
        case CLCOM: {
          CLComPredicate pred = ((CLComPredicate) predicate);
          CredentialCommitment cred = input.credentialCommitments.get(pred.getTempCredName());
          if (cred.onSmartcard()) {
            if (scSpec == null) {
              throw new RuntimeException("Missing credential manager.");
            }
            if (!input.smartcardManager.credentialExists(cred.getSmartcardName(),
                cred.getNameOnSmartcard())) {
              throw new RuntimeException(
                  "Credential manager does not know about this credcom/smartcard.");
            }
            scSpec.addCredentialProof(cred.getSmartcardName(), cred.getNameOnSmartcard());
            usingSmartcard = true;
          }
        }
          break;
        case PSEUDONYM: {
          PseudonymPredicate pred = ((PseudonymPredicate) predicate);
          URI location = input.pseudonyms.get(pred.getName()).getSmartcardUri();
          if (location == null) {
            throw new RuntimeException("Missing location for domainNym " + pred.getName());
          }
          if (!input.smartcardManager.smartcardLoaded(location)) {
            throw new RuntimeException("Credential manager does not know about this smartcard");
          }
          scSpec.addPublicKeyProof(location);
          usingSmartcard = true;
        }
          break;
        case DOMAINNYM: {
          DomainNymPredicate pred = ((DomainNymPredicate) predicate);
          URI scope = pred.getDomain();
          URI location = input.domainPseudonyms.get(pred.getTempName()).getSmartcardUri();
          if (location == null) {
            throw new RuntimeException("Missing location for domainNym " + scope);
          }
          if (!input.smartcardManager.smartcardLoaded(location)) {
            throw new RuntimeException("Credential manager does not know about this smartcard");
          }
          scSpec.addScopeExclusivePseudonymProof(location, scope);
          usingSmartcard = true;
        }
      }
    }
    IdemixProofCommitment scComm = null;
    if (usingSmartcard) {
      scComm = input.smartcardManager.prepareProof(scSpec);

      if (sp.getL_H() != input.smartcardManager.getChallengeSizeBytes() * 8) {
        throw new RuntimeException("Incompatible challenge length Idemix/Smartcard");
      }
      if (sp.getL_Phi() != input.smartcardManager.getStatisticalHidingSizeBytes() * 8) {
        throw new RuntimeException("Incompatible statistical hiding parameter Idemix/Smartcard");
      }
    }

    // we have two rounds: in the first round we compute the t-values
    // (witnesses) then the Fiat-Shamir challenge. In the second round we
    // compute the s-values (responses) using that challenge.

    // [spec: buildProof 0.1]
    Iterator<Identifier> identifiers = spec.getIdentifiers().iterator();
    while (identifiers.hasNext()) {
      Identifier identifier = identifiers.next();
      if (!identifier.isRevealed()) {
        int bitlength = sp.getL_m() + sp.getL_Phi() + sp.getL_H();
        identifier.setRandom(Utils.computeRandomNumber(bitlength));
      }
    }

    // [spec: buildProof 1.] iterate over all predicates, call sub-provers
    Iterator<Predicate> predicates = spec.getPredicates().iterator();
    while (predicates.hasNext()) {
      Predicate predicate = predicates.next();
      switch (predicate.getPredicateType()) {
        case CL: {
          CLPredicate pred = ((CLPredicate) predicate);
          Credential cred = input.credentials.get(pred.getTempCredName());
          proveCL(cred, pred, scComm);
          if (!cred.verifySignature(input.smartcardManager)) {
            throw new RuntimeException("The signature on the credential does not verify. " + cred.toStringPretty());
          }
        }
          break;
        case CLCOM: {
          CLComPredicate pred = ((CLComPredicate) predicate);
          CredentialCommitment cred = input.credentialCommitments.get(pred.getTempCredName());
          proveCLCom(cred, pred, scComm);
        }
          break;
        case ENUMERATION:
          provePrimeEncode((PrimeEncodePredicate) predicate);
          break;
        case INEQUALITY:
          proveInequality((InequalityPredicate) predicate);
          break;
        case NOTEQUAL:
          proveNotEqual((NotEqualPredicate) predicate);
          break;
        case COMMITMENT:
          CommitmentPredicate predComm = (CommitmentPredicate) predicate;
          CommitmentOpening commOpen = input.commitmentOpenings.get(predComm.getName());
          proveCommitment(commOpen, predComm);
          break;
        case REPRESENTATION:
          proveRepresentation((RepresentationPredicate) predicate);
          break;
        case PSEUDONYM:
          provePseudonym((PseudonymPredicate) predicate, scComm);
          break;
        case DOMAINNYM:
          proveDomainNym((DomainNymPredicate) predicate, scComm);
          break;
        case VERENC:
          proveVerEnc((VerEncPredicate) predicate);
          break;
        case MESSAGE:
          // nothing to be done;
          break;
        case ACCUMULATOR:
          proveAccumulator((AccumulatorPredicate) predicate);
          break;
        default:
          throw new RuntimeException("Unimplemented predicate.");
      }
    }
    
    addGroupParametersCheck(gp, sp);
    addProofSpecCheck(spec);

    // [spec: buildProof 2.]
    BigInteger challenge = computeChallenge(nonce);
    IdemixProofResponse scResp = null;
    byte[] smartcardNonce = null;
    if (usingSmartcard) {
      log.log(Level.INFO, "on smartcard: hashing twice...");
      byte[] preimage = challenge.toByteArray();
      smartcardNonce = input.smartcardManager.prepareNonce(scComm);
      challenge = input.smartcardManager.computeChallenge(preimage, smartcardNonce);
      scResp = input.smartcardManager.finalizeZkProof(scComm, preimage, smartcardNonce);
    }


    // iterate over all the identifiers
    identifiers = spec.getIdentifiers().iterator();
    while (identifiers.hasNext()) {
      Identifier identifier = identifiers.next();
      BigInteger s;
      if (identifier.isRevealed()) {
        s = identifier.getValue();
      } else {
        s = Utils.computeResponse(identifier.getRandom(), challenge, identifier.getValue());
      }
      // note that identifier names must be unique
      state.sValues.put(identifier.getName(), new SValue(s));
      System.out.println("S-VALUE:" + identifier.getName() + "..." + identifier.getValue());
    }
    System.out.println(spec.toStringPretty());

    // [spec: buildProof 3.] call sub-provers again, this time with the
    // challenge
    predicates = spec.getPredicates().iterator();
    while (predicates.hasNext()) {
      Predicate predicate = predicates.next();
      switch (predicate.getPredicateType()) {
        case CL: {
          CLPredicate predCl = (CLPredicate) predicate;
          Credential cred = input.credentials.get(predCl.getTempCredName());
          proveCL(predCl, cred, challenge, scResp);
        }
          break;
        case CLCOM: {
          CLComPredicate predCl = (CLComPredicate) predicate;
          CredentialCommitment cred = input.credentialCommitments.get(predCl.getTempCredName());
          proveCLCom(predCl, cred, challenge, scResp);
        }
          break;
        case COMMITMENT:
          CommitmentPredicate predComm = (CommitmentPredicate) predicate;
          CommitmentOpening commOpen = input.commitmentOpenings.get(predComm.getName());
          proveCommitment(commOpen, predComm, challenge);
          break;
        case PSEUDONYM:
          provePseudonym((PseudonymPredicate) predicate, challenge, scResp);
          break;
        case VERENC:
          proveVerEnc((VerEncPredicate) predicate, challenge);
          break;
        case ENUMERATION:
          // - enumerated values are handled further down.
          break;
        case INEQUALITY:
          // - inequalities are handled further down.
          break;
        case NOTEQUAL:
          proveNotEqual((NotEqualPredicate) predicate, challenge);
          break;
        case REPRESENTATION:
          // - the s-values for the representation are all computed
          // globally.
          break;
        case DOMAINNYM:
          proveDomainNym((DomainNymPredicate) predicate, challenge, scResp);
          break;
        case MESSAGE:
          // - messages are included in the Fiat-Shamir heuristic.
          break;
        case ACCUMULATOR:
          proveAccumulator((AccumulatorPredicate) predicate, challenge);
          break;
        default:
          throw new RuntimeException("Unimplemented predicate.");
      }
    }

    // Inequality Prover and Enumeration Prover keep state between the
    // computation of the t-values and the s-values. Thus, there is a
    // seperate object for each predicate storing the corresponding values.
    // Now we iterate through all those prover objects rather than
    // considering them in the previous switch statement.

    // [spec: ProvePrimeEncoding 4.] add s-values for prime encodings
    Iterator<PrimeEncodeProver> peps = state.primeEncodingProvers.iterator();
    while (peps.hasNext()) {
      state.sValues.putAll(peps.next().computeSValues(challenge));
    }
    // [spec: ProveInequality 3.] add s-values for inequality provers
    Iterator<InequalityProver> iterator = state.inequalityProvers.iterator();
    while (iterator.hasNext()) {
      state.sValues.putAll(iterator.next().computeSValues(challenge));
    }
    
    // output proof
    return new Proof(challenge, state.sValues, state.tList, state.commonList, state.verEncsSend, smartcardNonce);

  }

  private void proveAccumulator(AccumulatorPredicate predicate, BigInteger challenge) {
    if (predicate.getValue().isUnrevealed()) {
      BigInteger e = predicate.getValue().getValue();
      
      ProofState state = this.state.states.get(predicate.getTempName());
      BigInteger r1 = state.get("r1");
      BigInteger r2 = state.get("r2");
      BigInteger r3 = state.get("r3");
      BigInteger r3e = r3.multiply(e).negate();
      BigInteger r2e = r2.multiply(e).negate();
      
      BigInteger rand_r1 = state.get("r_r1");
      BigInteger rand_r2 = state.get("r_r2");
      BigInteger rand_r3 = state.get("r_r3");
      BigInteger rand_r2e = state.get("r_r2e");
      BigInteger rand_r3e = state.get("r_r3e");
      
      BigInteger s_r1 = rand_r1.add(challenge.multiply(r1));
      BigInteger s_r2 = rand_r2.add(challenge.multiply(r2));
      BigInteger s_r3 = rand_r3.add(challenge.multiply(r3));
      BigInteger s_r2e = rand_r2e.add(challenge.multiply(r2e));
      BigInteger s_r3e = rand_r3e.add(challenge.multiply(r3e));

      String prefix = predicate.getTempName() + Constants.DELIMITER;
      this.state.sValues.put(prefix + "s_r1", new SValue(s_r1));
      this.state.sValues.put(prefix + "s_r2", new SValue(s_r2));
      this.state.sValues.put(prefix + "s_r3", new SValue(s_r3));
      this.state.sValues.put(prefix + "s_r2e", new SValue(s_r2e));
      this.state.sValues.put(prefix + "s_r3e", new SValue(s_r3e));
    }
    // else: do nothing
  }

  private void proveAccumulator(AccumulatorPredicate predicate) {
    AccumulatorWitness wit = input.accumulatorWitnesses.get(predicate.getTempName());
    
    if (predicate.getValue().isRevealed()) {
      // If the value is revealed, it is OK to reveal the witness, since it can anyway be
      // re-computed from the history.
      String commonName = predicate.getTempName() + Constants.DELIMITER + "W";
      state.commonList.put(commonName, wit.getWitness());
    } else {
      BigInteger e = predicate.getValue().getValue();
      if (!e.equals(wit.getValue())) {
        System.err.println("Value in predicate: " + e);
        System.err.println("Value in witness object: " + wit.getValue());
        throw new RuntimeException("Value mismtach in predicate and witness.");
      }
      BigInteger u = wit.getWitness();
      // BigInteger v = wit.getState().getAccumulatorValue();
      BigInteger n = wit.getState().getPublicKey().getN();
      BigInteger g = wit.getState().getPublicKey().getBaseG();
      BigInteger h = wit.getState().getPublicKey().getBaseH();
      
      int com_bitlength = sp.getL_n() - 2;
      BigInteger r1 = Utils.computeRandomNumberSymmetric(com_bitlength);
      BigInteger r2 = Utils.computeRandomNumberSymmetric(com_bitlength);
      BigInteger r3 = Utils.computeRandomNumberSymmetric(com_bitlength);
      // BigInteger r3e = r3.multiply(e).negate();
      // BigInteger r2e = r2.multiply(e).negate();
      
      // Compute commitments
      // Ce = g^e * h^r1 (mod n)
      BigInteger Ce = g.modPow(e, n).multiply(h.modPow(r1, n)).mod(n);
      // Cu = u * h^r2
      BigInteger Cu = u.multiply(h.modPow(r2, n)).mod(n);
      // Cr = g^r2 * h^r3
      BigInteger Cr = g.modPow(r2, n).multiply(h.modPow(r3, n)).mod(n);
      
      String prefix = predicate.getTempName() + Constants.DELIMITER;
      
      state.commonList.put(prefix + "Ce", Ce);
      state.commonList.put(prefix + "Cu", Cu);
      state.commonList.put(prefix + "Cr", Cr);
      
      int bitlength_short = sp.getL_n() + sp.getL_Phi() + sp.getL_H() - 2;
      int bitlength_long = (sp.getL_n() - 2)*2 + sp.getL_Phi() + sp.getL_H();
      BigInteger rand_e = predicate.getValue().getRandom();
      BigInteger rand_r1 = Utils.computeRandomNumberSymmetric(bitlength_short);
      BigInteger rand_r2 = Utils.computeRandomNumberSymmetric(bitlength_short);
      BigInteger rand_r3 = Utils.computeRandomNumberSymmetric(bitlength_short);
      BigInteger rand_r2e = Utils.computeRandomNumberSymmetric(bitlength_long);
      BigInteger rand_r3e = Utils.computeRandomNumberSymmetric(bitlength_long);
      
      // Proof equations
      // Ce = g^e * h^r1
      BigInteger t_Ce = g.modPow(rand_e, n).multiply(h.modPow(rand_r1, n)).mod(n);
      // Cr = g^r2 * h^r3
      BigInteger t_Cr = g.modPow(rand_r2, n).multiply(h.modPow(rand_r3, n)).mod(n);
      // v = Cu^e * h^r2e
      BigInteger t_v = Cu.modPow(rand_e, n).multiply(h.modPow(rand_r2e, n)).mod(n);
      // 1 = Cr^e * g^r2e * h^r3e
      BigInteger t_1 = Cr.modPow(rand_e, n).multiply(g.modPow(rand_r2e, n)).multiply(h.modPow(rand_r3e, n)).mod(n);
      
      ProofState state = new ProofState();
      state.put("r_e",   rand_e);
      state.put("r_r1",  rand_r1);
      state.put("r_r2",  rand_r2);
      state.put("r_r3",  rand_r3);
      state.put("r_r2e", rand_r2e);
      state.put("r_r3e", rand_r3e);
      state.put("r1",  r1);
      state.put("r2",  r2);
      state.put("r3",  r3);
      this.state.states.put(predicate.getTempName(), state);
      
      this.state.tList.add(t_Ce);
      this.state.tList.add(t_Cr);
      this.state.tList.add(t_v);
      this.state.tList.add(t_1);
    }
  }

  /**
   * Wrapper to call the challenge computation. Note that the challenge depends on the commonList.
   * 
   * @return challenge value.
   */
  private BigInteger computeChallenge(final BigInteger nonce) {

    // TODO (pbi) define how the common list and messages should be ordered
    // (cf. Verifier.java)
    Vector<BigInteger> list = new Vector<BigInteger>();
    list.addAll(this.state.commonList.values());
    list.addAll(this.state.tList);

    if (input.messages == null) {
      input.messages = new TreeMap<String, MessageToSign>();
    }
    BigInteger challenge =
        Utils.computeChallenge(sp, spec.getContext(), list, nonce, input.messages.values());

    return challenge;
  }

  /**
   * @return System parameters used for this proof.
   */
  public final SystemParameters getSysParams() {
    return sp;
  }


  public BigInteger getVPrimeForCLCom(String tempName) {
    return state.states.get(tempName).get("r");
  }

  /**
   * Second round: Computes the s-values. Note that the s-values for all identifiers are computed in
   * {@link Prover#computeSValues(CLPredicate, Credential)}.
   * 
   * @param pred CL predicate.
   * @param challenge Challenge.
   * @param scResp
   */
  private void proveCL(final CLPredicate pred, final Credential cred, final BigInteger challenge,
      IdemixProofResponse scResp) {

    ProofState state = this.state.states.get(pred.getTempCredName());
    assert (state != null);
    assert (challenge != null);

    // [spec: ProveCL 4.1]
    final BigInteger eHat =
        Utils.computeResponse(state.get("eTilde"), challenge, state.get("ePrime"));
    // [spec: ProveCL 4.2]
    BigInteger vHatPrime =
        Utils.computeResponse(state.get("vTildePrime"), challenge, state.get("vPrime"));
    // [spec: ProveCL 4.3]

    // add s-value for master secret (again we deviate from the spec fo make
    // the master secret seperable)
    if (cred.onSmartcard()) {
      BigInteger zx = scResp.responseForDeviceSecretKey(cred.getSmartcardName());
      String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getTempSecretName();
      this.state.sValues.put(scName, new SValue(zx));

      BigInteger zv =
          scResp
              .responseForCredentialRandomizer(cred.getSmartcardName(), cred.getNameOnSmartcard());
      vHatPrime = vHatPrime.add(zv);
    }

    final SValue sVals = new SValue(new SValuesProveCL(eHat, vHatPrime));
    this.state.sValues.put(pred.getTempCredName(), sVals);
  }

  /**
   * First round: Computes t-value and commons-value.
   * 
   * @param cred Credential that this predicate corresponds to.
   * @param pred CL predicate.
   * @param scComm
   */
  private void proveCL(final Credential cred, final CLPredicate pred, IdemixProofCommitment scComm) {
    if (!cred.getCredStructId().equals(pred.getCredStructLocation())) {
      throw new RuntimeException("Credential structures of given "
          + "credential and proof specification do not match " + "for " + pred.getTempCredName());
    }
    
    final IssuerPublicKey ipk = cred.getPublicKey();
    int l_Phi = sp.getL_Phi();
    int l_H = sp.getL_H();

    // [spec: ProveCL 1.] randomize signature
    final BigInteger r_A = Utils.computeRandomNumber(sp.getL_n() + l_Phi);
    final BigInteger capS = ipk.getCapS();
    final BigInteger n = ipk.getN();

    final BigInteger capAPrime = Utils.expMul(cred.getCapA(), capS, r_A, n);
    final BigInteger vPrime = cred.getV().subtract(cred.getE().multiply(r_A));

    // assertion to make sure that shiftLeft works correctly.
    assert (sp.getL_e() - 1) > 0;

    // Arithmetic shifting by n bits is an efficient ways of performing
    // multiplication (or division) of signed integers by powers of two
    // to the n. Left shift is multiplication. Right shift is division.
    final BigInteger ePrime = cred.getE().subtract(BigInteger.ONE.shiftLeft(sp.getL_e() - 1));

    // [spec: ProveCL 2.1] compute t-values
    final BigInteger eTilde = Utils.computeRandomNumberSymmetric(sp.getL_ePrime() + l_Phi + l_H);
    final BigInteger vTildePrime = Utils.computeRandomNumberSymmetric(sp.getL_v() + l_Phi + l_H);

    // save the state to compute the s-values later
    ProofState state = new ProofState();
    state.put("eTilde", eTilde);
    state.put("ePrime", ePrime);
    state.put("vPrime", vPrime);
    state.put("vTildePrime", vTildePrime);
    this.state.states.put(pred.getTempCredName(), state);

    // [spec: ProveCL 2.2] compute capZTilde.
    final Vector<Exponentiation> expos = new Vector<Exponentiation>();
    expos.add(new Exponentiation(capAPrime, eTilde, n));
    // log.log(Level.FINE, pred.getTempCredName() + "..............");
    // log.log(Level.FINE, "ePrime:      " + Utils.logBigInt(ePrime));
    // log.log(Level.FINE, "vPrime:      " + Utils.logBigInt(vPrime));
    // log.log(Level.FINE, "capAPrime:   " + Utils.logBigInt(capAPrime));
    // log.log(Level.FINE, "eTilde:      " + Utils.logBigInt(eTilde));
    // log.log(Level.FINE, "capS:        " +
    // Utils.logBigInt(pubKey.getS()));
    // log.log(Level.FINE, "vTildePrime: " + Utils.logBigInt(vTildePrime));

    for (Attribute attribute : cred.getAttributes()) {
      String attName = attribute.getName();
      Identifier identifier = pred.getIdentifier(attName);
      identifier.setAttr(attribute);
      if (identifier.isRevealed()) {
        continue;
      }

      // recovering the randomness computed in step 0.1 of buildProof
      BigInteger mTilde = identifier.getRandom();
      expos.add(new Exponentiation(ipk.getCapR()[attribute.getKeyIndex()], mTilde, n));
      log.log(Level.FINE, "mTilde_" + attribute.getKeyIndex() + ":    " + Utils.logBigInt(mTilde));

    }

    expos.add(new Exponentiation(ipk.getCapS(), vTildePrime, n));
    BigInteger capZTilde = Utils.multiExpMul(expos, n);
    // add the master secret (we deviate from the spec as we want to have
    // the master secret easily separable)
    if (cred.onSmartcard()) {

      if (!n.equals(input.smartcardManager.getNOfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched N (Idemix / Smartcard)");
      }
      if (!capS.equals(input.smartcardManager.getSOfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched S (Idemix / Smartcard)");
      }
      BigInteger R0 = ipk.getCapR()[IssuanceSpec.SMARTCARD_SECRET_INDEX];
      if (!R0.equals(input.smartcardManager.getR0OfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched R0 (Idemix / Smartcard)");
      }

      BigInteger com =
          scComm.commitmentForCredential(cred.getSmartcardName(), cred.getNameOnSmartcard());
      capZTilde = capZTilde.multiply(com).mod(n);
    }

    // [spec: ProveCL 3.] output t-value capZTilde, common value capAPrime.
    this.state.tList.add(capZTilde);
    // note that we wrap the common value A' into a tagged common value.
    this.state.commonList.put(pred.getTempCredName(), capAPrime);
    
    addIssuerPublicKeyCheck(ipk, pred.getTempCredName());
  }

  private void proveCLCom(CLComPredicate pred, CredentialCommitment cred, BigInteger challenge,
      IdemixProofResponse scResp) {

    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# prover start 2");
    // get the state from the first round
    ProofState state = this.state.states.get(pred.getTempCredName());
    assert (state != null);
    assert (challenge != null);

    BigInteger rHat = Utils.computeResponse(state.get("rTilde"), challenge, state.get("r"));

    if (cred.onSmartcard()) {
      BigInteger zx = scResp.responseForDeviceSecretKey(cred.getSmartcardName());
      String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getTempSecretName();
      this.state.sValues.put(scName, new SValue(zx));

      BigInteger zv =
          scResp
              .responseForCredentialRandomizer(cred.getSmartcardName(), cred.getNameOnSmartcard());
      rHat = rHat.add(zv);
    }

    SValue sVal = new SValue(rHat);
    this.state.sValues.put(pred.getTempCredName(), sVal);

    log.log(Level.FINE,
        "s-value rHat for pred name: " + pred.getTempCredName() + " : " + Utils.logBigInt(rHat));
    
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# S-value: " + rHat);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# prover end 2");
  }

  private void proveCLCom(CredentialCommitment cred, CLComPredicate pred,
      IdemixProofCommitment scComm) {
    
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# prover start 1");

    final IssuerPublicKey ipk = cred.getPublicKey();
    final BigInteger n = ipk.getN();
    final BigInteger capS = ipk.getCapS();

    // [spec: ProveCommitment 1.1]
    int bitlength = sp.getL_n() + sp.getL_Phi() + sp.getL_H() + 1;
    final BigInteger r = Utils.computeRandomNumberSymmetric(sp.getL_v());
    BigInteger rTilde = Utils.computeRandomNumberSymmetric(bitlength);

    // [spec: ProveCommitment 1.2] add product of hidden attributes
    // R_i^(a_i) to the the product
    Vector<Exponentiation> expos = new Vector<Exponentiation>();
    final Vector<Exponentiation> comExpos = new Vector<Exponentiation>();
    for (Attribute attribute : cred.getAttributes()) {
      String attName = attribute.getName();
      Identifier identifier = pred.getIdentifier(attName);
      identifier.setAttr(attribute);

      comExpos.add(new Exponentiation(ipk.getCapR()[attribute.getKeyIndex()], attribute.getValue(),
          n));

      if (identifier.isRevealed()) {
        continue;
      }

      // recovering the randomness computed in step 0.1 of buildProof
      BigInteger mTilde = identifier.getRandom();
      expos.add(new Exponentiation(ipk.getCapR()[attribute.getKeyIndex()], mTilde, n));
      log.log(Level.FINE, "mTilde_" + attribute.getKeyIndex() + ":    " + Utils.logBigInt(mTilde));
    }

    expos.add(new Exponentiation(capS, rTilde, n));
    comExpos.add(new Exponentiation(capS, r, n));
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# Starting capCTilde");
    BigInteger capCTilde = Utils.multiExpMul(expos, n);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# Starting common");
    BigInteger common = Utils.multiExpMul(comExpos, n);
    
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# common1: " + common);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# capCTilde1: " + capCTilde);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# n: " + n);

    if (cred.onSmartcard()) {
      if (!n.equals(input.smartcardManager.getNOfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched N (Idemix / Smartcard)");
      }
      if (!capS.equals(input.smartcardManager.getSOfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched S (Idemix / Smartcard)");
      }
      BigInteger R0 = ipk.getCapR()[IssuanceSpec.SMARTCARD_SECRET_INDEX];
      if (!R0.equals(input.smartcardManager.getR0OfCredential(cred.getSmartcardName(),
          cred.getNameOnSmartcard()))) {
        throw new RuntimeException("Mismatched R0 (Idemix / Smartcard)");
      }
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# R0: " + R0);

      BigInteger com =
          scComm.commitmentForCredential(cred.getSmartcardName(), cred.getNameOnSmartcard());
      capCTilde = capCTilde.multiply(com).mod(n);
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# com: " + com);
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# CapCTilde2: " + capCTilde);
      BigInteger frag =
          input.smartcardManager.computeCredentialFragment(cred.getSmartcardName(),
              cred.getNameOnSmartcard());
      common = common.multiply(frag).mod(n);
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# fragment: " + frag);
      Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# common2: " + common);
    }

    // save the state for the 2nd round of building proof.
    ProofState state = new ProofState();
    state.put("r", r);
    state.put("rTilde", rTilde);
    this.state.states.put(pred.getTempCredName(), state);

    this.state.tList.add(capCTilde);
    this.state.commonList.put(pred.getTempCredName(), common);
    
    addIssuerPublicKeyCheck(ipk, pred.getTempCredName());
    
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# r: " + r);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# rTilde: " + rTilde);
    Constants.printCalculationLog("#CL-COM# " + pred.getTempCredName() + "# prover end 1");
  }

  /**
   * First round: Computes t-value for a commitment.
   * 
   * @param commOpen Commitment opening.
   * @param pred Commitment predicate.
   */
  private void proveCommitment(final CommitmentOpening commOpen, final CommitmentPredicate pred) {

    // [spec: ProveCommitment 1.1]
    int bitlength = sp.getL_n() + sp.getL_Phi() + sp.getL_H() + 1;
    BigInteger rTilde = Utils.computeRandomNumberSymmetric(bitlength);

    // [spec: ProveCommitment 1.2] add product of hidden attributes
    // R_i^(a_i) to the the product
    Vector<Exponentiation> expos = new Vector<Exponentiation>();
    for (int i = 0; i < pred.getIdentifiers().size(); i++) {
      Identifier id = pred.getIdentifiers().get(i);
      if (!id.isRevealed()) {
        // capR_i := commOpen.getMsgBase(i)
        Exponentiation e =
            new Exponentiation(commOpen.getMsgBase(i), id.getRandom(), commOpen.getN());
        expos.add(e);
      }
    }

    Exponentiation e = new Exponentiation(commOpen.getCapS(), rTilde, commOpen.getN());
    expos.add(e);
    BigInteger capCTilde = Utils.multiExpMul(expos, commOpen.getN());

    // save the state for the 2nd round of building proof.
    ProofState state = new ProofState();
    state.put("rTilde", rTilde);
    this.state.states.put(pred.getName(), state);

    this.state.tList.add(capCTilde);
  }

  /**
   * Second round: Computes the s-values.
   * 
   * @param commOpen Commitment opening.
   * @param pred Commitment predicate.
   * @param challenge Challenge.
   */
  private void proveCommitment(final CommitmentOpening commOpen, final CommitmentPredicate pred,
      final BigInteger challenge) {
    // get the state from the first round
    ProofState state = this.state.states.get(pred.getName());
    assert (state != null);

    final BigInteger rHat =
        Utils.computeResponse(state.get("rTilde"), challenge, commOpen.getRandom());
    SValue sVal = new SValue(rHat);
    this.state.sValues.put(pred.getName(), sVal);

    log.log(Level.FINE,
        "s-value rHat for pred name: " + pred.getName() + " : " + Utils.logBigInt(rHat));
  }

  /*
   * Second round: compute s-value for a domain pseudonym
   */
  private void proveDomainNym(final DomainNymPredicate predicate, BigInteger challenge,
      IdemixProofResponse scResp) {
    String name = predicate.getTempName();
    URI location = input.domainPseudonyms.get(name).getSmartcardUri();
    BigInteger zx = scResp.responseForDeviceSecretKey(location);
    String scName = IssuanceSpec.SMARTCARD_SECRET + predicate.getTempSecretName();
    this.state.sValues.put(scName, new SValue(zx));
    
    BigInteger dn = this.state.states.get(predicate.getTempName()).get("dn");
    BigInteger dnt = this.state.states.get(predicate.getTempName()).get("dnt");
    BigInteger base = this.state.states.get(predicate.getTempName()).get("base");
    
    Vector<Exponentiation> product = new Vector<Exponentiation>();
    product.add(new Exponentiation(dn, challenge.negate(), gp.getCapGamma()));
    product.add(new Exponentiation(base, zx, gp.getCapGamma()));

    BigInteger dNymHat = Utils.multiExpMul(product, gp.getCapGamma());
    if(!dnt.equals(dNymHat)) {
      throw new RuntimeException("Problem computing domain pseudonym: smartcard returned incorrect zero-knowledge proof.");
    }
  }

  /**
   * First round: Computes t-value for a domain pseudonym.
   */
  private void proveDomainNym(final DomainNymPredicate pred, IdemixProofCommitment scComm) {
    URI scope = pred.getDomain();
    String name = pred.getTempName();
    URI location = input.domainPseudonyms.get(name).getSmartcardUri();
    BigInteger base = input.smartcardManager.computeBaseForScopeExclusivePseudonym(location, scope);
    BigInteger domNym = input.smartcardManager.computeScopeExclusivePseudonym(location, scope);
    BigInteger dNymTilde = scComm.commitmentForScopeExclusivePseudonym(location, scope);
    this.state.commonList.put(name, domNym);
    this.state.tList.add(dNymTilde);

    if (!scope.equals(input.domainPseudonyms.get(name).getScope())) {
      throw new RuntimeException("Stored domain pseudonym has wrong scope.");
    }
    if (!input.smartcardManager.getPseudonymModulusOfCard(location).equals(gp.getCapGamma())) {
      throw new RuntimeException("Incompatible modulus of pseudonyms Idemix/smartcard");
    }
    if (!input.smartcardManager.getPseudonymSubgroupOrderOfCard(location).equals(gp.getRho())) {
      throw new RuntimeException("Incompatible subgroup order of pseudonyms Idemix/smartcard");
    }
    
    // save the state for the 2nd round of building proof.
    ProofState state = new ProofState();
    state.put("base", base);
    state.put("dn", domNym);
    state.put("dnt", dNymTilde);
    this.state.states.put(pred.getTempName(), state);
    
    appendCommonValue(pred.getTempName() + Constants.DELIMITER + "base", base);
  }

  /**
   * First round: Computes t-value for inequality proofs.
   * 
   * @param pred Inequality predicate.
   */
  private void proveInequality(final InequalityPredicate pred) {
    final InequalityProver ip = new InequalityProver(this, pred);
    // [spec: ProveInequality 2.1]
    this.state.tList.addAll(ip.computeTHatValues());
    this.state.inequalityProvers.add(ip);
    
    addIssuerPublicKeyCheck(pred.getKey(), pred.getName());
  }

  private void proveNotEqual(NotEqualPredicate predicate) {

    final BigInteger rho = gp.getRho();
    final BigInteger gamma = gp.getCapGamma();
    final BigInteger g = gp.getG();
    final BigInteger h = gp.getH();
    final BigInteger lhs = predicate.getLhs().getValue();
    final BigInteger rhs = predicate.getRhs();

    if (predicate.getLhs().isRevealed()) {
      // Sanity check
      if (lhs.equals(rhs)) {
        throw new RuntimeException("Invalid not-equal proof (revealed): LHS == RHS");
      }
      System.out.println("Trivial inequality predicate: " + predicate.getName() + "  " + lhs
          + " != " + rhs);
      // nothing else to do
      return;
    } else {
      System.out.println("Proving: " + lhs + "!=" + rhs);
    }

    // Choose random r in 0...rho-1
    BigInteger r = Utils.computeRandomNumber(rho, sp);

    // compute C = g^lhs * h^r
    BigInteger C = g.modPow(lhs, gamma).multiply(h.modPow(r, gamma)).mod(gamma);

    // add C to common values
    String commonName = predicate.getName() + Constants.DELIMITER + "C";
    state.commonList.put(commonName, C);

    // compute Chat = C * g^{-rhs}
    BigInteger Chat = C.multiply(g.modPow(rhs.negate(), gamma)).mod(gamma);

    // compute xhat = lhs-rhs
    BigInteger xhat = lhs.subtract(rhs);

    // compute a = xhat^-1
    BigInteger a = xhat.modInverse(rho);

    // compute b = -r*a
    BigInteger b = a.multiply(r).negate().mod(rho);

    // add a, b, r to witnesses (lhs is managed globally)
    BigInteger rand_a = Utils.computeRandomNumber(rho, sp);
    BigInteger rand_b = Utils.computeRandomNumber(rho, sp);
    BigInteger rand_r = Utils.computeRandomNumber(rho, sp);
    ProofState state = new ProofState();
    state.put("r_a", rand_a);
    state.put("r_b", rand_b);
    state.put("r_r", rand_r);
    state.put("x_a", a);
    state.put("x_b", b);
    state.put("x_r", r);
    this.state.states.put(predicate.getName(), state);

    // Prove C = g^lhs * h^r
    BigInteger rand_lhs = predicate.getLhs().getRandom();
    BigInteger t_C = g.modPow(rand_lhs, gamma).multiply(h.modPow(rand_r, gamma)).mod(gamma);

    // Prove that g = Chat^a * h^b
    BigInteger t_g = Chat.modPow(rand_a, gamma).multiply(h.modPow(rand_b, gamma)).mod(gamma);

    this.state.tList.add(t_C);
    this.state.tList.add(t_g);
  }

  private void proveNotEqual(NotEqualPredicate predicate, BigInteger challenge) {
    if (predicate.getLhs().isRevealed()) {
      return;
    }

    final BigInteger rho = gp.getRho();
    ProofState state = this.state.states.get(predicate.getName());
    // compute s-values for a, b and r
    BigInteger s_a = state.get("r_a").add(challenge.multiply(state.get("x_a"))).mod(rho);
    BigInteger s_b = state.get("r_b").add(challenge.multiply(state.get("x_b"))).mod(rho);
    BigInteger s_r = state.get("r_r").add(challenge.multiply(state.get("x_r"))).mod(rho);

    this.state.sValues.put(predicate.getName() + Constants.DELIMITER + "s_a", new SValue(s_a));
    this.state.sValues.put(predicate.getName() + Constants.DELIMITER + "s_b", new SValue(s_b));
    this.state.sValues.put(predicate.getName() + Constants.DELIMITER + "s_r", new SValue(s_r));
  }

  /**
   * First round: Computes t-value for enumerations.
   * 
   * @param pred Enumeration predicate.
   */
  private void provePrimeEncode(final PrimeEncodePredicate pred) {
    // use the issuer public key of the first certificate that certifies E
    IssuerPublicKey ipk = Utils.getPrimeEncodingConstants(pred);

    PrimeEncodeProver pep = new PrimeEncodeProver(pred, this, ipk);
    this.state.primeEncodingProvers.add(pep);
    this.state.tList.addAll(pep.computeTValues());
  }

  /**
   * Second round: Computes the s-values.
   * 
   * @param pred Pseudonym predicate.
   * @param challenge Challenge.
   * @param scResp
   */
  private void provePseudonym(final PseudonymPredicate pred, final BigInteger challenge,
      IdemixProofResponse scResp) {
    String name = pred.getName();
    URI location = input.pseudonyms.get(name).getSmartcardUri();
    BigInteger zx = scResp.responseForDeviceSecretKey(location);
    String scName = IssuanceSpec.SMARTCARD_SECRET + pred.getSecretName();
    this.state.sValues.put(scName, new SValue(zx));

    BigInteger r_rand = this.state.states.get(name).get("r_rand");
    BigInteger randomizer = input.pseudonyms.get(name).getRandomizer();
    BigInteger z_rand = r_rand.add(challenge.multiply(randomizer));

    this.state.sValues.put(name, new SValue(z_rand));
  }

  /**
   * First round: Computes t-value for a regular pseudonym.
   * 
   * @param pred Pseudonym predicate.
   * @param scComm
   */
  private void provePseudonym(final PseudonymPredicate pred, IdemixProofCommitment scComm) {
    String name = pred.getName();
    URI location = input.pseudonyms.get(name).getSmartcardUri();
    BigInteger randomizer = input.pseudonyms.get(name).getRandomizer();
    BigInteger gamma = gp.getCapGamma();
    BigInteger h = gp.getH();

    BigInteger nym = input.smartcardManager.computePublicKeyOfCard(location);
    nym = nym.multiply(h.modPow(randomizer, gamma)).mod(gamma);
    this.state.commonList.put(name, nym);

    BigInteger nymTilde = scComm.commitmentForPublicKey(location);
    final BigInteger r_rand = Utils.computeRandomNumber(sp.getL_n() + sp.getL_Phi());
    nymTilde = nymTilde.multiply(h.modPow(r_rand, gamma)).mod(gamma);
    this.state.tList.add(nymTilde);

    ProofState state = new ProofState();
    state.put("r_rand", r_rand);
    this.state.states.put(name, state);

    if (!input.smartcardManager.getPseudonymModulusOfCard(location).equals(gp.getCapGamma())) {
      throw new RuntimeException("Incompatible modulus of pseudonyms Idemix/smartcard");
    }
    if (!input.smartcardManager.getPseudonymBaseOfCard(location).equals(gp.getG())) {
      throw new RuntimeException("Incompatible base G of pseudonyms Idemix/smartcard");
    }
  }

  /**
   * First round: Computes t-value for representations.
   * 
   * @param pred Representation predicate.
   */
  private void proveRepresentation(final RepresentationPredicate pred) {
    RepresentationOpening capR = input.representationOpenings.get(pred.getName());
    if (capR == null) {
      throw new RuntimeException("Computation of representation " + "not supported.");
    }

    Validation.validateRepresentation(pred, capR);

    // [spec: ProveRepresentation 1.] add product of hidden attributes
    // R_i^(tilde{a}_i) to the the product
    Vector<Exponentiation> expos = new Vector<Exponentiation>();
    for (int i = 0; i < pred.getIdentifiers().size(); i++) {
      Identifier id = pred.getIdentifiers().get(i);
      if (!id.isRevealed()) {
        // rTilde_j := id.getRandom()
        Exponentiation e = new Exponentiation(capR.getBase(i), id.getRandom(), capR.getModulus());
        expos.add(e);
      }
    }
    BigInteger capRTilde = Utils.multiExpMul(expos, capR.getModulus());
    this.state.tList.add(capRTilde);
  }

  /**
   * First round: Computes t-value for verifiable encryption.
   * 
   * @param pred Verifiable encryption predicate.
   */
  private void proveVerEnc(final VerEncPredicate pred) {

    VerifiableEncryptionOpening enc = input.verifiableEncryptions.get(pred.getName());
    if (enc == null) {
      // create the encryption
      BigInteger r = pred.getPublicKey().getRandom();
      enc =
          new VerifiableEncryptionOpening(pred.getIdentifier().getValue(), r,
              pred.getVEPublicKeyLocation(), pred.getLabel());
      // for the second round
      input.verifiableEncryptions.put(pred.getName(), enc);
    }
    if (state.verEncsSend.get(pred.getName()) == null) {
      // send it to the verifier
      state.verEncsSend.put(pred.getName(), enc.getEncryption());
    }
    assert (enc != null);
    VEPublicKey pk = enc.getEncryption().getPK();

    // [spec: ProveVerEnc 1.]
    BigInteger n2 = pk.getN2();
    int bitlength = 2 * sp.getL_enc() + sp.getL_Phi() + sp.getL_H() + 1;
    // [spec: ProveVerEnc 1.1]
    BigInteger rTilde = Utils.computeRandomNumberSymmetric(bitlength);
    // [spec: ProveVerEnc 1.2]
    BigInteger twoRTilde = rTilde.multiply(Utils.TWO);
    BigInteger mTilde = pred.getIdentifier().getRandom();

    BigInteger uHat = Utils.modPow(pk.getG(), twoRTilde, n2);

    Vector<Exponentiation> v = new Vector<Exponentiation>();
    v.add(new Exponentiation(pk.getY1(), twoRTilde, n2));
    v.add(new Exponentiation(pk.getH(), mTilde.multiply(Utils.TWO), n2));
    BigInteger eHat = Utils.multiExpMul(v, n2);

    v = new Vector<Exponentiation>();
    v.add(new Exponentiation(pk.getY2(), twoRTilde, n2));
    // Hash_hk(u,e,L) := enc.getHash(sp.getL_H()
    v.add(new Exponentiation(pk.getY3(), enc.getHash().multiply(twoRTilde), n2));
    BigInteger vHat = Utils.multiExpMul(v, n2);

    log.log(Level.FINE, " uHat: " + Utils.logBigInt(uHat));
    log.log(Level.FINE, " eHat: " + Utils.logBigInt(eHat));
    log.log(Level.FINE, " vHat: " + Utils.logBigInt(vHat));

    this.state.tList.add(uHat);
    this.state.tList.add(eHat);
    this.state.tList.add(vHat);

    // keep the state for round 2
    ProofState state = new ProofState();
    state.put("rTilde", rTilde);
    this.state.states.put(pred.getName(), state);
  }

  /**
   * Second round: Computes the s-values.
   * 
   * @param pred Verifiable encryption predicate.
   * @param challenge Challenge.
   */
  private void proveVerEnc(final VerEncPredicate pred, final BigInteger challenge) {
    ProofState state = this.state.states.get(pred.getName());
    VerifiableEncryptionOpening enc = input.verifiableEncryptions.get(pred.getName());

    BigInteger rHat = Utils.computeResponse(state.get("rTilde"), challenge, enc.getR());
    this.state.sValues.put(pred.getName(), new SValue(rHat));
  }

  /**
   * Validation of the proof. If we do not care that we fail at compilation time of the proof, we
   * might include that validation in the process of compiling the proof for efficiency reasons.
   */
  private void validateSpec() {
    Iterator<Predicate> predicates = spec.getPredicates().iterator();
    while (predicates.hasNext()) {
      Predicate predicate = predicates.next();
      // TODO (pbi) check if all values assigned to one identifier match?
      switch (predicate.getPredicateType()) {
        case CL: {
          String name = ((CLPredicate) predicate).getTempCredName();
          if (input.credentials.get(name) == null) {
            throw new RuntimeException("Missing credential with " + "temporary name: " + name);
          }
        }
          break;
        case CLCOM: {
          String name = ((CLComPredicate) predicate).getTempCredName();
          if (input.credentialCommitments.get(name) == null) {
            throw new RuntimeException("Missing credential commitment with " + "temporary name: "
                + name);
          }
        }
          break;
        case INEQUALITY:
          // TODO (pbi) implement verification if inequality holds?
          break;
        case NOTEQUAL:
          // TODO (pbi) implement verification if inequality holds?
          break;
        case ENUMERATION:
          break;
        case COMMITMENT: {
          String name = ((CommitmentPredicate) predicate).getName();
          if (input.commitmentOpenings.get(name) == null) {
            throw new RuntimeException("Missing commitment with " + "temporary name: " + name);
          }
          // TODO (pbi) implement verification that all commitments are
          // used (i.e., all elements in commitments are referred to by a
          // predicate)?
        }
          break;
        case REPRESENTATION:
          // TODO (pbi) implement verification that all required
          // representations are available
          // TODO (pbi) implement verification that bases in the spec ==
          // bases in the object
          break;
        case PSEUDONYM: {
          PseudonymPredicate pred = (PseudonymPredicate) predicate;
          if (!input.pseudonyms.containsKey(pred.getName())) {
            throw new RuntimeException("Cannot find pseudonym with temp. name " + pred.getName());
          }
          GroupParameters gp2 = input.pseudonyms.get(pred.getName()).getGroupParameters();
          if (!gp2.equals(spec.getGroupParams())) {
            throw new RuntimeException("Incompatible group parameters proofSpec/nym");
          }
        }
          break;
        case DOMAINNYM: {
          DomainNymPredicate pred = (DomainNymPredicate) predicate;
          if (!input.domainPseudonyms.containsKey(pred.getTempName())) {
            throw new RuntimeException("Cannot find domnym with temp. name " + pred.getTempName());
          }
          GroupParameters gp2 = input.domainPseudonyms.get(pred.getTempName()).getGroupParameters();
          if (!gp2.equals(spec.getGroupParams())) {
            throw new RuntimeException("Incompatible group parameters proofSpec/domNym");
          }
        }
          break;
        case VERENC:
          // TODO (pbi) implement verification that all used verifiable
          // encryptions are available?
          break;
        case MESSAGE:
          if (input.messages.isEmpty()) {
            throw new RuntimeException("Proof specification requires " + "that the message: "
                + ((MessagePredicate) predicate).getName()
                + " be signed, but the prover does not have any " + "messages");
          }
          break;
        case EPOCH:
          // TODO (pbi) implement verification that all the credentials
          // have epochs
          // TODO (pbi) implement verification that epoch identifier is
          // revealed
          break;
        case ACCUMULATOR:
        {
          AccumulatorPredicate accPred = (AccumulatorPredicate)predicate;
          AccumulatorWitness wit = input.accumulatorWitnesses.get(accPred.getTempName());
          if(wit == null) {
            throw new RuntimeException("Missing accumulator witness for: " + accPred.getTempName());
          }
          if(wit.getState().getEpoch() != accPred.getEpoch()) {
            throw new RuntimeException("Invalid accumulator epoch for: " + accPred.getTempName());
          }
          if(! wit.getState().getPublicKey().getUri().equals(accPred.getPublicKey())) {
            throw new RuntimeException("Invalid accumulator public key for: " + accPred.getTempName());
          }
          break;
        }
        default:
          throw new RuntimeException("Wrong predicate type.");
      }
    }
  }
}
