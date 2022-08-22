//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.accumulator;

import java.io.Serializable;
import java.math.BigInteger;

import com.ibm.zurich.idmx.utils.Utils;

/**
 * This class represents a witness/value pair, used for proving that a value was indeed accumulated
 * in the accumulator.
 * 
 * @author enr
 * 
 */
public class AccumulatorWitness implements Serializable {
  private static final long serialVersionUID = 2290962106669856865L;
  
  private final AccumulatorState state;
  private final BigInteger value;
  private final BigInteger witness;


  /**
   * Construct witness based on XML.
   * 
   * @param state
   * @param value
   * @param witness
   */
  public AccumulatorWitness(AccumulatorState state, BigInteger value, BigInteger witness) {
    this.state = state;
    this.value = value;
    this.witness = witness;
  }

  /**
   * Compute witness using private key.
   * 
   * @param state
   * @param value
   * @param ask
   * @return
   */
  public static AccumulatorWitness calculateWitness(AccumulatorState state, BigInteger value,
      AccumulatorSecretKey ask) {
    if (!ask.getPublicKey().getN().equals(state.getPublicKey().getN())) {
      throw new RuntimeException("Using invalid private key in AccumulatorEvent:removePrime");
    }
    BigInteger valueInv = value.modInverse(ask.getOrder());
    BigInteger witness = state.getAccumulatorValue().modPow(valueInv, ask.getPublicKey().getN());
    return new AccumulatorWitness(state, value, witness);
  }

  /**
   * Update witness based on a new event.
   * 
   * @param previous
   * @param event
   * @param check
   * @return
   * @throws ValueHasBeenRevokedException in case our value was revoked.
   */
  public static AccumulatorWitness updateWitness(AccumulatorWitness previous,
      AccumulatorEvent event, boolean check) throws ValueHasBeenRevokedException {
    final BigInteger n = previous.state.getPublicKey().getN();

    AccumulatorState newState = AccumulatorState.applyEvent(previous.state, event, check);
    BigInteger newWitness = null;
    {
      if (!previous.value.gcd(event.getAccumulatedPrime()).equals(BigInteger.ONE)) {
        throw new ValueHasBeenRevokedException();
      }
      // find a, b st. a*value + b*prime = 1
      BigInteger euclid[] = Utils.extendedEuclid(previous.value, event.getAccumulatedPrime());
      // newWit = oldWit^b * newAcc^a (mod n)
      BigInteger term1 = previous.witness.modPow(euclid[1], n);
      BigInteger term2 = event.getFinalAccumulatorValue().modPow(euclid[0], n);
      newWitness = term1.multiply(term2).mod(n);
    }

    AccumulatorWitness newAw = new AccumulatorWitness(newState, previous.value, newWitness);
    if (check) {
      if (!newAw.isConsistent()) {
        throw new RuntimeException("Witness update failed in Accumulator");
      }
    }
    return newAw;
  }

  /**
   * Check if the witness/value pair is consistent with the current state.
   * 
   * @return
   */
  public boolean isConsistent() {
    BigInteger acc = witness.modPow(value, state.getPublicKey().getN());
    return acc.equals(state.getAccumulatorValue());
  }

  /**
   * Return accumulator state this witness/value pair is valid for
   * 
   * @return
   */
  public AccumulatorState getState() {
    return state;
  }

  /**
   * Return the value that was accumulated in the accumulator.
   * 
   * @return
   */
  public BigInteger getValue() {
    return value;
  }

  /**
   * Return the witness proving that this value was accumulated in the accumulator.
   * 
   * @return
   */
  public BigInteger getWitness() {
    return witness;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((state == null) ? 0 : state.hashCode());
    result = prime * result + ((value == null) ? 0 : value.hashCode());
    result = prime * result + ((witness == null) ? 0 : witness.hashCode());
    return result;
  }

  @Override
  public String toString() {
    return "AccumulatorWitness [state=" + state + ", value=" + value + ", witness=" + witness + "]";
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorWitness other = (AccumulatorWitness) obj;
    if (state == null) {
      if (other.state != null) return false;
    } else if (!state.equals(other.state)) return false;
    if (value == null) {
      if (other.value != null) return false;
    } else if (!value.equals(other.value)) return false;
    if (witness == null) {
      if (other.witness != null) return false;
    } else if (!witness.equals(other.witness)) return false;
    return true;
  }
}
