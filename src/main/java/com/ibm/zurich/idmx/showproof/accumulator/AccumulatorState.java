//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.accumulator;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;

import javax.xml.datatype.XMLGregorianCalendar;

import com.ibm.zurich.idmx.utils.StructureStore;

/**
 * Class representing the current state of the accumulator. Note that this class is immutable.
 * 
 * @author enr
 * 
 */
public class AccumulatorState implements Serializable{
  private static final long serialVersionUID = 1050548416762447339L;
  
  private final AccumulatorPublicKey apk;
  private final int epoch;
  private final BigInteger accumulatorValue;
  private final XMLGregorianCalendar lastChange;

  @Override
  public String toString() {
    return "AccumulatorState [apk=" + apk + ", epoch=" + epoch + ", accumulatorValue="
        + accumulatorValue + ", lastChange=" + lastChange + "]";
  }

  /**
   * Construct the state based on XML.
   * 
   * @param apk
   * @param epoch
   * @param accumulatorValue
   */
  public AccumulatorState(AccumulatorPublicKey apk, int epoch, BigInteger accumulatorValue, /* nullable */
      XMLGregorianCalendar lastChange) {
    this.apk = apk;
    this.epoch = epoch;
    this.accumulatorValue = accumulatorValue;
    this.lastChange = lastChange;
  }

  /**
   * Construct the state based on XML. Load the public key from storage.
   */
  public AccumulatorState(URI publicKeyUri, int epoch, BigInteger accumulatorValue, /* nullable */
      XMLGregorianCalendar lastChange) {
    this.apk = (AccumulatorPublicKey) StructureStore.getInstance().get(publicKeyUri);
    this.epoch = epoch;
    this.accumulatorValue = accumulatorValue;
    this.lastChange = lastChange;
  }

  /**
   * Generate an empty accumulator.
   * 
   * @param apk
   * @return
   */
  public static AccumulatorState getEmptyAccumulator(AccumulatorPublicKey apk) {
    return new AccumulatorState(apk, 0, apk.getBaseG(), null);
  }

  /**
   * Extract the latest state of the accumulator from an event. It is recommened to use applyEvent()
   * instead.
   * 
   * @param lastEvent
   * @param publicKey
   * @return
   */
  public static AccumulatorState getStateFromLastEvent(AccumulatorEvent lastEvent,
      AccumulatorPublicKey publicKey) {
    return new AccumulatorState(publicKey, lastEvent.getNewEpoch(),
        lastEvent.getFinalAccumulatorValue(), lastEvent.getEventDate());
  }

  /**
   * Apply an event to an accumulator, yielding a new state. This method is the preferred way of
   * updating the state.
   * 
   * @param previous The current state of the accumulator
   * @param event The event to apply
   * @param check Perform a consistency check?
   * @return The state of the accumulator after having applied the event.
   */
  public static AccumulatorState applyEvent(AccumulatorState previous, AccumulatorEvent event,
      boolean check) {
    // Check that the event's epoch matches the state's epoch
    if (previous.getEpoch() + 1 != event.getNewEpoch()) {
      throw new RuntimeException("Incompatible state and event in AccumulatorState:applyEvent");
    }

    if (check) {
      BigInteger oldAcc =
          event.getFinalAccumulatorValue().modPow(event.getAccumulatedPrime(),
              previous.getPublicKey().getN());
      if (!oldAcc.equals(previous.accumulatorValue)) {
        throw new RuntimeException("Incorrect final accumulator value when applying event (del)");
      }
    }

    return new AccumulatorState(previous.getPublicKey(), event.getNewEpoch(),
        event.getFinalAccumulatorValue(), event.getEventDate());
  }

  /**
   * The epoch (number of events that have been applied to this accumulator) of this accumulator.
   * 
   * @return
   */
  public int getEpoch() {
    return epoch;
  }

  /**
   * The current value of the accumulator
   * 
   * @return
   */
  public BigInteger getAccumulatorValue() {
    return accumulatorValue;
  }

  /**
   * The public key of this accumulator
   * 
   * @return
   */
  public AccumulatorPublicKey getPublicKey() {
    return apk;
  }

  /**
   * Returns the date of the last time the accumulator was changed, or null if the accumulator has
   * never been updated
   */
  public XMLGregorianCalendar getLastChange() {
    return lastChange;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((accumulatorValue == null) ? 0 : accumulatorValue.hashCode());
    result = prime * result + ((apk == null) ? 0 : apk.hashCode());
    result = prime * result + epoch;
    result = prime * result + ((lastChange == null) ? 0 : lastChange.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorState other = (AccumulatorState) obj;
    if (accumulatorValue == null) {
      if (other.accumulatorValue != null) return false;
    } else if (!accumulatorValue.equals(other.accumulatorValue)) return false;
    if (apk == null) {
      if (other.apk != null) return false;
    } else if (!apk.equals(other.apk)) return false;
    if (epoch != other.epoch) return false;
    if (lastChange == null) {
      if (other.lastChange != null) return false;
    } else if (!lastChange.equals(other.lastChange)) return false;
    return true;
  }
}
