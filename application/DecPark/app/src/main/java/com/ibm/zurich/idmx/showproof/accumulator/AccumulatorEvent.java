//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.accumulator;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * This class represents an event, i.e., the removal of a value from the accumulator. The
 * accumulator value is not changed when "adding" an element to it, and this there is no event for
 * that; instead, one simply extracts the witness of the value to "add".
 * 
 * @author enr
 * 
 */
public class AccumulatorEvent implements Serializable {
  private static final long serialVersionUID = -8903935595434550778L;
  
  private final int newEpoch;
  private final BigInteger removedPrime;
  private final XMLGregorianCalendar eventDate;
  private final BigInteger finalAccumulatorValue;

  /**
   * Construct an AccumulatorEvent from XML
   * 
   * @param newEpoch
   * @param add
   * @param accumulatedPrime
   * @param eventDate
   * @param finalAccumulatorValue
   */
  public AccumulatorEvent(int newEpoch, BigInteger accumulatedPrime,
      XMLGregorianCalendar eventDate, BigInteger finalAccumulatorValue) {
    super();
    this.newEpoch = newEpoch;
    this.removedPrime = accumulatedPrime;
    this.eventDate = eventDate;
    this.finalAccumulatorValue = finalAccumulatorValue;
  }

  /**
   * Construct an AccumulatorEvent to remove a prime from the accumulator given the secret key of
   * the accumulator. This method is faster than the one taking the whole history.
   * 
   * @param currentState
   * @param accumulatedPrime
   * @param date
   * @param ask
   * @return
   */
  public static AccumulatorEvent removePrime(AccumulatorState currentState,
      BigInteger accumulatedPrime,
      /* Nullable */XMLGregorianCalendar date, AccumulatorSecretKey ask) {
    if (!ask.getPublicKey().getN().equals(currentState.getPublicKey().getN())) {
      throw new RuntimeException("Using invalid private key in AccumulatorEvent:removePrime");
    }
    int newEpoch = currentState.getEpoch() + 1;
    if (date == null) {
      date = now();
    }
    // acc = acc^( prime^-1 mod phi ) mod n
    BigInteger inv = accumulatedPrime.modInverse(ask.getOrder());
    BigInteger acc = currentState.getAccumulatorValue().modPow(inv, ask.getPublicKey().getN());
    return new AccumulatorEvent(newEpoch, accumulatedPrime, date, acc);
  }

  private static XMLGregorianCalendar now() {
    try {
      return DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());
    } catch (DatatypeConfigurationException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * The epoch of the accumulator after this event has been applied.
   * 
   * @return
   */
  public int getNewEpoch() {
    return newEpoch;
  }

  /**
   * The value that was added/removed from the accumulator
   * 
   * @return
   */
  public BigInteger getAccumulatedPrime() {
    return removedPrime;
  }

  /**
   * The date at which the event was created.
   * 
   * @return
   */
  public XMLGregorianCalendar getEventDate() {
    return eventDate;
  }

  /**
   * The value of the accumulator after applying the event.
   * 
   * @return
   */
  public BigInteger getFinalAccumulatorValue() {
    return finalAccumulatorValue;
  }


  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((eventDate == null) ? 0 : eventDate.hashCode());
    result =
        prime * result + ((finalAccumulatorValue == null) ? 0 : finalAccumulatorValue.hashCode());
    result = prime * result + newEpoch;
    result = prime * result + ((removedPrime == null) ? 0 : removedPrime.hashCode());
    return result;
  }


  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorEvent other = (AccumulatorEvent) obj;
    if (eventDate == null) {
      if (other.eventDate != null) return false;
    } else if (!eventDate.equals(other.eventDate)) return false;
    if (finalAccumulatorValue == null) {
      if (other.finalAccumulatorValue != null) return false;
    } else if (!finalAccumulatorValue.equals(other.finalAccumulatorValue)) return false;
    if (newEpoch != other.newEpoch) return false;
    if (removedPrime == null) {
      if (other.removedPrime != null) return false;
    } else if (!removedPrime.equals(other.removedPrime)) return false;
    return true;
  }


  @Override
  public String toString() {
    return "AccumulatorEvent [newEpoch=" + newEpoch + ", removedPrime=" + removedPrime
        + ", eventDate=" + eventDate + ", finalAccumulatorValue=" + finalAccumulatorValue + "]";
  }

}
