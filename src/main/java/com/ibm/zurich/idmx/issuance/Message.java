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
import java.util.Iterator;
import java.util.Map;

import com.ibm.zurich.idmx.showproof.Proof;

/**
 *
 */
public class Message {

    public enum IssuanceProtocolValues {
        /** Common value <tt>U</tt>. */
        capU,
        /** Nonce. */
        nonce,

        /** Signature value <tt>A</tt>. */
        capA,
        /** Signature value <tt>e</tt>. */
        e,
        /** Signature value <tt>v''</tt>. */
        vPrimePrime,
    }

    /** Map with all the elements of the message. */
    private final Map<IssuanceProtocolValues, BigInteger> issuanceProtocolValues;
    /** Map with key-value pairs of revealed attributes */
    private final Map<String, BigInteger> revealedAttributes;
    /** Proof. */
    private final Proof proof;
    /** Location where the updates for a credential can be downloaded. */
    private final URI updateLocation;
    /** Message counter. */
    private final int counter;

   
    /**
     * Convenience constructor with counter.
     */
    public Message(
            HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof, int theCounter) {
        this(theIssuanceElements, theProof, null, theCounter);
    }
    
    /**
     * Convenience constructor.
     */
    public Message(
            HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof) {
        this(theIssuanceElements, theProof, null, 0);
    }
    
    /**
     * Constructor without a counter.
     */
    public Message(
            HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof, URI theUpdateLocation) {
        this(theIssuanceElements, theProof,  theUpdateLocation, 0);
    }
    
    public Message(
                   HashMap<IssuanceProtocolValues, BigInteger> theIssuanceElements,
                   Proof theProof, URI theUpdateLocation, int theCounter) {
      this(theIssuanceElements, theProof, theUpdateLocation, theCounter, null);
    }

    /**
     * Constructor.
     * 
     * @param theIssuanceElements
     *            Values generated during a protocol step that need to be
     *            communicated to the communication partner.
     * @param theProof
     *            Relevant values of the proof convincing the communication
     *            partner to continue the protocol.
     * @param theUpdateLocation
     *            [optional] If the credential is updateable, the location where
     *            updates can be fetched needs to be sent to the RECIPIENT.
     * @param theCounter 
     * 	          [optional] Number of the message.
     */
    public Message(
            Map<IssuanceProtocolValues, BigInteger> theIssuanceElements,
            Proof theProof, URI theUpdateLocation, int theCounter,
            Map<String, BigInteger> revealedAttributes) {
        issuanceProtocolValues = theIssuanceElements;
        proof = theProof;
        updateLocation = theUpdateLocation;
        counter = theCounter;
        this.revealedAttributes = revealedAttributes;
    }

    /**
     * @return The issuance element queried for (e.g., <tt>A</tt>, <tt>e</tt>,
     *         <tt>v''</tt>, <tt>Q</tt>).
     */
    public final BigInteger getIssuanceElement(IssuanceProtocolValues element) {
      BigInteger e = issuanceProtocolValues.get(element);
      return new BigInteger(e.toString());
    }

    /**
     * @return Proof.
     */
    public final Proof getProof() {
        return proof;
    }
    
    /**
     * @return Counter.
     */
	public int getCounter() {
		return counter;
	}

    /**
     * @return Location where the credential update can be downloaded.
     */
    public final URI getUpdateLocation() {
        return updateLocation;
    }

    /**
     * Serialization method.
     */
    public final Iterator<IssuanceProtocolValues> iterator() {
        return issuanceProtocolValues.keySet().iterator();
    }
    
    public final Map<String, BigInteger> getRevealedAttributes() {
      return revealedAttributes;
    }
    
    public final BigInteger getRevealedAttribute(String attName) {
      return revealedAttributes.get(attName);
    }
}
