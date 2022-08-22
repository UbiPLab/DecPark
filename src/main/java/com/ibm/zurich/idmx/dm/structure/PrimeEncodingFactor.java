//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm.structure;

import java.math.BigInteger;

import com.ibm.zurich.idmx.utils.Constants;

/**
 * Defines one prime corresponding factor. In particular, it defines the
 * attribute it belongs to, the enumeration value it encodes, and the prime it
 * uses to encode the enumerated value.
 */
public class PrimeEncodingFactor {

    /** Name of the attribute corresponding to this factor. */
    private final String attributeName;
    /** Enumeration value corresponding to this factor. */
    private final String enumValue;
    /** Prime associated with this prime factor. */
    private BigInteger primeFactor;

    /**
     * Constructor.
     * 
     * @param theAttributeName
     *            Name of the attribute corresponding to this factor.
     * @param theAttributeValue
     *            Enumeration value corresponding to this factor.
     */
    public PrimeEncodingFactor(final String theAttributeName,
            final String theAttributeValue) {
        attributeName = theAttributeName;
        enumValue = theAttributeValue;
    }

    /**
     * Sets the corresponding prime.
     * 
     * @param thePrimeFactor
     *            Prime number.
     */
    public final void setPrimeFactor(final BigInteger thePrimeFactor) {
        if (primeFactor != null) {
            throw (new RuntimeException("Prime factor " + attributeName
                    + Constants.DELIMITER + enumValue
                    + " cannot be overwritten."));
        }
        primeFactor = thePrimeFactor;
    }

    /**
     * @return Prime number associated with this factor.
     */
    public final BigInteger getPrimeFactor() {
        return primeFactor;
    }

    @Override
    public String toString() {
      return "PrimeEncodingFactor [attributeName=" + attributeName + ", enumValue=" + enumValue
          + ", primeFactor=" + primeFactor + "]";
    }

}
