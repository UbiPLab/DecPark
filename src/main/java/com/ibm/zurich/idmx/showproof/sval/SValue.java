//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * Object that stores an s-value.
 */
public class SValue {

    /** Content of the s-value. */
    private Object value;

    /**
     * Constructor.
     * 
     * @param theValue
     *            S-Value.
     */
    public SValue(final BigInteger theValue) {
        value = theValue;
    }
    /**
     * Constructor.
     * 
     * @param theValue
     *            S-Value.
     */
    public SValue(final SValueType theValue) {
        value = theValue;
    }

    /**
     * @return S-value.
     */
    public final Object getValue() {
        return value;
    }
    
    @Override
    public String toString() {
      return "SValue [value=" + value + "]";
    }
}
