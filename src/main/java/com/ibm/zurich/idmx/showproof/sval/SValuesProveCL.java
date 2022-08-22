//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * S-values for ProveCL().
 */
public class SValuesProveCL  implements SValueType  {

    /** eHat value of CL-proof s-values. */
    private final BigInteger eHat;
    /** vHatPrime value of CL-proof s-values. */
    private final BigInteger vHatPrime;

    /**
     * Constructor for CL-proof s-values tied to a given certificate.
     * 
     * @param theEHat
     *            eHat value of CL-proof s-values.
     * @param theVHatPrime
     *            vHatPrime value of CL-proof s-values.
     */
    public SValuesProveCL(final BigInteger theEHat,
            final BigInteger theVHatPrime) {
        eHat = theEHat;
        vHatPrime = theVHatPrime;
    }

    /**
     * @return eHat.
     */
    public final BigInteger getEHat() {
        return eHat;
    }

    /**
     * @return vHat.
     */
    public final BigInteger getVHatPrime() {
        return vHatPrime;
    }

    @Override
    public String toString() {
      return "SValuesProveCL [eHat=" + eHat + ", vHatPrime=" + vHatPrime + "]";
    }

}
