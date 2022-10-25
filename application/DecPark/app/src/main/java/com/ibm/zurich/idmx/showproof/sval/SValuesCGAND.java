//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.sval;

import java.math.BigInteger;

/**
 * Class to store the s-values for the prime encoded AND proofs.
 */
public class SValuesCGAND implements SValueType {

    private final BigInteger mHat_h;
    private final BigInteger rHat;

    public SValuesCGAND(BigInteger theMHat_h, BigInteger theRHat) {
        mHat_h = theMHat_h;
        rHat = theRHat;
    }

    public BigInteger getMHat_h() {
        return mHat_h;
    }

    public BigInteger getRHat() {
        return rHat;
    }

    @Override
    public String toString() {
      return "SValuesCGAND [mHat_h=" + mHat_h + ", rHat=" + rHat + "]";
    }

}
