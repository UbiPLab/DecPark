//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

import com.ibm.zurich.idmx.utils.Constants;

/**
 * Default BigInteger exponentiation. A wrapper around BigInteger modPow().
 * 
 * @see BigInteger#modPow(BigInteger, BigInteger)
 */
public class DefModPow implements ModPow {

    private final BigInteger base;
    private final BigInteger modulus;

    public DefModPow(final BigInteger base, final BigInteger modulus) {
        this.base = base;
        this.modulus = modulus;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getBase()
     */
    public BigInteger getBase() {
        return this.base;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getMaxExpWidth()
     */
    public int getMaxExpWidth() {
        return Integer.MAX_VALUE;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#getModulus()
     */
    public BigInteger getModulus() {
        return this.modulus;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ibm.zurich.idmx.utils.perf.ModPow#modPow(java.math.BigInteger,
     * java.math.BigInteger)
     */
    public BigInteger modPow(BigInteger exponent, BigInteger modulus) {
        if (!modulus.equals(this.modulus)) {
            throw new IllegalArgumentException();
        }
        Constants.printCalculationLog("#EXP base# " + base);
        Constants.printCalculationLog("#EXP exp# " + exponent);
        return this.base.modPow(exponent, modulus);
    }

}
