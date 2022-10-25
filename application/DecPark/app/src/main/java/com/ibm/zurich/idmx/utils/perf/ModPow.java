//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils.perf;

import java.math.BigInteger;

/**
 * Abstraction for the modular exponentiation operation.
 */
public interface ModPow {

    BigInteger modPow(final BigInteger exponent, final BigInteger modulus);

    /**
     * @return max width of exponent in bit.
     */
    int getMaxExpWidth();

    /**
     * @return modulus of exponentiation.
     */
    BigInteger getModulus();

    /**
     * @return exponentiation base.
     */
    BigInteger getBase();

}
