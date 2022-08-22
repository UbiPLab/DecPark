//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.util.Date;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Idemix group parameters abstraction.
 */
public class GroupParameters implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 149541487042118685L;

	/** Logger. */
    private static Logger log = Logger.getLogger(GroupParameters.class
            .getName());

    /**
     * System parameters with respect to which the group parameters have been
     * created.
     */
    private final URI systemParametersLocation;
    /** Committment group order. */
    private final BigInteger capGamma;
    /** Order of the subgroup of the commitment group. */
    private final BigInteger rho;
    /** Generator. */
    private final BigInteger g;
    /** Generator. */
    private final BigInteger h;

    /**
     * Constructor.
     * 
     * @param theCapGamma
     *            Modulus of the commitment group.
     * @param theRho
     *            Order of the subgroup of the commitment group.
     * @param theG
     *            Generator of ...
     * @param theH
     *            Generator of ...
     * @param theSp
     *            System parameter location.
     */
    public GroupParameters(final BigInteger theCapGamma, final BigInteger theRho,
            final BigInteger theG, final BigInteger theH, final URI theSp) {
        super();
        capGamma = theCapGamma;
        rho = theRho;
        g = theG;
        h = theH;
        systemParametersLocation = theSp;
    }

    /**
     * @return System parameters.
     */
    public final SystemParameters getSystemParams() {
        return (SystemParameters) StructureStore.getInstance().get(
                systemParametersLocation);
    }

    /**
     * @return System parameters location.
     */
    public final URI getSystemParamsLocation() {
        return systemParametersLocation;
    }

    /**
     * @return the gamma
     */
    public BigInteger getCapGamma() {
        return capGamma;
    }

    /**
     * @return the rho
     */
    public BigInteger getRho() {
        return rho;
    }

    /**
     * @return the g
     */
    public BigInteger getG() {
        return g;
    }

    /**
     * @return the h
     */
    public BigInteger getH() {
        return h;
    }

    /**
     * @return The number of elements in the group parameters.
     */
    public final int getNumber() {
        // FIXME (pbi) this should count the number of elements of the group
        // parameters.
        return 4;
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof GroupParameters)) {
            return false;
        }

        GroupParameters otherGp = (GroupParameters) o;
        if (this == otherGp) {
            return true;
        }
        return (systemParametersLocation
                .equals(otherGp.systemParametersLocation)
                && g.equals(otherGp.g)
                && h.equals(otherGp.h)
                && capGamma.equals(otherGp.capGamma) && rho.equals(otherGp.rho));
    }

    /**
     * Generates group parameters according to section 4.1 in math doc.
     * 
     * @param systemParameterLocation
     *            Location of the system parameters.
     * @return newly created group parameters.
     */
    public static GroupParameters generateGroupParams(
            final URI systemParameterLocation) {

        Date start = new Date();

        final SystemParameters sp = (SystemParameters) StructureStore
                .getInstance().get(systemParameterLocation);

        BigInteger capGamma;
        BigInteger g;
        BigInteger rho;
        BigInteger h;

        int l_rho = sp.getL_rho();

        // select rho of given length with prime probability.
        rho = generatePrime(l_rho, sp);

        // find the group order Gamma.
        capGamma = generateGroupModulus(rho, sp);

        // get generator g. see math doc for this detail.
        g = newGenerator(rho, capGamma, sp);

        // compute second generator h = g^random.
        final BigInteger rh = Utils.computeRandomNumber(BigInteger.ZERO, rho,
                sp);

        h = g.modPow(rh, capGamma);

        Date stop = new Date();

        log.log(Level.INFO, "Param generation: start: " + start.toString()
                + " end: " + stop.toString());

        return new GroupParameters(capGamma, rho, g, h, systemParameterLocation);
    }
    
    /**
     * Generate a prime with a given length, based on the prime probability of the system parameters
     * @param bitLength
     * @param sp
     * @return
     */
    public static BigInteger generatePrime(int bitLength, SystemParameters sp) {
      BigInteger rho;  
      do {
          rho = new BigInteger(bitLength, sp.getL_pt(),
                  Utils.getRandomGenerator());
      } while (!Utils.isInInterval(rho, bitLength - 1, bitLength));
      return rho;
    }
    
    /**
     * Generate the modulus for a prime order group.
     * The length of the modulus and the prime probability is taken from the system parameters.
     * The modulus might actually be 1 bit less than what is required by the system parameters.
     * @param order The order of the prime order group
     * @param sp
     * @return
     */
    public static BigInteger generateGroupModulus(BigInteger order, SystemParameters sp) {
      BigInteger capGamma;
      
      int l_b = sp.getL_Gamma() - order.bitLength();
      BigInteger b; // co-factor of (Gamma - 1).
      do {
          // see Table 4 of math doc as well as section 4.1
          do {
              b = new BigInteger(l_b, Utils.getRandomGenerator());
              // b != 0 (mod order)
          } while (b.mod(order).equals(BigInteger.ZERO));

          // Gamma = (order * b) + 1
          capGamma = order.multiply(b).add(BigInteger.ONE);

      } while (!capGamma.isProbablePrime(sp.getL_pt())
              || !Utils.isInInterval(capGamma, sp.getL_Gamma() - 2,
                      sp.getL_Gamma()));
      return capGamma;
    }
    
    public static BigInteger newGenerator(BigInteger order, BigInteger modulus, SystemParameters sp) {
      BigInteger g;
      BigInteger gPrime;
      // Gamma = (order * b) + 1
      BigInteger b = modulus.subtract(BigInteger.ONE).divide(order);
      do {
          gPrime = Utils.computeRandomNumber(order, sp);
          g = gPrime.modPow(b, modulus);
      } while (g.equals(BigInteger.ONE));
      // g'^{b} != 1 (mod Gamma)
      return g;
    }

    @Override
    public String toString() {
      return "GroupParameters [systemParametersLocation=" + systemParametersLocation
          + ", capGamma=" + capGamma + ", rho=" + rho + ", g=" + g + ", h=" + h + "]";
    }

    public BigInteger generateHash() {
      BigInteger[] items = new BigInteger[4];
      items[0] = capGamma;
      items[1] = rho;
      items[2] = g;
      items[3] = h;
      System.out.println(this);
      return Utils.hashOf(256, items);
    }
}
