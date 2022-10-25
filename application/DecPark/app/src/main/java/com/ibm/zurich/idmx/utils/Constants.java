//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils;

/**
 * Constants that are used in various places and information (such as the
 * version of the library).
 */
public class Constants {

    public static boolean PRINT_MOD_EXP = false;
    
    /** Number of bits per byte. */
    public static final int BIT_PER_BYTE = 8;

    /** Enables caching of fixed-based accelerated exponentiation. */
    public static final boolean USE_FAST_EXPO_CACHE = false;
    /** Enables multi-core exponentiation. */
    public static final boolean USE_MULTI_CORE_EXP = false;
    /** Enables multi-core generation of safe-primes. */
    public static final boolean USE_MULTI_CORE_SAFE_PRIMES = false;

    /** Delimiter between the attribute name and its value for set attributes. */
    public static final String DELIMITER = ";";

    /** XML Namespace used in XML serialization */
    public static final String XML_NAMESPACE = "http://www.zurich.ibm.com/security/idemix";
    /** Location of XML Schema. */
    public static final String XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /** Location of XML Schema instance. */
    public static final String XML_SCHEMA_INSTANCE = "http://www.w3.org/2001/XMLSchema-instance";
    /** Location of XML Schema of generated XML documents. */
    public static final String XML_SCHEMA_LOCATION = "http://www.zurich.ibm.com/security/idemix";

    /** Current version of the library. */
    private static final String VERSION = "2.3.43";

    /**
     * Sets a constant seed for random number generation and a constant master
     * secret to attain deterministic results.
     */
    public static final boolean DEVELOPING = false;

    /**
     * @return Version of the library.
     */
    public static final String getVersion() {
        return VERSION;
    }
    
    public static final void printCalculationLog(String message) {
      if(PRINT_MOD_EXP) {
        System.out.println(message);
      }
    }

}
