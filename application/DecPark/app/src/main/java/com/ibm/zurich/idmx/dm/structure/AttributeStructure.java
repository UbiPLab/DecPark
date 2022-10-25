//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm.structure;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.Value;
import com.ibm.zurich.idmx.utils.SystemParameters;

/**
 * Attribute structures are used as part to a credential structure. In
 * particular, they define the issuance mode, data type, name and the position
 * within the credential (i.e., the public key index).
 */
public class AttributeStructure {

    /** Data types for attributes. */
    public enum DataType {
        /** Integer attributes. */
        INT,
        /** String attributes. */
        STRING,
        /** Attributes used to limit credential lifetime. */
        EPOCH,
        /** Enumerated attributes. */
        ENUM
    };

    /** Issuance mode of attributes. */
    public enum IssuanceMode {
        /** Attribute is known to the issuer (and the recipient). */
        KNOWN,
        /** The recipient committed to the attribute. */
        COMMITTED,
        /** Attribute is hidden towards the issuer. */
        HIDDEN,
        /** Attribute is known to the issuer, receipient receives the value only after issuance */
        ISSUER
    }

    // /** Location of the issuer public key. */
    // private URI ipkLocation;
    /** Attribute's name. */
    private final String name;
    /**
     * Position at which this attribute appears within the credential. This
     * corresponds to the indexes the attribute has with respect to the bases of
     * the issuer public key.
     */
    private int publicKeyIndex;
    /** The issuance mode of this attribute. */
    private final IssuanceMode issuanceMode;
    /** Data type of the attribute (e.g., INT, STR, DATE, EPOCH). */
    private final DataType dataType;
    /** Map of all possible attributes and their corresponding prime values. */
    private HashMap<String, PrimeEncodingFactor> primeFactors;
    /** Number of primes encoded into one attribute. */
    private int t;

    @Override
    public String toString() {
      return "AttributeStructure [name=" + name + ", publicKeyIndex=" + publicKeyIndex
          + ", issuanceMode=" + issuanceMode + ", dataType=" + dataType + ", primeFactors="
          + primeFactors + ", t=" + t + "]";
    }

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of this attribute;
     * @param thePublicKeyIndex
     *            Position of the attribute within the credential.
     * @param theIssuanceMode
     *            Issuance mode of this attribute.
     * @param theAttributeType
     *            Attribute type of this attribute.
     */
    public AttributeStructure(final String theName,
            final int thePublicKeyIndex, final IssuanceMode theIssuanceMode,
            final DataType theAttributeType) {
        name = theName;
        issuanceMode = theIssuanceMode;
        dataType = theAttributeType;
        publicKeyIndex = thePublicKeyIndex;
    }

    /**
     * @return Name of the attribute.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Index w.r.t. the bases of the public key.
     */
    public final int getKeyIndex() {
        return publicKeyIndex;
    }

    /**
     * @return Issuance mode of the attribute (e.g. KNOWN, HIDDEN).
     */
    public final IssuanceMode getIssuanceMode() {
        return issuanceMode;
    }

    /**
     * @return Data type of the attribute (e.g. INT, STRING).
     */
    public final DataType getDataType() {
        return dataType;
    }

    /**
     * @param theValue
     *            Value of the attribute.
     * @return New attribute object.
     */
    public final Attribute createAttribute(final Value theValue) {
        if (dataType == DataType.ENUM) {
            return new Attribute(this, theValue.getContent(),
                    theValue.getPrimeEncodedElements());
        } else {
            return new Attribute(this, theValue.getContent());
        }
    }

    /**
     * When loading a credential structure, the elements that one prime encoding
     * might encode are extracted and saved here.
     * 
     * @param hashMap
     *            Map of all elements this attribute might encode.
     */
    public final void setPrimeEncodedFactors(
            final HashMap<String, PrimeEncodingFactor> hashMap, int numValues) {
        if (primeFactors != null) {
            throw (new RuntimeException("Prime encoding is already "
                    + "instantiated."));
        }
        primeFactors = hashMap;
        t = numValues;
    }

    /**
     * @param key
     *            Name of the prime factor.
     * @return Prime factor corresponding to the given name.
     */
    public final BigInteger getPrimeFactor(final String key) {
      try {
        return primeFactors.get(key).getPrimeFactor();
      } catch(NullPointerException e) {
        throw e;
      }
    }

    public final int getL_t(SystemParameters sp) {
        return (int) Math.floor(sp.getL_m() / t);
    }

    // /**
    // * Sets the issuer public key (needed for the prime encoding commitments).
    // * This could also be implemented using a reference to the credential
    // * structure, which might be of use in other features as well.
    // *
    // * @param issuerPublicKeyLocation
    // * Location of the issuer public key of this credential
    // * structure.
    // *
    // */
    // public final void setPublicKeyLocation(final URI issuerPublicKeyLocation)
    // {
    // ipkLocation = issuerPublicKeyLocation;
    // }
    //
    // /**
    // * @return Location of the issuer public key.
    // */
    // public final URI getPublicKeyLocation() {
    // return ipkLocation;
    // }

    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AttributeStructure other = (AttributeStructure) obj;
        if (name != other.name) {
            return false;
        }
        if (issuanceMode != other.issuanceMode) {
            return false;
        }
        if (dataType != other.dataType) {
            return false;
        }
        return true;
    }

    @Override
    public final int hashCode() {
        int tmp = name.hashCode();
        tmp += issuanceMode.hashCode();
        tmp += dataType.hashCode();
        return tmp;
    }

    public HashSet<String> recoverPrimeFactors(BigInteger value) {
      HashSet<String> factors = new HashSet<String>();
      for(Entry<String, PrimeEncodingFactor> es: primeFactors.entrySet()) {
        BigInteger factor = es.getValue().getPrimeFactor();
        if (value.mod(factor).equals(BigInteger.ZERO)) {
          factors.add(es.getKey());
        }
      }
      return factors;
    }
}
