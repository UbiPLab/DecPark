//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm.structure;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.Attribute;
import com.ibm.zurich.idmx.dm.CommitmentOpening;
import com.ibm.zurich.idmx.dm.Value;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.DataType;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;

/**
 * Defines the structure of a credential using attribute structures and some
 * extra information such as the location of the update information, or if a
 * credential has an epoch.
 */
public class CredentialStructure {

    /** Set of attributes issued in any mode (hidden, known or committed). */
    private final Vector<AttributeStructure> attStructures;
    /** Location where update information can be collected. */
    private URI updateSpecLocation = null;
    /** Indicates if the epoch feature is used. */
    private final boolean hasEpoch;
    /** Domain of the credential. */
    private final String domain;
    /** Indicates if this credential has to be bound to a smartcard-borne secret */
    private final boolean onSmartcard;

    /**
     * Create a credential structure object.
     * 
     * @param theAttStructures
     *            Attribute structures that this credential will have excluding
     *            special attributes (e.g., the master secret).
     * @param featureInformation
     *            Information parsed from the features element containing, e.g.,
     *            domain or update location.
     * 
     */
    @Deprecated
    public CredentialStructure(final Vector<AttributeStructure> theAttStructures,
                               final HashMap<String, String> featureInformation) {
      this(theAttStructures, featureInformation, false);
    }
    
    public CredentialStructure(
            final Vector<AttributeStructure> theAttStructures,
            final HashMap<String, String> featureInformation, final boolean onSmartcard) {
        attStructures = theAttStructures;

        domain = featureInformation.get("domain");
        String updateInfoLocationString = featureInformation
                .get("updateSpecification");
        if (updateInfoLocationString != null) {
            try {
                updateSpecLocation = new URI(updateInfoLocationString);
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
        }

        // determine if there is an epoch attribute
        hasEpoch = getEpochFromAttStructs();
        if (hasEpoch && updateSpecLocation == null) {
            throw new RuntimeException("Epoch attributes require updates. "
                    + "Please indicate an update information location.");
        }
        
        // determine smartcard requirements
        this.onSmartcard = onSmartcard;
    }

    /**
     * @return Location where the update information of the credential can be
     *         collected. This contains information such as the attribute the
     *         will be update, terms for those updates.
     */
    public final URI getUpdateSpecLocation() {
        return updateSpecLocation;
    }

    /**
     * @return Domain of the credential.
     */
    public final String getDomain() {
        return domain;
    }

    /**
     * @return True if an attribute structure of the given vector has attribute
     *         type EPOCH.
     */
    private boolean getEpochFromAttStructs() {
        for (AttributeStructure att : attStructures) {
            if (att.getDataType() == DataType.EPOCH) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return True if there is an epoch present.
     */
    public final boolean getEpoch() {
        return hasEpoch;
    }

    /**
     * Returns all attributes that are of the given issuance mode
     * <code>theIssuanceMode</code>.
     * 
     * @param theIssuanceMode
     *            Given issuance mode.
     * @return Attributes of the indicated issuance mode.
     */
    public final Vector<AttributeStructure> getAttributeStructs(
            final IssuanceMode theIssuanceMode) {
        Vector<AttributeStructure> atts = new Vector<AttributeStructure>();
        for (AttributeStructure att : attStructures) {
            if (att.getIssuanceMode() == theIssuanceMode) {
                atts.add(att);
            }
        }
        return atts;
    }

    /**
     * @return New vector containing all attribute structures of this
     *         credential.
     */
    public final Vector<AttributeStructure> getAttributeStructs() {
        Vector<AttributeStructure> attStructs = new Vector<AttributeStructure>();
        attStructs.addAll(attStructures);
        return attStructs;
    }

    /**
     * @param name
     *            Name of the attribute.
     * @return Structure of the queried attribute named <code>name</code> or
     *         <code>null</code> if the attribute structure is not found.
     */
    public final AttributeStructure getAttributeStructure(final String name) {
        for (AttributeStructure attStruct : attStructures) {
            if (attStruct.getName().equalsIgnoreCase(name)) {
                return attStruct;
            }
        }
        return null;
    }

    /**
     * Verifies if the values contain everything an issuer needs to issue a
     * credential of this structure. It only makes sure that all the attributes
     * have a corresponding value.
     * 
     * @param values
     *            Values to be used during issuance.
     * @return True if all required values are present.
     */
    public final boolean verifyIssuerValues(final Values values) {
        // TODO (pbi) check for epoch attribute?
        for (AttributeStructure attStructure : attStructures) {
            if ((attStructure.getIssuanceMode() != IssuanceMode.HIDDEN)) {
                if (values.get(attStructure.getName()) == null) {
                  System.err.println("Expected revealed attribute " + attStructure.getName());  
                  return false;
                }
            }
        }
        return true;
    }

    /**
     * Verifies if the values contain everything a recipient needs to get a
     * credential of this structure and that they are of the right form.
     * 
     * @param values
     *            Values to be used during issuance.
     * @return True if all required values are present.
     */
    public final boolean verifyRecipientValues(final Values values) {
        // TODO (pbi) check for epoch attribute?
        for (AttributeStructure attStruct : attStructures) {
            Value v = values.get(attStruct.getName());
            Object object = null;
            if (null != v) {
              object = v.getContent();
            }
            switch (attStruct.getIssuanceMode()) {
            case KNOWN:
            case HIDDEN:
                if (!(object instanceof BigInteger)) {
                    return false;
                }
                break;
            case COMMITTED:
                if (!(object instanceof CommitmentOpening)) {
                    return false;
                }
                break;
            case ISSUER:
              if (v != null) {
                return false;
              }
              break;
            default:
                throw new RuntimeException("Issuance mode not implemented.");
            }
        }
        return true;
    }

    /**
     * @param values
     *            Values encoded in the attribute.
     * @return Attributes contained in a credential of this structure.
     */
    public final Vector<Attribute> createAttributes(final Values values) {
        Vector<Attribute> atts = new Vector<Attribute>();
        for (AttributeStructure attStructure : attStructures) {
          String attName = attStructure.getName();
          Value v = values.get(attName);
          if (attStructure.getIssuanceMode() == IssuanceMode.ISSUER && null == v) {
            continue;
          }
          Attribute a = attStructure.createAttribute(v);
          atts.add(a);
        }
        return atts;
    }

    @Override
    public String toString() {
      return "CredentialStructure [attStructures=" + attStructures + ", updateSpecLocation="
          + updateSpecLocation + ", hasEpoch=" + hasEpoch + ", domain=" + domain + ", onSmartcard="
          + onSmartcard + "]";
    }

    public boolean isOnSmartcard() {
      return onSmartcard;
    }
}
