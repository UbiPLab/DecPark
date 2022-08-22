//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;

import com.ibm.zurich.idmx.dm.structure.AttributeStructure;
import com.ibm.zurich.idmx.dm.structure.AttributeStructure.IssuanceMode;
import com.ibm.zurich.idmx.dm.structure.CredentialStructure;
import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.smartcard.IdemixSmartcardManager;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;
import com.ibm.zurich.idmx.utils.perf.Exponentiation;

/**
 * Credential abstraction. When persisted by the recipient, all attribute values
 * are set. When we use a certificate in a show-proof on the verifier side, the
 * attribute values must be nullified.
 * 
 */
public class CredentialCommitment {

    /** The ID of the issuer public key used to issue this credential. */
    private final URI issuerPublicKeyId;
    /** Public key of the issuer of this credential. */
    private final IssuerPublicKey ipk;
    /** Credential structure that corresponds to this credential. */
    private final URI credStructId;
    /** Set of attributes of any issuance mode (hidden, known or committed). */
    private final List<Attribute> attributes;
    
    /** Name of the credential on the smartcard (or null) */
    private final URI nameOnSmartcard;
    /** Name of the smartcard that hosts the secret of this credential */
    private final URI smartcardName;
    /** The smartcard manager */
    private final IdemixSmartcardManager smartcardManager;

    /**
     * Constructor. Create a credential object. Input is a CL signature
     * <tt>(A,e,v)</tt>, a credential structure (containing issuer public key,
     * group parameters, ...) and the values that will be assigned to the
     * attributes in the newly created credential.
     * 
     * @param ipkId
     *            Identifier of the issuer public key.
     * @param theCredStructLocation
     *            Location of the credential structure.
     * @param theCapA
     *            Signature value <tt>A</tt>.
     * @param theE
     *            Signature value <tt>e</tt>.
     * @param theV
     *            Signature value <tt>v</tt>.
     * @param values
     *            Values of the attributes that will be contained in the
     *            credential.
     * @param theMasterSecret
     *            Master secret object.
     */
    public CredentialCommitment(final URI ipkId, final URI theCredStructLocation,
                                final Values values,
            final IdemixSmartcardManager smartcardManager,
            final URI nameOnSmartcard, final URI smartcardUri    
        ) {
        issuerPublicKeyId = ipkId;
        credStructId = theCredStructLocation;

        CredentialStructure credStruct = (CredentialStructure) StructureStore
                .getInstance().get(credStructId);

        // dependent values for convenience
        ipk = (IssuerPublicKey) StructureStore.getInstance().get(
                issuerPublicKeyId);

        // create attributes using the given information
        attributes = credStruct.createAttributes(values);
        this.nameOnSmartcard = nameOnSmartcard;
        this.smartcardName = smartcardUri;
        this.smartcardManager = smartcardManager;
        if (credStruct.isOnSmartcard() &&
            (nameOnSmartcard == null || smartcardName == null || smartcardManager == null)) {
          throw new RuntimeException("Cred struct says credential is on smartcard, but not enough" +
          		"information is given in the Credential constructor");
        }

        if (!verifyCredential()) {
            throw new RuntimeException("Credential does not comply with "
                    + "the given structure.");
        }
    }

    /**
     * Verifies the CL signature of this credential.
     */
    public BigInteger getCommitment(BigInteger v) {
        final BigInteger[] capR = ipk.getCapR();
        final BigInteger n = ipk.getN();

        final Vector<Exponentiation> expos = new Vector<Exponentiation>();
        expos.add(new Exponentiation(ipk.getCapS(), v, n));
        // add attribute exponentiations
        for (Attribute att : attributes) {
            int keyIndex = att.getKeyIndex();
            assert (keyIndex >= 0 && keyIndex < capR.length);

            expos.add(new Exponentiation(capR[keyIndex], att.getValue(), n));
        }
        final BigInteger capZHatPrime = Utils.multiExpMul(expos, n);
        final BigInteger capZHat = capZHatPrime.multiply(computeFragmentOnSmartcard()).mod(n);

        return capZHat;
    }
    
    /**
     * Returns the value  R0^deviceSecret * S^v  with the help of the smartcard
     * If the credential does not live on a smartcard, return ONE
     * @return
     */
    public BigInteger computeFragmentOnSmartcard() {
      if(onSmartcard()) {
        return smartcardManager.computeCredentialFragment(smartcardName, nameOnSmartcard);
      } else {
        return BigInteger.ONE;
      }
    }

    /**
     * Verify a credential upon validity with respect to this credential
     * structure.
     * 
     * @param cred
     *            The credential to be analyzed.
     * @return True if the credential matches the credential structure.
     */
    private final boolean verifyCredential() {
        CredentialStructure credStruct = (CredentialStructure) StructureStore
                .getInstance().get(credStructId);
        HashSet<String> queriedAtts = new HashSet<String>();
        for (Attribute att : attributes) {
            if (credStruct.getAttributeStructure(att.getName()) != null) {
                queriedAtts.add(att.getName());
            }
        }
        for (AttributeStructure attStruct : credStruct.getAttributeStructs()) {
          if (attStruct.getIssuanceMode() != IssuanceMode.ISSUER) {
            if (!queriedAtts.contains(attStruct.getName())) {
                return false;
            }
          }
        }
        return true;
    }

    /**
     * @return Public key of the issuer of this certificate.
     */
    public final IssuerPublicKey getPublicKey() {
        return ipk;
    }

    /**
     * @return Identifier of the credential structure.
     */
    public final URI getCredStructId() {
        return credStructId;
    }
    
    public String getFullTemporaryNameForProof(String tempNameInProofSpec) {
      return getCredStructId().toString().concat(Constants.DELIMITER).concat(tempNameInProofSpec);
    }
    
    public final boolean onSmartcard() {
      return nameOnSmartcard != null;
    }

    /**
     * @return Identifier of the issuer public key.
     */
    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }

    /**
     * Returns the set of attributes of this credential. Note that the master
     * secret is not part of this set.
     * 
     * @return Set of attributes.
     */
    public final List<Attribute> getAttributes() {
        return attributes;
    }

    /**
     * @param attName
     *            Attribute's name.
     * @return Attribute or <code>null</code> if no attribute with the given
     *         name is found.
     */
    public final Attribute getAttribute(final String attName) {
        for (int i = 0; i < attributes.size(); i++) {
            final Attribute a = attributes.get(i);
            if (attName.equalsIgnoreCase(a.getName())) {
                return a;
            }
        }
        return null;
    }

    /**
     * Creates a string with a human-readable description of this object.
     * 
     * @return string containing the most important elements of this object.
     */
    public final String toStringPretty() {
        String endl = System.getProperty("line.separator");

        String s = "CredentialCommitment Information:" + endl;
        s += "\tSignature..." + endl;
        s += "\tNumber of attributes:" + attributes.size() + endl;
        s += "\t\t( Name: \tIndex: \tDataType: \tValue [ev. primes])" + endl;
        for (int i = 0; i < attributes.size(); i++) {
            Attribute a = attributes.get(i);
            assert (a != null);
            s += "\t\t" + a.toStringPretty() + endl;
        }
        s += ipk.toStringPretty();
        return s;
    }
    
    public URI getNameOnSmartcard() {
      return nameOnSmartcard;
    }
    
    public URI getSmartcardName() {
      return smartcardName;
    }
}
