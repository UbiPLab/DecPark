//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import com.ibm.zurich.idmx.key.IssuerPublicKey;
import com.ibm.zurich.idmx.showproof.Identifier;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * This predicate expresses proofs of knowledge about credentials. It uses a
 * credential and a map from attribute names to identifiers to determine over
 * which attributes it should issue equality proofs.
 */
public abstract class CredentialPredicate extends Predicate {

    /** Identifier of the issuer public key associated with this predicate. */
    private final URI issuerPublicKeyId;
    /** Identifier of the credential structure associated to this predicate. */
    private final URI credStructId;
    /** Temporary name of the credential as used in the proof specification. */
    protected final String credName;
    /** Temporary name of the secret as used in the proof specification. */
    private final String tempSecretName;

    /** Map from attribute names to identifiers used in this predicate. */
    private HashMap<String, Identifier> attToIdentifierMap;

    /**
     * Constructor.
     * 
     * @param ipkId
     *            Identifier of the issuer public key associated to this
     *            predicate.
     * @param theCredStructId
     *            Location of the credential structure associated to this
     *            predicate.
     * @param theCredName
     *            Temporary name of the credential as used in the proof
     *            specification.
     * @param attToIds
     *            Map from attribute names to identifiers used in this
     *            predicate.
     */
    public CredentialPredicate(final URI ipkId, final URI theCredStructId,
            final String theCredName, final String theSecretTempName,
            final HashMap<String, Identifier> attToIds, PredicateType pt) {
        super(pt);
        issuerPublicKeyId = ipkId;
        credStructId = theCredStructId;
        credName = theCredName;
        tempSecretName = theSecretTempName;
        attToIdentifierMap = attToIds;
    }

    /**
     * @param attName
     *            Name of the attribute associated with some identifier.
     * @return Identifier associated with the given <code>attName</code>.
     */
    public final Identifier getIdentifier(final String attName) {
        return attToIdentifierMap.get(attName);
    }
    
    public final Map<String, Identifier> getIdentifierMap() {
      return attToIdentifierMap;
    }
    
    public final boolean containsIdentifier(final String attName) {
      return attToIdentifierMap.containsKey(attName);
    }

    /**
     * @return Temporary name for the credential associated with this predicate.
     *         The name consists of a concatenation of the structure location
     *         and the credential name given in the proof specification.
     */
    public String getTempCredName() {
        return credStructId.toString().concat(Constants.DELIMITER)
                .concat(credName);
    }
    
    public String getTempSecretName() {
      return tempSecretName;
    }

    /**
     * @return Credential structure location of the credential associated with
     *         this predicate.
     */
    public final URI getCredStructLocation() {
        return credStructId;
    }

    /**
     * @return Issuer public key identifier of the credential associated with
     *         this predicate.
     */
    public final URI getIssuerPublicKeyId() {
        return issuerPublicKeyId;
    }

    /**
     * Convenience method.
     * 
     * @return Issuer public key object.
     */
    public final IssuerPublicKey getIssuerPublicKey() {
        return (IssuerPublicKey) StructureStore.getInstance().get(
                issuerPublicKeyId);
    }

    abstract protected String getNameForStringPretty();
    
    /**
     * @return Human-readable string of this predicate.
     */
    public final String toStringPretty() {
        String s = getNameForStringPretty() + "( " + credStructId + Constants.DELIMITER
                + credName + ")\n";
        Iterator<String> iterator = attToIdentifierMap.keySet().iterator();
        while (iterator.hasNext()) {
            String attName = iterator.next();
            s += "\t(" + attName + " -> "
                    + attToIdentifierMap.get(attName).getName() + ")\n";
        }
        return s;
    }

    @Override
    public String toString() {
      return "CredentialPredicate [issuerPublicKeyId=" + issuerPublicKeyId + ", credStructId="
          + credStructId + ", credName=" + credName + ", tempSecretName=" + tempSecretName
          + ", attToIdentifierMap=" + attToIdentifierMap + "]";
    }
    
    @Override
    public BigInteger generateHash() {
      BigInteger items[] = new BigInteger[attToIdentifierMap.size()*2+4];
      items[0] = Utils.hashString(issuerPublicKeyId.toString(), 256);
      items[1] = Utils.hashString(credStructId.toString(), 256);
      items[2] = Utils.hashString(credName, 256);
      if(tempSecretName!=null) {
        items[3] = Utils.hashString(tempSecretName, 256);
      } else {
        items[3] = BigInteger.ZERO;
      }
      int i=0;
      for(Entry<String, Identifier> id: attToIdentifierMap.entrySet()) {
        items[4+2*i] = Utils.hashString(id.getKey(), 256);
        items[4+2*i+1] = Utils.hashString(id.getValue().getName(), 256);
        ++i;
      }
      return Utils.hashOf(256, items);
    }
}
