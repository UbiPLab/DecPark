//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.api;

import java.net.URI;

import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.issuance.Message;

/**
 *
 */
public interface RecipientInterface {

    /**
     * @param message0
     *            Message from the verifier.
     * @return Message containing the proof about the hidden and committed
     *         attributes sent to the Issuer.
     */
    public abstract Message round1(final Message message0);
    public abstract Message round1(final Message message0, final URI nameOfSmartcard, final URI credNameOnSmartcard);

    /**
     * Called with the second protocol flow as input, outputs the Credential.
     * This is the last step of the issuance protocol, where the Recipient
     * verifies that the signature is valid and outputs it.
     * 
     * @param msg
     *            the second flow of the protocol, a message from the Issuer
     * @return the Credential, if it's valid, null otherwise.
     */
    public abstract Credential round3(final Message msg);

}