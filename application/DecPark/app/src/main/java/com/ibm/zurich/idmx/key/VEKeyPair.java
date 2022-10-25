//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.key;

/**
 * Key pair object for verifiable encryption.
 */
public final class VEKeyPair {

    /** Private key of the key pair. */
    private final VEPrivateKey vePrivateKey;
    /** Public key of the key pair. */
    private final VEPublicKey vePublicKey;

    /**
     * Constructor.
     */
    private VEKeyPair() {
        vePrivateKey = new VEPrivateKey(null, null);
        vePublicKey = vePrivateKey.getPublicKey();
    }

    /**
     * @return the privKey
     */
    public synchronized final VEPrivateKey getPrivKey() {
        return vePrivateKey;
    }

    /**
     * @return the pubKey
     */
    public synchronized final VEPublicKey getPubKey() {
        return vePublicKey;
    }
}
