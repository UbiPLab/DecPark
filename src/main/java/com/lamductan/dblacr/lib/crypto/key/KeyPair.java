package com.lamductan.dblacr.lib.crypto.key;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;

import java.io.Serializable;
import java.net.URI;

public class KeyPair implements Serializable {
    private static final long serialVersionUID = 6529685098267757695L;

    /** Private key of the . */
    private final PrivateKey privateKey;
    /** Public key of the . */
    private final PublicKey publicKey;

    /**
     * @return Private portion of the key pair.
     */
    public final PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * @return Public portion of the key pair.
     */
    public final PublicKey getPublicKey() {
        return publicKey;
    }


    /**
     * Constructor. Uses a persistent object at an indicated location to create
     * the java object.
     *
     * @param PrivateKey
     *            Private Key.
     */
    public KeyPair(final PrivateKey PrivateKey) {
        privateKey = PrivateKey;
        publicKey = privateKey.getPublicKey();
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof KeyPair)) {
            return false;
        }

        KeyPair ikp = (KeyPair) o;
        return (privateKey.equals(ikp.privateKey) && publicKey
                .equals(ikp.publicKey));
    }

    @Override
    public final int hashCode() {
        int tmp = privateKey.hashCode();
        tmp += publicKey.hashCode();
        return tmp;
    }
}
