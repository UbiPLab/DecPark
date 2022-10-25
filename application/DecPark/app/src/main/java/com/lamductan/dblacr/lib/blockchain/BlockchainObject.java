package com.lamductan.dblacr.lib.blockchain;

import java.io.Serializable;

public abstract class BlockchainObject implements Serializable {
    private static final long serialVersionUID = 6529685098267757682L;

    public boolean uploadToBlockchain() {
        return true;
    }
    public String getType() {return "";}
}
