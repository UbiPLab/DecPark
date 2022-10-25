package com.lamductan.dblacr.lib.crypto.nym;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;

public class Pseudonym implements Serializable {
    private static final long serialVersionUID = 6529685098267757694L;

    private final GroupParameters gp;
    private final URI groupParameters;
    private final BigInteger randomizer;

    public BigInteger getRandomizer() {
        return randomizer;
    }

    public GroupParameters getGroupParameters() {
        return gp;
    }

    public URI getGroupParametersLocations() {
        return groupParameters;
    }

    public Pseudonym(URI smartcardUri, URI groupParameters, BigInteger randomizer) {
        this.groupParameters = groupParameters;
        this.randomizer = randomizer;
        this.gp = (GroupParameters) StructureStore.getInstance().get(groupParameters);
    }
}
