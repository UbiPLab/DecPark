package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23;

import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;

public class CategoryType23Proof extends TreeMapProof implements Serializable {
    private static final long serialVersionUID = 652968509826775768L;
    private Vector<BigInteger> listMod;

    public CategoryType23Proof(BigInteger challenge, TreeMap<String, BigInteger> sValues,
                               Vector<BigInteger> bList, TreeMap<String, BigInteger> objects,
                               TreeSet<String> freeVarNames, TreeMap<String, Integer> bitLengthLowerBounds,
                               TreeMap<String, Integer> bitLengthUpperBounds,
                               Vector<TreeMap<String, Pair<String, BigInteger>>> commonRelations,
                               Vector<BigInteger> _listMod) {
        super(challenge, sValues, bList, objects, freeVarNames, bitLengthLowerBounds, bitLengthUpperBounds,
              commonRelations);
        listMod = _listMod;
    }


    @Override
    public BigInteger getModulus() {
        return null;
    }

    public Vector<BigInteger> getListMod() {return listMod;}
}
