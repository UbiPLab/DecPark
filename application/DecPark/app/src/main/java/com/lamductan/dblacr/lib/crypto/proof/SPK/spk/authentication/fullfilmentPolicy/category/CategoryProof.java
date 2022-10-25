package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category;

import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.CategoryType2Proof;
import javafx.util.Pair;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Vector;

public class CategoryProof implements IProof, Serializable{
    private static final long serialVersionUID = 6529685098267757678L;

    private BigInteger modulus;
    private Vector<BigInteger> auxMeritList;
    private Vector<BigInteger> auxBlackList;
    private Vector<Pair<TreeMapProof, CategoryType2Proof>> proofMeritList;
    private Vector<Pair<TreeMapProof, CategoryType2Proof>> proofBlackList;
    private TreeMapProof proofFinal;

    public CategoryProof() {
        auxMeritList = new Vector<>();
        auxBlackList = new Vector<>();
        proofMeritList = new Vector<>();
        proofBlackList = new Vector<>();
        proofFinal = new TreeMapProof();
    }

    public CategoryProof(Vector<BigInteger> _auxMeritList, Vector<BigInteger> _auxBlackList,
                         Vector<Pair<TreeMapProof, CategoryType2Proof>> _proofMeritList,
                         Vector<Pair<TreeMapProof, CategoryType2Proof>> _proofBlackList,
                         TreeMapProof _proofFinal) {
        auxMeritList = _auxMeritList;
        auxBlackList = _auxBlackList;
        proofMeritList = _proofMeritList;
        proofBlackList = _proofBlackList;
        proofFinal = _proofFinal;
    }

    public Vector<BigInteger> getAuxMeritList() {return auxMeritList;}
    public Vector<BigInteger> getAuxBlackList() {return auxBlackList;}
    public Vector<Pair<TreeMapProof, CategoryType2Proof>> getProofMeritList() {return proofMeritList;}
    public Vector<Pair<TreeMapProof, CategoryType2Proof>> getProofBlackList() {return proofBlackList;}
    public TreeMapProof getProofFinal() {return proofFinal;}

    @Override
    public BigInteger getModulus() {
        return null;
    }
}
