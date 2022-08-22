package com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType21.CategoryType21SPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType22.CategoryType22SPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23.CategoryType23Proof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.category.categoryType2.categoryType23.CategoryType23SPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.TreeMap;
import java.util.Vector;

public class CategoryType2SPKProver {
    SystemParameters sp;
    GroupParameters gp;
    PrivateKey privateKey;
    PublicKey publicKey;
    Ticket tau;
    Ticket tau_i;
    BigInteger g1;
    BigInteger g2;
    int score;
    BigInteger delta;
    int keppa;
    CLSignature clSignature;
    Pair<Integer, TreeMap<Integer, CLSignature>> threshold;
    Pair<String, Integer> thresholdLimit;

    CategoryType21SPKProver categoryType21SPKProver;
    CategoryType22SPKProver categoryType22SPKProver;
    CategoryType23SPKProver categoryType23SPKProver;

    public CategoryType2SPKProver(SystemParameters _sp, GroupParameters _gp, PrivateKey _privateKey,
                                  PublicKey _publicKey, Ticket _tau, Ticket _tau_i, BigInteger _g1,
                                  BigInteger _g2, int _score,
                                  BigInteger _delta, int _keppa, CLSignature _clSignature,
                                  Vector<BigInteger> _auxList, Vector<BigInteger> _gammaTildeList,
                                  Pair<Integer, TreeMap<Integer, CLSignature>> _threshold,
                                  Pair<String, Integer> _thresholdLimit) {
        sp = _sp;
        gp = _gp;
        privateKey = _privateKey;
        publicKey = _publicKey;
        tau = _tau;
        tau_i = _tau_i;
        g1 = _g1;
        g2 = _g2;
        score = _score;
        delta = _delta;
        keppa = _keppa;
        clSignature = _clSignature;
        threshold = _threshold;
        thresholdLimit = _thresholdLimit;

        categoryType21SPKProver = new CategoryType21SPKProver(
                sp, gp, privateKey, publicKey, tau, tau_i, g1, g2,
                score, delta, keppa, _auxList, _gammaTildeList);

        Vector<BigInteger> witnesses = new Vector<>();
        witnesses.add(BigInteger.valueOf(keppa));
        witnesses.add(delta);
        categoryType22SPKProver = new CategoryType22SPKProver(sp, witnesses, clSignature);
    }


    public IProof buildProof() {
        TreeMapProof categoryProof1 = categoryType21SPKProver.buildProof();
        TreeMapProof categoryProof2 = categoryType22SPKProver.buildProof();

        TreeMap<String, BigInteger> categoryType23SPKProverInput = createCategoryType23SPKProverInput();
        categoryType23SPKProver = new CategoryType23SPKProver(sp, gp, privateKey, publicKey,
                categoryType23SPKProverInput);
        CategoryType23Proof categoryProof3 = categoryType23SPKProver.buildProof();
        return new CategoryType2Proof(categoryProof1, categoryProof2, categoryProof3);
    }

    private TreeMap<String, BigInteger> createCategoryType23SPKProverInput() {
        TreeMap<String, BigInteger> categoryType23SPKProverInput = new TreeMap<>();
        TreeMap<String, BigInteger> objectsProof1 = categoryType21SPKProver.getObjects();
        TreeMap<String, BigInteger> objectsProof2 = categoryType22SPKProver.getObjects();
        BigInteger Modulus = publicKey.getModulus();

        categoryType23SPKProverInput.put("keppa", BigInteger.valueOf(keppa));
        categoryType23SPKProverInput.put("delta", delta);

        categoryType23SPKProverInput.put("U4Inverse", objectsProof1.get("U4Inverse").multiply(g1).mod(Modulus));
        categoryType23SPKProverInput.put("U5Inverse", objectsProof1.get("U5Inverse"));
        categoryType23SPKProverInput.put("alpha3", categoryType21SPKProver.getAlpha3());
        categoryType23SPKProverInput.put("alpha4", categoryType21SPKProver.getAlpha4());
        categoryType23SPKProverInput.put("g1", g1);
        categoryType23SPKProverInput.put("g2", g2);

        categoryType23SPKProverInput.put("T1Inverse", objectsProof2.get("T0Inverse"));
        categoryType23SPKProverInput.put("T2Inverse", objectsProof2.get("T1Inverse"));
        Vector<BigInteger> r = categoryType22SPKProver.getR();
        categoryType23SPKProverInput.put("r1", r.get(0));
        categoryType23SPKProverInput.put("r2", r.get(1));
        categoryType23SPKProverInput.put("g", objectsProof2.get("g"));
        categoryType23SPKProverInput.put("h", objectsProof2.get("h"));
        categoryType23SPKProverInput.put("n", categoryType22SPKProver.getN());

        return categoryType23SPKProverInput;
    }

    public BigInteger getC() {return categoryType21SPKProver.getC(); }
    public BigInteger getCTilde() {return categoryType21SPKProver.getCTilde();}

    public BigInteger getGamma() { return categoryType21SPKProver.getGamma(); }
    public BigInteger getGammaTilde() { return categoryType21SPKProver.getGammaTilde(); }
}
