package com.lamductan.dblacr.lib.crypto.proof.SPK.common;

import com.carrotsearch.sizeof.RamUsageEstimator;
import com.ibm.zurich.idmx.dm.MessageToSign;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.IPrivateKey;
import com.lamductan.dblacr.lib.crypto.key.IPublicKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;
import javafx.util.Pair;

import javax.xml.bind.SchemaOutputResolver;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;

public abstract class SPKProverInterface extends SPKProverVerifierInterface implements Serializable {
    private static final long serialVersionUID = 6529685098267757685L;

    protected TreeMap<String, BigInteger> freeVars;
    protected Vector<TreeMap<String, Pair<String, BigInteger>>> relations;
    protected GroupParameters gp;
    protected IPrivateKey privateKey;
    protected IPublicKey publicKey;

    protected BigInteger N;
    protected BigInteger p;
    protected BigInteger q;
    protected BigInteger g;
    protected BigInteger h;

    protected TreeMap<String, BigInteger> twList;
    protected final Pair<String, BigInteger> nullPair = createNewPair("", ZERO);

    public SPKProverInterface(SystemParameters _sp, BigInteger _nonce) {
        super(_sp, _nonce);
    }

    public SPKProverInterface(SystemParameters _sp, GroupParameters _gp, IPrivateKey _privateKey,
                              IPublicKey _publicKey, BigInteger _nonce) {
        super(_sp, _nonce);
        gp = _gp;
        publicKey = _publicKey;
        privateKey = _privateKey;

        // Get parameters
        N = publicKey.getN();
        p = privateKey.getP();
        q = privateKey.getQ();
        Modulus = DBLACRSystem.getModulus();
        g = ((PublicKey) publicKey).getG();
        h = ((PublicKey) publicKey).getH();

        freeVars = new TreeMap<>();
        inputNRelations();
    }

    protected abstract void inputNRelations();

    protected abstract void inputObjects();
    protected abstract void createRelations();
    protected abstract void inputFreeVars();
    protected abstract void inputLengthConditions();
    protected void inputFreeVarsAndLengthConditions() {
        inputFreeVars();
        freeVarNames = new TreeSet<>(freeVars.keySet());
        inputLengthConditions();
    }

    protected void inputObjectsFreeVarsRelations() {
        inputObjects();
        inputFreeVarsAndLengthConditions();
        // Compute relations
        createRelations();
        assert checkRelations();
        createCommonRelations();
    }

    public TreeMap<String, BigInteger> getFreeVars() {return freeVars;}
    public Vector<TreeMap<String, Pair<String, BigInteger>>> getRelations() {return relations;}
    public GroupParameters getGroupParameters() {return gp;}
    public IPrivateKey getPrivateKey() {return privateKey;}
    public IPublicKey getPublicKey() {return publicKey;}
    public TreeMap<String, BigInteger> getTwList() {return twList;}

    protected static Pair<String, BigInteger> createNewPair(String s, BigInteger value) {
        Pair<String, BigInteger> p = new Pair<>(s, value);
        return p;
    }

    protected boolean checkRelations() {
        BigInteger N = publicKey.getN();
        for(TreeMap<String, Pair<String, BigInteger>> row : relations) {
            BigInteger P = BigInteger.ONE;
            for(Map.Entry<String, Pair<String, BigInteger>> entry : row.entrySet()) {
                String objectName = entry.getKey();
                BigInteger Aj = objects.get(objectName);
                Pair<String, BigInteger> cell = entry.getValue();
                String freeVarName = cell.getKey();
                BigInteger value = cell.getValue();
                if (freeVars.containsKey(freeVarName) || !freeVarName.equals("")) {
                    P = P.multiply(Aj.modPow(value, Modulus)).mod(Modulus);
                }
            }
            if (!P.equals(BigInteger.ONE)) return false;
        }
        return true;
    }

    protected void createCommonRelations() {
        commonRelations = new Vector<>();
        for(TreeMap<String, Pair<String, BigInteger>> relationRow : relations) {
            TreeMap<String, Pair<String, BigInteger>> commonRelationRow = new TreeMap<>();
            for(Map.Entry<String, Pair<String, BigInteger>> relationElem : relationRow.entrySet()) {
                String objectName = relationElem.getKey();
                Pair<String, BigInteger> tmp = relationElem.getValue();
                String freeVarName = tmp.getKey();
                if (freeVars.containsKey(freeVarName)) {
                    commonRelationRow.put(objectName, createNewPair(freeVarName, ZERO));
                } else {
                    commonRelationRow.put(objectName, tmp);
                }
            }
            commonRelations.add(commonRelationRow);
        }
    }

    public TreeMapProof buildProof() {
        int nFreeVars = freeVars.size();
        int nRelations = relations.size();
        int nObjects = objects.size();

        // Compute random tw
        twList = new TreeMap<>();
        for(Map.Entry<String, BigInteger> entry : freeVars.entrySet()) {
            String freeVarName = entry.getKey();
            BigInteger tw;
            if (bitLengthLowerBounds.containsKey(freeVarName))
                tw = Utils.computeRandomNumber(bitLengthUpperBounds.get(freeVarName) - 2);
            else tw = Utils.computeRandomNumber(Modulus, sp);
            twList.put(freeVarName, tw);
        }

        // Compute tValues B[i]
        Vector<BigInteger> bList = new Vector<>();
        for(int i = 0; i < nRelations; ++i) {
            TreeMap<String, Pair<String, BigInteger>> relation = relations.get(i);
            BigInteger B = BigInteger.ONE;
            for(Map.Entry<String, Pair<String, BigInteger>> relationElem : relation.entrySet()) {
                String objectName = relationElem.getKey();
                BigInteger Aj = objects.get(objectName);
                Pair<String, BigInteger> tmp = relationElem.getValue();
                String freeVarName = tmp.getKey();
                if (twList.containsKey(freeVarName)) {
                    BigInteger tw = twList.get(freeVarName);
                    B = B.multiply(Aj.modPow(tw, Modulus)).mod(Modulus);
                }
            }
            bList.add(B);
        }

        // Compute challenge Fiat-Shamir Heuristic
        BigInteger challenge = computeChallenge(sp, AuxUtils.treeMapToList(objects), bList, nonce);

        // Compute sValues
        for(Map.Entry<String, BigInteger> entry : twList.entrySet()) {
            String freeVarName = entry.getKey();
            BigInteger tw = entry.getValue();
            BigInteger xw = freeVars.get(freeVarName);
            BigInteger sw = tw.subtract(challenge.multiply(xw));
            if (bitLengthLowerBounds.containsKey(freeVarName)) {
                int lowerBoundBitLenght = bitLengthLowerBounds.get(freeVarName);
                sw = sw.add(challenge.shiftLeft(lowerBoundBitLenght));
            }
            sValues.put(freeVarName, sw);
        }
//        System.out.println("先为r1,r2,p,q,a产生随机数：");
//        for (Map.Entry<String, BigInteger> entry : twList.entrySet()) {
//            System.out.println("key = " + entry.getKey() + ", value = " + entry.getValue());
//        }
//        System.out.println("t 长度:"+bList.size());
//        System.out.println("输出t");
//        for (Map.Entry<String, BigInteger> entry : twList.entrySet()) {
//            System.out.println("key = " + entry.getKey() + ", value = " + entry.getValue());
//            break;
//        }
//        System.out.println("challenge:"+challenge);
//        // 1. entrySet遍历，在键和值都需要时使用（最常用）
//        System.out.println("svalue 长度:" + sValues.size());
//        System.out.println("输出svalue");
//        for (Map.Entry<String, BigInteger> entry : sValues.entrySet()) {
//            System.out.println("key = " + entry.getKey() + ", value = " + entry.getValue());
//            break;
//        }
//        System.out.println("objects 长度:"+objects.size());
//        System.out.println("输出objects");
//        for (Map.Entry<String, BigInteger> entry : objects.entrySet()) {
//            System.out.println("key = " + entry.getKey() + ", value = " + entry.getValue());
//            break;
//        }



        // Build Proof
        TreeMapProof proof = new TreeMapProof(challenge, sValues, bList, objects, freeVarNames,
                bitLengthLowerBounds, bitLengthUpperBounds, commonRelations, Modulus);

        //System.out.println("Created SPKProof");
        return proof;
    }

    public static BigInteger computeChallenge(SystemParameters sp, Vector<BigInteger> commons,
                                              Vector<BigInteger> tValues, BigInteger nonce) {
        Vector<BigInteger> list = new Vector<>();
        list.addAll(commons);
        list.addAll(tValues);
        BigInteger context = DBLACRSystem.getInstance().getContext();
        TreeMap<String, MessageToSign> messages = new TreeMap<>();
        try {
            BigInteger challenge = Utils.computeChallenge(sp, context, list, nonce, messages.values());
            return challenge;
        } catch (Exception e) {
            e.printStackTrace();
            return ONE;
        }
    }

    protected void createRelations(int n) {
        relations = new Vector<>();
        for(int i = 0; i < n; ++i) {
            TreeMap<String, Pair<String, BigInteger>> relationRow = new TreeMap<>();
            relations.add(relationRow);

        }
    }

}
