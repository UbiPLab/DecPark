package com.lamductan.dblacr.lib.utils;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.system.DBLACRSystem;
import javafx.util.Pair;

import java.io.File;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Vector;

public class AuxUtils {

    public static boolean checkFileExists(String filename) {
        File f = null;
        boolean bool = false;
        try {
            f = new File(filename);
            bool = f.exists();
        } catch(Exception e) {
            e.printStackTrace();
        }
        return bool;
    }

    public static Vector<BigInteger> treeMapToList(TreeMap<String, BigInteger> treeMap) {
        return new Vector<>(treeMap.values());
    }

    public static BigInteger product(Vector<BigInteger> constants, BigInteger Modulus) {
        Iterator<BigInteger> iterator = constants.iterator();

        BigInteger product;
        for(product = BigInteger.ONE; iterator.hasNext();
            product = product.multiply((BigInteger)iterator.next()).mod(Modulus)) {
            ;
        }

        return product;
    }

    public static Vector<BigInteger> getListN(Vector<PublicKey> listPublicKey) {
        Vector<BigInteger> listN = new Vector<>();
        for(int i = 0; i < listPublicKey.size(); ++i) {
            listN.add(listPublicKey.get(i).getN());
        }
        return listN;
    }

    public static BigInteger sum(Vector<BigInteger> listBigInteger) {
        BigInteger res = BigInteger.ZERO;
        for(BigInteger bigInteger : listBigInteger) res = res.add(bigInteger);
        return res;
    }

    public static Pair<BigInteger, BigInteger> computeRandomInvertible(int l_e, BigInteger n, BigInteger phiN) {
        while (true) {
            BigInteger x = Utils.genPrime(l_e, 1);
            try {
                BigInteger xInversePhiN = x.modInverse(phiN);
                return new Pair(x, xInversePhiN);
                //if (x.bitLength() == l_e) return new Pair(x, xInversePhiN);
                //else continue;
            } catch (Exception e) {}
            continue;
        }
    }

    public static BigInteger computeModulus(SystemParameters sp) {
        System.out.println("ln = " + sp.getL_n());
        BigInteger p = computeSafePrime(sp.getL_n()/2, sp.getL_pt());
        BigInteger q = computeSafePrime(sp.getL_n()/2, sp.getL_pt());
        System.out.println("p,q bitlength: " + p.bitLength() + " " + q.bitLength());
        return p.multiply(q);
    }

    public static BigInteger computeSafePrime(int bitLength, int primeCertainty) {
        BigInteger p;
        do {
            p = Utils.computeSafePrime(bitLength, primeCertainty);
        } while(p.bitLength() != bitLength);
        return p;
    }

    public static BigInteger computeRandomNumber(int bitLength) {
        BigInteger r;
        do {
            r = Utils.computeRandomNumber(bitLength);
        } while(r.bitLength() != bitLength);
        return r;
    }

    public static BigInteger computeGeneratorQuadraticResidueInvertibleWithModulus(BigInteger n, SystemParameters sp) {
        BigInteger Modulus = DBLACRSystem.getModulus();
        BigInteger qr, x;
        do {
            qr = Utils.computeRandomNumber(n, sp);
            qr = qr.modPow(Utils.TWO, n);
            x = qr.subtract(BigInteger.ONE);
        } while(qr.equals(BigInteger.ONE) || !n.gcd(x).equals(BigInteger.ONE)
        || !Modulus.gcd(x).equals(BigInteger.ONE));

        return qr;
    }

    public static void printRelations(Vector<TreeMap<String, Pair<String, BigInteger>>> relations) {
        for(TreeMap<String, Pair<String, BigInteger>> row : relations) {
            System.out.println(row);
        }
        System.out.println();
    }
}
