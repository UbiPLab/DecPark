package com.lamductan.dblacr.lib.crypto.key;

import com.ibm.zurich.idmx.key.Npq;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import java.security.SecureRandom;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PrivateKey implements IPrivateKey, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -3668863181505529062L;

    /** Logger. */
    private static Logger log = Logger.getLogger(PrivateKey.class
            .getName());

    /** Location of the issuer public key. */
    protected URI publicKeyLocation;

    /** Safe prime <tt>p = 2*p' + 1</tt>. */
    private final BigInteger p;
    /** Safe prime <tt>q = 2*q' + 1</tt>. */
    private final BigInteger q;
    /** Modulus <tt>n = p*q</tt>. */
    private final BigInteger n;
    /** Safe prime <tt>p'</tt>. */
    private final BigInteger pPrime;
    /** Safe prime <tt>q'</tt>. */
    private final BigInteger qPrime;
    private PublicKey publicKey;

    /**
     * Constructor.
     *
     * @param sp
     *            System parameter.
     */
    public PrivateKey(final SystemParameters sp) {
        super();

//        Date start = new Date();
//        log.info("Generating new private key");
        long starttime = System.currentTimeMillis();
        final Npq theNpq = getNPQ(sp.getL_n(), sp.getL_pt());
        n = theNpq.getN();
        p = theNpq.getP();
//        System.out.println("p:"+p);
        q = theNpq.getQ();
//        System.out.println("q:"+q);
        long endtime = System.currentTimeMillis();
        System.out.println("Generate npq in"+ 1.0 * (endtime - starttime)  + "ms");
        PublicKey publicKey;

        // p = 2*p' + 1, q = 2*q' - 1 <-> p' = (p - 1)/2, q' = (q - 1)/2
        pPrime = p.subtract(BigInteger.ONE).shiftRight(1);
        qPrime = q.subtract(BigInteger.ONE).shiftRight(1);

//        Date stop = new Date();

//        log.info("\nPrivateKey: start: " + start.toString() + " end: "
//                + stop.toString());
    }

    /**
     * Constructor.
     *
     * @param thePublicKeyLocation
     *            Location of the issuer public key.
     * @param theN
     *            Modulus.
     * @param theP
     *            <tt>p</tt>.
     * @param thePPrime
     *            <tt>p'</tt>.
     * @param theQ
     *            <tt>q</tt>.
     * @param theQPrime
     *            <tt>q'</tt>.
     */
    public PrivateKey(final URI thePublicKeyLocation,
                      final BigInteger theN, final BigInteger theP,
                      final BigInteger thePPrime, final BigInteger theQ,
                      final BigInteger theQPrime) {
        publicKeyLocation = thePublicKeyLocation;
        n = theN;
        p = theP;
        pPrime = thePPrime;
        q = theQ;
        qPrime = theQPrime;
    }

    public void setPublicKey(PublicKey _publicKey) {
        publicKey = _publicKey;
    }

    /**
     * @return public key location.
     */
    public URI getPublicKeyLocation() {
        return publicKeyLocation;
    }

    /**
     * @return <tt>p</tt>.
     */
    public final BigInteger getP() {
        return p;
    }

    /**
     * @return <tt>q</tt>.
     */
    public final BigInteger getQ() {
        return q;
    }

    /**
     * @return <tt>n</tt>.
     */
    public final BigInteger getN() {
        return n;
    }

    /**
     * @return <tt>p'</tt>.
     */
    public final BigInteger getPPrime() {
        return pPrime;
    }

    /**
     * @return <tt>q'</tt>.
     */
    public final BigInteger getQPrime() {
        return qPrime;
    }

    /**
     * Computes <tt>(p')*(q')</tt>.
     *
     * @return product <tt>(p')*(q')</tt>.
     */
    public final BigInteger computeQPrimePPrime() {
        // p = 2*p' + 1, q = 2*q' + 1
        return getPPrime().multiply(getQPrime());
    }

    @Override
    public final boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof PrivateKey)) {
            return false;
        }

        PrivateKey ikp = (PrivateKey) o;
        if (this == ikp) {
            return true;
        }
        return (publicKeyLocation.equals(ikp.publicKeyLocation)
                && p.equals(ikp.p) && pPrime.equals(ikp.pPrime)
                && q.equals(ikp.q) && qPrime.equals(ikp.qPrime) && n
                .equals(ikp.n));
    }

    @Override
    public final int hashCode() {
        int tmp = publicKeyLocation.hashCode();
        tmp += n.hashCode();
        tmp += p.hashCode();
        tmp += pPrime.hashCode();
        tmp += q.hashCode();
        tmp += qPrime.hashCode();
        return tmp;
    }

    /**
     * To return a triple of n, p, q such that n = p*q and p = 2p' + 1, q = 2q'
     * + 1 with p, q, p', q' prime.
     *
     * @param lengthMod
     *            length of modulus
     * @param primeCertainty
     *            probability for prime testing.
     *
     * @return an array of n, p, q.
     */
    public static final Npq getNPQ(final int lengthMod, final int primeCertainty) {

        BigInteger _p;
        BigInteger _n;
        BigInteger _q;
        SecureRandom secureRandom = new SecureRandom();
        do {

//            _p = Utils.computeSafePrime(lengthMod / 2, primeCertainty);

             _p = new BigInteger(1024, 100, secureRandom);
            log.log(Level.FINE, ".");
            do {
//                _q = Utils.computeSafePrime(lengthMod - (lengthMod / 2),
//                        primeCertainty);
                 _q = new BigInteger(1024, 100, secureRandom);
                log.log(Level.FINE, ".");
                // make sure p and q are unequal
            } while (_p.equals(_q));

            _n = _p.multiply(_q);
            log.log(Level.FINE, ".");

        } while (_n.bitLength() != lengthMod);

        return new Npq(_n, _p, _q);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getModulus() {
        return publicKey.getModulus();
    }
    public BigInteger getG() {return publicKey.getG();}
    public BigInteger getH() {return publicKey.getH();}
}
