package com.lamductan.dblacr.lib.crypto.key;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;

/**
 * The 's public key for the CL-signature scheme. In addition to the key
 * itself, this object also contains the epochLength (which defines intervals
 * when credentials expire), and a unique identifier to identify the key.
 *
 * @see PrivateKey
 * @see KeyPair
 */
public final class PublicKey implements IPublicKey, Serializable{


    /**
     *
     */
    private static final long serialVersionUID = 2130192696934134618L;

    /** Logger. */
    private static Logger log = Logger.getLogger(PublicKey.class
            .getName());

    /** Location of the group parameters corresponding to this key. */
    private URI groupParametersLocation;
    private GroupParameters gp;

    /** <tt>S</tt> as specified in ... */
    private final BigInteger capS;
    /** <tt>Z</tt> as specified in ... */
    private final BigInteger capZ;
    /** Bases for the messages. */
    private final BigInteger[] capR;
    /** Modulus. */
    private final BigInteger N;
    /** Length of an epoch. */
    private final int epochLength;

    /** Modulus of all computation **/
    private final BigInteger g;
    private final BigInteger h;
    private final BigInteger Modulus;

    private final BigInteger n1;
    private final BigInteger h1;
    private final BigInteger h2;

    public PublicKey(SystemParameters sp, GroupParameters _gp, final PrivateKey privKey,
              final int nbrOfAttrs, final int theEpochLength) {

        if (privKey == null || nbrOfAttrs < sp.getL_res()) {
            throw new IllegalArgumentException();
        }

        if (theEpochLength < 1) {
            // case when no epoch is used
            log.log(Level.FINE, "No epoch used in  public key.");
            epochLength = 0;
        } else {
            epochLength = theEpochLength;
        }
        gp = _gp;

//        log.log(Level.INFO, "Generating public key");
//        Date start = new Date();
        N = privKey.getN();
        capS = Utils.computeGeneratorQuadraticResidue(privKey.getN(), sp);
        // p'*q'
        final BigInteger productPQprime = privKey.getPPrime().multiply(
                privKey.getQPrime());

        // upper = p'q'-1 - 2
        final BigInteger upper = productPQprime.subtract(BigInteger.ONE)
                .subtract(Utils.TWO);
        // capZ: rand num range [2 .. p'q'-1]. we pick capZ in [0..upper] and
        // then add 2.
        final BigInteger x_Z = Utils.computeRandomNumber(upper, sp).add(
                Utils.TWO);
        capZ = capS.modPow(x_Z, privKey.getN());//capS ^ x_Z % N

        // capR[]
        capR = new BigInteger[nbrOfAttrs];
        for (int i = 0; i < nbrOfAttrs; i++) {
            // pick x_R as rand num in range [2 .. p'q'-1]
            final BigInteger x_R = Utils.computeRandomNumber(upper, sp).add(
                    Utils.TWO);
            capR[i] = capS.modPow(x_R, privKey.getN());
        }
//        Date stop = new Date();

//        log.log(Level.INFO, "\nIssuePublicKey: start: " + start.toString()
//                + " end: " + stop.toString());
        Modulus = DBLACRSystem.getModulus();
        g = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
//        g = new BigInteger("5964624486856407129796763686065777534547362902027820868116492166593625372896105751045448438478815931921386733625608758174092432892497503144902654067717442583036024468798341080142444692259395968199051880378121300393828509945702234879679530971663208243965823831508381281896956204846876263708996970813181878531214866373183320713524288254585896102036799071168852236104841293987113861832613458786710615582027056434295497674212035430128006636839892474060878337215006780849508123542506240264449303981602870962061652393402442549649371166997975645317860126378224353455416547296658982525386885255173168136727923474596283166413");
//        System.out.println("g:"+g);
        h = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
//        h = new BigInteger("13702289949286103594248633386269800121705542720013974554167375845375862205014231505611328393171876965708969075059172125258581604563423308039526139890972409001842736256592507829136977105988759187124315042160682009101795071884815722888911363159142207679889893895891728529469939186982011173057591065706734682055691814807283344666234573866511801795078466007581532577939407808471379622326433275907452964116445069967306425931380678037616298698794789515321246299707618086619215848273469654165686501031307072758773257046555123373966335173520596512598966052563399068139561745217533204967975239135047603856959665069095499569728");
//        System.out.println("h:"+h);
        n1 = AuxUtils.computeModulus(sp);
//        n1 = new BigInteger("16516990950795409533075471419105383011487853600765106404535289823044358838312437056843770880312440851132008702598243382930424497240852444819841285421485231122537899595419681448506969836568306104721640314929754592470131298545932554258766436471228919060121252126215964152783676313303207791502792571317381884449403830848434458623533775461895367884855266248088661568349881978485458750451124524794395286430752828926615885509829730036465271865932635246358045700526773125825291462648208491651618058664097044884080205213644418917939331149803016096800796602092438890711843303143558610386765918109088815368718128359460200498797");
//        System.out.println("n1:"+n1);
        h1 = Utils.computeGeneratorQuadraticResidue(n1, sp);
//        h1 = new BigInteger("10629935104631070743242064656272556882638737268676348392690364112219490879559852114704953653296488385967124649611787525478257753662859685672751532069619791978333887201283350544273038573033988277880166958496013870894182575043703767100491753910699250869628987059004977389243149545237623584260043492574974638066218253968161801614979868226627691954155586893568951407572497224269397831609331639671899495537201429404361008693328167762152347185086825198795731125677659433259896054917443909416945615188559257055701753413916662682623209127103340013070383378453430948160943083337501270370290189481330516518772082594303123826508");
//        System.out.println("h1:"+h1);
        h2 = Utils.computeGeneratorQuadraticResidue(n1, sp);
//        h2 = new BigInteger("11616569574752936619708999727311766616890572260280812394027291414786584778409903692436142550446854980494394979925892939156420660020402703929158783302055510160378038432127811580500501289218272508114029764361802202617181097575984336061382812284831979732231387691838115872004040248821201140553626832123056130857264355490202290501014557948781859058731960126865658885682377324852537016712890566410773360950130556324554489596577588974945575142289190803167323480017384107759455841041679193566520411870717708788402782160907883405515646629116431998213491592894096453268947101257401706489157434623865042732220024726549941000371");
//        System.out.println("h2:"+h2);

    }

    /**
     * @return Group parameters.
     */
    public GroupParameters getGroupParams() {
        return gp;
    }

    /**
     * @return Group parameters location.
     */
    public final URI getGroupParamsLocation() {
        return groupParametersLocation;
    }

    /**
     * @return True if this PublicKey has the epoch length field set.
     */
    public boolean hasEpoch() {
        if (epochLength > 0) {
            return true;
        }

        return false;
    }

    /**
     * @return Epoch length (in seconds) if this public key has the epoch field
     *         set. If not, an {@link IllegalArgumentException} is thrown.
     */
    public int getEpochLength() {
        if (!hasEpoch()) {
            throw new IllegalArgumentException("Requesting epochLength from "
                    + "PublicKey which dosen't have one.");
        }
        return epochLength;
    }

    /**
     * @return Current epoch. Computes an integer value representing the current
     *         epoch. The current epoch is computed as floor(
     *         currentTime/epochLength), where the currentTime and epochLength
     *         are in seconds.
     */
    public BigInteger computeCurrentEpoch() {
        double localEpochLength = (double) getEpochLength();
        double currentTime = ((double) System.currentTimeMillis()) / 1000.0;
        BigInteger currentEpoch = BigInteger.valueOf((long) Math
                .floor(currentTime / localEpochLength));
        return currentEpoch;
    }

    /**
     * @return Number of attributes which may be signed by this public key. (the
     *         dimension of the message space in the CL signature scheme)
     */
    public int getMaxNbrAttrs() {
        return capR.length;
    }

    /**
     * @return Randomization base <tt>S</tt>.
     */
    public BigInteger getCapS() {
        return capS;
    }

    /**
     * @return Signature element <tt>Z</tt>.
     */
    public BigInteger getCapZ() {
        return capZ;
    }

    /**
     * @return Array of attribute bases <tt>R_i</tt>.
     */
    public BigInteger[] getCapR() {
        return capR;
    }

    /**
     * @return Modulus <tt>n</tt>.
     */
    public BigInteger getN() {
        return N;
    }

    public BigInteger getModulus() {return Modulus;}

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String endl = System.getProperty("line.separator");
        String s = "'s public key: " + endl;
        s += "\tNumber of bases: " + capR.length + endl;
        s += "\tn, capS, capZ : " + Utils.logBigInt(N) + ", "
                + Utils.logBigInt(capS) + ", " + Utils.logBigInt(capZ) + endl;
        s += "\tR[" + 0 + "..." + (capR.length - 1) + "]: ";
        for (int i = 0; i < capR.length; i++) {
            s += Utils.logBigInt(capR[i]);
            if (i < capR.length - 1) {
                s += ", ";
            }
        }

        return s;
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof PublicKey)) {
            return false;
        }

        PublicKey ikp = (PublicKey) o;
        if (this == ikp) {
            return true;
        }
        return (capS.equals(ikp.capS) && capZ.equals(ikp.capZ)
                && N.equals(ikp.N) && Arrays.equals(capR, ikp.capR));
    }

    @Override
    public int hashCode() {
        int tempHashCode = 0;
        tempHashCode += capS.hashCode();
        tempHashCode += capZ.hashCode();
        tempHashCode += N.hashCode();
        tempHashCode += capR.hashCode();
        return tempHashCode;
    }

    public BigInteger generateHash() {
        BigInteger[] items = new BigInteger[3 + capR.length];
        items[0] = capS;
        items[1] = capZ;
        items[2] = N;
        for(int i = 0; i < capR.length;++i) {
            items[i+3] = capR[i];
        }

        return Utils.hashOf(256, items);
    }

    public BigInteger getG() {return g;}
    public BigInteger getH() {return h;}
    public BigInteger getN1() {return n1;}
    public BigInteger getH1() {return h1;}
    public BigInteger getH2() {return h2;}
}

