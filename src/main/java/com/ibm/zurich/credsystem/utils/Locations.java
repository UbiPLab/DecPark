//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.credsystem.utils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.zurich.idmx.key.IssuerKeyPair;
import com.ibm.zurich.idmx.key.VEPrivateKey;
import com.ibm.zurich.idmx.key.VEPublicKey;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.XMLSerializer;

/**
 *
 */
public class Locations {

    /** Logger. */
    private static Logger log = Logger.getLogger(Locations.class.getName());

    private static String SYSTEM_PARAMETER_NAME = "sp.xml";
    public static String GROUP_PARAMETER_NAME = "gp.xml";

    /**
     * Number of attributes an issuer key supports (i.e., number of bases
     * excluding the reserved attributes such as the master secret).
     */
    public static final int NBR_ATTRS = 9;
    /**
     * Issuer public key should have epoch length of 120 days -- 432000 seconds.
     * Note that this will require him to issuer an update for each credential
     * every 120 days.
     */
    public static final int EPOCH_LENGTH = 432000;

    public static URI gpUri;
    public static URI spUri;
    public static URI iskUri;
    public static URI ipkUri;
    public static URI msUri;
    public static URI vepkUri;
    public static URI veskUri;

    public static URI gpIdUri;
    public static URI ipkIdUri;
    public static URI vepkIdUri;

    /**
     * Load an element with a corresponding identifying URI.
     * 
     * @param objectUri
     *            URI that identifies the element.
     * @param objectLocation
     *            URI indicating the location of the URI where it will be loaded
     *            from.
     * @return Object that has been loaded.
     */
    public static Object init(URI objectUri, URI objectLocation) {
        return init(objectUri.toString(), objectLocation);
    }

    /**
     * Load an element with a corresponding identifying URI.
     * 
     * @param objectUri
     *            String representation of a URI that identifies the element.
     * @param objectLocation
     *            URI indicating the location of the URI where it will be loaded
     *            from.
     * @return Object that has been loaded.
     */
    public static Object init(String objectUri, URI objectLocation) {
        return StructureStore.getInstance().get(objectUri, objectLocation);
    }
    
    /**
     * Load an object with a corresponding identifying URI.
     * 
     * @param objectUri
     *            String representation of a URI that identifies the element.
     * @param object
     *            Object to be loaded
     */
    public static void init(String objectUri, Object object) {
        StructureStore.getInstance().add(objectUri, object);
    }

    /**
     * Load an element from an identifying URI.
     * 
     * @param identifierUri
     *            String representation of a URI that identifies the element.
     * @return Object that has been loaded.
     */
    public static Object init(URI identifierUri) {
        return StructureStore.getInstance().get(identifierUri);
    }

    public static void initSystem(URI baseLocation, String baseUri) {
        initSystem(baseLocation.resolve(SYSTEM_PARAMETER_NAME), baseUri
                + SYSTEM_PARAMETER_NAME,
                baseLocation.resolve(GROUP_PARAMETER_NAME), baseUri
                        + GROUP_PARAMETER_NAME);
    }

    public static void initSystem(URI spLocation, String spUri, URI gpLocation,
            String gpUri) {
        URI spUri_converted = null;
        try {
            spUri_converted = new URI(spUri);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        // load system parameters
        init(spUri, spLocation);
        GroupParameters gp = (GroupParameters) init(gpUri, gpLocation);
        if (gp == null) {
            gp = GroupParameters.generateGroupParams(spUri_converted);
            try {
                XMLSerializer.getInstance().serialize(gp, gpLocation);
                init(gpUri, gpLocation);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (gp.getSystemParams() == null) {
            throw new RuntimeException("System parameters are not correctly "
                    + "referenced in group parameters at: "
                    + gpLocation.toString());
        }
    }

    /**
     * Initialise issuer with all data required.
     * 
     * @param baseLocation
     *            Location where the system parameters and group parameters can
     *            be loaded from.
     * @param baseUri
     *            URI used to refer to the system parameters and group
     *            parameters.
     * @param iskLocation
     *            Issuer secret key location (there is no URI associated with
     *            the secret key!).
     * @param ipkLocation
     *            Location of the issuer public key.
     * @param ipkUri
     *            Identifying URI of the issuer public key.
     * @return Issuer key pair.
     */
    public static IssuerKeyPair initIssuer(URI baseLocation, String baseUri,
            URI iskLocation, URI ipkLocation, URI ipkUri) {

        URI spLocation = null, gpLocation = null;
        String spId = null, gpId = null;
        if (baseLocation != null) {
            spLocation = baseLocation.resolve(SYSTEM_PARAMETER_NAME);
            gpLocation = baseLocation.resolve(GROUP_PARAMETER_NAME);
        }
        if (baseUri != null) {
            spId = baseUri + SYSTEM_PARAMETER_NAME;
            gpId = baseUri + GROUP_PARAMETER_NAME;
        }
        return initIssuer(spLocation, spId, gpLocation, gpId, iskLocation,
                ipkLocation, ipkUri);
    }

    /**
     * Convenience method.
     * 
     * @see Locations#initIssuer(URI, String, URI, String, URI, URI, URI,
     *      Integer, Integer).
     */
    public static IssuerKeyPair initIssuer(URI spLocation, String spUri,
            URI gpLocation, String gpUri, URI iskLocation, URI ipkLocation,
            URI ipkUri) {
        return initIssuer(spLocation, spUri, gpLocation, gpUri, iskLocation,
                ipkLocation, ipkUri, null, null);
    }

    /**
     * Initialise issuer with all data required.
     * 
     * @param spLocation
     *            Location of the system parameters on disk.
     * @param spUri
     *            Identifying URI of the system parameters.
     * @param gpLocation
     *            Group parameter location on disk.
     * @param gpUri
     *            Identifying URI of the group parameters.
     * @param iskLocation
     *            Issuer secret key location (there is no URI associated with
     *            the secret key!).
     * @param ipkLocation
     *            Location of the issuer public key.
     * @param ipkUri
     *            Identifying URI of the issuer public key.
     * @param numOfAttributes
     *            Maximal number of attributes supported (this number is the
     *            usable attributes excluding reserved attributes such as the
     *            master secret). Use 'null' to use the default value.
     * @param epochLength
     *            Length of one epoch for credentials issued with the given key.
     *            Use 'null' to use the default epoch length.
     * @return Issuer key pair.
     */
    public static IssuerKeyPair initIssuer(URI spLocation, String spUri,
            URI gpLocation, String gpUri, URI iskLocation, URI ipkLocation,
            URI ipkUri, Integer numOfAttributes, Integer epochLength) {
        if (epochLength == null) {
            epochLength = EPOCH_LENGTH;
        }
        if (numOfAttributes == null) {
            numOfAttributes = NBR_ATTRS;
        }

        URI gpUri_converted = null;
        if (spLocation != null && spUri != null && gpLocation != null
                && gpUri != null) {
            initSystem(spLocation, spUri, gpLocation, gpUri);

            try {
                gpUri_converted = new URI(gpUri);
            } catch (URISyntaxException e1) {
                e1.printStackTrace();
            }
        }

        // load issuer key
        IssuerKeyPair issuerKey = null;
        try {
            // try loading the public key
            init(ipkUri, ipkLocation);
            // try loading the secret key
            issuerKey = (IssuerKeyPair) init(iskLocation);
        } catch (Exception e) {
            log.log(Level.INFO, "Issuer secred key not found " + "in "
                    + iskLocation.toString() + ". I will generate "
                    + "a new one. If you are running the test case for "
                    + "the first time this is nothing to worry about!");
        }
        // NOTE (pbi) This is functionality that is only for testing purposes!
        // Clearly, one cannot simply generate a new issuer key pair just like
        // that!
        if ((issuerKey == null) || (issuerKey.getPublicKey() == null)) {
            // generating a new key
            issuerKey = new IssuerKeyPair(ipkUri, gpUri_converted,
                    numOfAttributes, epochLength);
            XMLSerializer.getInstance().serialize(issuerKey.getPublicKey(),
                    ipkLocation);
            XMLSerializer.getInstance().serialize(issuerKey.getPrivateKey(),
                    iskLocation);

            // remove previous entries in the structure store database and load
            // them through the structure store to make the right keys
            // accessible
            StructureStore.getInstance().remove(iskLocation);
            StructureStore.getInstance().remove(ipkUri);

            init(ipkUri, ipkLocation);
            init(iskLocation);
            issuerKey = (IssuerKeyPair) init(iskLocation);
        }
        return issuerKey;
    }

    public static final VEPrivateKey initTrustedParty(URI spId,
            URI veskLocation, URI vepkLocation, URI vepkId) {
        // try to load VE keypair
        VEPublicKey pk = (VEPublicKey) StructureStore.getInstance().get(
                vepkId.toString(), vepkLocation);
        VEPrivateKey sk = (VEPrivateKey) StructureStore.getInstance().get(
                veskLocation);
        if (pk == null || sk == null) {
            log.log(Level.INFO, "Verifiable encryption key failed to load. "
                    + "Generating a new one and saving it...");
            sk = new VEPrivateKey(spId, vepkId);
            pk = sk.getPublicKey();

            XMLSerializer.getInstance().serialize(pk, vepkLocation);
            XMLSerializer.getInstance().serialize(sk, veskLocation);

            StructureStore.getInstance().remove(veskLocation);
            StructureStore.getInstance().remove(vepkId);

            init(vepkId, vepkLocation);
            init(veskLocation);
        }
        return sk;
    }
}
