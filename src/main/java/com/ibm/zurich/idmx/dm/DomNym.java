//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.dm;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.Serializer;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;

/**
 * Domain nym abstraction. Must be serializable in order to persist.
 */
@Deprecated
public class DomNym implements Serializable {

    /** Serial version number. */
    private static final long serialVersionUID = 1L;

    /** Group parameters. */
    private final GroupParameters gp;
    /** Value of the pseudonym. */
    private final BigInteger nym;
    /** Base of the domain pseudonym. */
    private final BigInteger g_dom;

    /**
     * To compute value of domain-nym.
     * 
     * @param theG_dom
     *            Base.
     * @param masterSecret
     *            Master secret.
     * 
     * @return <tt>g_dom^m_1 (mod capGamma)</tt>.
     */
    public final BigInteger compute(final BigInteger theG_dom,
            final BigInteger masterSecret) {
        return theG_dom.modPow(masterSecret, gp.getCapGamma());
    }

    /**
     * Construct a DomNym from the computed value of the nym.
     * 
     * @param groupParams
     *            Group parameters.
     * @param theNym
     *            Domain pseudonym value.
     * @param domain
     *            Domain string.
     */
    public DomNym(final GroupParameters groupParams, final BigInteger theNym,
            final String domain) {
        gp = groupParams;
        nym = theNym;
        g_dom = computeG_dom(groupParams, domain);
    }

    /**
     * Construct a DomNym from the computed value of the nym.
     * 
     * @param groupParams
     *            Group parameters.
     * @param theNym
     *            Domain pseudonym value.
     * @param theG_dom
     *            Computed base for a domain string.
     */
    @Deprecated
    public DomNym(final GroupParameters groupParams, final BigInteger theNym,
                  final BigInteger theG_dom) {
      throw new UnsupportedOperationException("Please do not call this constructor anymore.");
    }
    
    public DomNym(final GroupParameters groupParams, final BigInteger theNym,
            final BigInteger theG_dom, final URI nameOfSmartcard) {
        gp = groupParams;
        nym = theNym;
        g_dom = theG_dom;
    }

    /**
     * Computes the base for the domain pseudonym (i.e., <tt>g_dom</tt> in the
     * specification).
     * 
     * @param gp
     *            Group parameters.
     * @param domain
     *            The domain of the pseudonym.
     * @return <tt>g_dom</tt>.
     */
    public static BigInteger computeG_dom(final GroupParameters gp,
            final String domain) {
        final SystemParameters sp = gp.getSystemParams();
        final BigInteger capGamma = gp.getCapGamma();

        BigInteger hashedDom = Utils.hashString(domain, sp.getL_Gamma());
        BigInteger g_domExp = (capGamma.subtract(BigInteger.ONE)).divide(gp
                .getRho());
        return hashedDom.modPow(g_domExp, capGamma);
    }

    /**
     * @return Domain pseudonym.
     */
    public final BigInteger getNym() {
        return nym;
    }

    /**
     * @return Base used for this domain pseudonym <tt>g_dom</tt>.
     */
    public final BigInteger getG_dom() {
        return g_dom;
    }

    /**
     * Persist domain pseudonym to some file.
     * 
     * @param fn
     *            File name.
     * @return True on success; False on failure.
     */
    public final boolean save(final String fn) {
        return Serializer.serialize(fn, this);
    }

    /**
     * To fetch a domain-nym from file.
     * 
     * @param fn
     *            File name.
     * @return Domain pseudonym.
     */
    public static DomNym load(final String fn) {
        final DomNym dn = (DomNym) Serializer.deserialize(fn, DomNym.class);
        return dn;
    }
}