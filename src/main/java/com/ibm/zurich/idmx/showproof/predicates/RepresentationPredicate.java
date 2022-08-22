//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.predicates;

import java.math.BigInteger;
import java.util.Vector;

import com.ibm.zurich.idmx.showproof.Identifier;

/**
 * Predicate to prove knowledge of a representation.
 */
public class RepresentationPredicate extends Predicate {

    /** Name of the predicate. */
    private final String name;
    /** Identifiers used in the representation. */
    private final Vector<Identifier> identifiers;
    /** Bases used in the representation. */
    private final Vector<BigInteger> bases;

    /**
     * Constructor.
     * 
     * @param theName
     *            Name of the predicate.
     * @param theIdentifiers
     *            Identifiers used within the predicate.
     * @param theBases
     *            Bases used in the representation.
     */
    public RepresentationPredicate(final String theName,
            final Vector<Identifier> theIdentifiers,
            final Vector<BigInteger> theBases) {
        super(PredicateType.REPRESENTATION);
        name = theName;
        if (theIdentifiers == null || theBases == null) {
            throw new IllegalArgumentException("Representation predicates "
                    + "require the declaration of identifiers and bases.");
        }
        identifiers = theIdentifiers;
        bases = theBases;
    }

    /**
     * @return Name of the predicate.
     */
    public final String getName() {
        return name;
    }

    /**
     * @return Identifiers of the predicate.
     */
    public final Vector<Identifier> getIdentifiers() {
        return identifiers;
    }

    /**
     * @return Bases used in the representation.
     */
    public final Vector<BigInteger> getBases() {
        return bases;
    }

    /**
     * @param index
     *            Index for the list of identifiers.
     * @return <tt>i</tt>-th identifier of the predicate.
     */
    public final Identifier getIdentifier(final int index) {
        if (index >= identifiers.size() || index < 0) {
            throw new IllegalArgumentException("invalid index (" + index
                    + ") in getIdentifier()");
        }
        return identifiers.get(index);
    }

    /**
     * @return Human-readable string of the predicate.
     */
    public final String toStringPretty() {
        String s = "RepresentationPredicate( " + name + ", "
                + Identifier.idsToString(identifiers) + ")";
        return s;
    }
}
