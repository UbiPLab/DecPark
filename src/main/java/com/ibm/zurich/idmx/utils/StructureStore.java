//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils;

import java.net.URI;
import java.util.HashMap;

/**
 * Utility class that loads structural information (e.g., credential structures,
 * public keys). All structural information that is needed throughout the
 * library is retrieved from this class.
 */
public final class StructureStore {

    /** Map of already loaded structural information objects. */
    private HashMap<String, Object> structureMap = new HashMap<String, Object>();
    /** Only instance of this object. */
    private static StructureStore structures;
    
    /**
     * If this flag is set to false, the structure store will only attempt to load objects
     * that are on the file system, i.e., the objectLocation must be a URL whose scheme is "file".
     */
    public static boolean FETCH_MISSING_OBJECTS_FROM_INTERNET = false;

    /**
     * @return Singleton instance of this class.
     */
    public static StructureStore getInstance() {
        if (structures == null) {
            structures = new StructureStore();
        }
        return structures;
    }

    /**
     * Constructor.
     */
    private StructureStore() {

    }

    /**
     * Convenience method. Creates the location of the structure using its name.
     * 
     * @param objectName
     *            Location indicator of a structural element (e.g., credential
     *            structure, issuer public key).
     * @return The object specified by <tt>objetName</tt>.
     */
    public Object get(final URI objectName) {
        return get(objectName.toString(), objectName);
    }

    /**
     * @param objectName
     *            Name of a structural element (e.g., credential structure,
     *            issuer public key).
     * @param objectLocation
     *            Location indicator of the object.
     * @return The object specified by <tt>objetName</tt> and located at
     *         <tt>objectLocation</tt>.
     */
    public Object get(final String objectName, final URI objectLocation) {
        Object obj = structureMap.get(objectName);
        if (obj == null) {
          if(FETCH_MISSING_OBJECTS_FROM_INTERNET || (objectLocation.getScheme()!= null && objectLocation.getScheme().equals("file"))) {
            obj = load(objectLocation);
            if (obj != null) {
                structureMap.put(objectName, obj);
            }
          } else {
            throw new RuntimeException("Cannot find object " + objectName + " located at " + objectLocation);
          }
        }
        return obj;
    }

    /**
     * @param objectName
     *            Location indicator of a persistent object.
     * @return Object loaded from the indicated location.
     */
    private Object load(final URI objectLocation) {
        return Parser.getInstance().parse(objectLocation);
    }

    /**
     * Removes a URI from the store of structures. This method is needed when a
     * wrong secret key is loaded.
     * 
     * @param uri
     *            URI of the object to be removed.
     */
    public void remove(URI uri) {
        if (structures.structureMap.containsKey(uri.toString())) {
            structures.structureMap.remove(uri.toString());
        }
    }
    
    /**
     * Adds an object to the store of structures
     * @param objectUri
     * @param obj
     */
    		
    public void add(String objectUri, Object obj) {
       // if (!structures.structureMap.containsKey(objectUri)) {
            structures.structureMap.put(objectUri, obj);
       // }
    }

    /**
     * Reset the state of this singleton
     */
    public void reset() {
      structures = new StructureStore();
    }
}
