//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Support to save/load objects from file.
 */
public class Serializer {

    private static Logger log = Logger.getLogger(Serializer.class.getName());

    /**
     * De-serializes a given object to the named file.
     * 
     * @param fn
     * @param cls
     * @return object instance or null.
     */
    public static Object deserialize(final String fn,
            final Class<? extends Object> cls) {
        // if file exists, load existing group params.
        File f = new File(fn);
        try {
            if (f.exists()) {
                log.log(Level.INFO, "deserialize: " + cls.getName() + ":  file " + fn);
                FileInputStream fis = new FileInputStream(f);
                ObjectInputStream in = new ObjectInputStream(fis);

                return deserialize(in, cls);
            } else {
                log.log(Level.SEVERE, "file " + fn + " does not exist");
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Object deserialize(final ObjectInputStream ois,
            final Class<? extends Object> cls) {

        try {

            Object o = ois.readObject();

            if (!o.getClass().equals(cls)) {
                log.log(Level.SEVERE, "wrong object class");
                return null;
            }

            return o;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * To serialize the given object to file.
     * 
     * @param fn
     * @param o
     * @return success or failure.
     */
    public static boolean serialize(final String fn, final Object o) {
        log.log(Level.INFO, "save fn: " + fn);
        File f = new File(fn);
        try {
            FileOutputStream fos = new FileOutputStream(f);
            ObjectOutputStream out = new ObjectOutputStream(fos);
            serialize(out, o);
            out.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean serialize(ObjectOutputStream oos, Object o) {
        try {
            oos.writeObject(o);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
