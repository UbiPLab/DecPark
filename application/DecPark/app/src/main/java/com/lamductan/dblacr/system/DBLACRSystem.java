package com.lamductan.dblacr.system;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.actor.sp.ServiceProvider;
import com.lamductan.dblacr.actor.user.User;
import com.lamductan.dblacr.lib.utils.AuxUtils;

import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.util.ArrayList;
import java.util.TreeMap;
import java.util.Vector;

public class DBLACRSystem implements Serializable {
    private static final long serialVersionUID = 6529685098267757690L;

    public static final URI groupParamsLocation = new File(System
            .getProperty("user.dir")).toURI().resolve("files/parameter/sp.xml");//get uri

    private static DBLACRSystem system = null;//dblacr class
    private static String cacheDataFilename = "data.dat";//video
    private ArrayList<Integer> sids;//sp's id list
    private ArrayList<User> userList;//user list
    private TreeMap<Integer, ServiceProvider> serviceProviders;//map of sp
    private SystemParameters sp;
    private GroupParameters gp;
    private BigInteger context;
    private ArrayList<BlockchainObject> listBlockchainObjects;//blockchain
    private Vector<ScoreRecord> listScores;
    private Vector<AuthenticationRecord> listAuthenticationRecords;
    private BigInteger Modulus;

    public static void main(String[] args) {
        System.out.println(groupParamsLocation);
    }

    public static DBLACRSystem getInstance() {
        if (system == null) {
            if (AuxUtils.checkFileExists(cacheDataFilename)) {
                DBLACRSystem system1 = loadFromDisk(cacheDataFilename);
                if (system1 != null) system = system1;
                else system = new DBLACRSystem();
            } else system = new DBLACRSystem();
        }
        return system;
    }

    private DBLACRSystem() {
        sids = new ArrayList<>();
        userList =  new ArrayList<>();
        serviceProviders = new TreeMap<>();

        sp = SystemParameters.generateSystemParametersFromRsaModulusSize(2048);
        gp = GroupParameters.generateGroupParams();

        Modulus = AuxUtils.computeModulus(sp);
        context = Utils.computeRandomNumber(sp.getL_H());
        listBlockchainObjects = new ArrayList<>();
        listScores = new Vector<>();
        listAuthenticationRecords = new Vector<>();
    }

    public static BigInteger getModulus() { return system.Modulus;}

    public int addNewServiceProvider(ServiceProvider serviceProvider) {
        int newSid = serviceProvider.getSid();
        serviceProviders.put(newSid, serviceProvider);
        return newSid;
    }

    public SystemParameters getSystemParameters() {return sp;}
    public GroupParameters getGroupParamters() {return gp;}
    public BigInteger getContext() {return context;}

    public ArrayList<Integer> getSids() {return sids;}
    public ArrayList<User> getUsers() {return userList;}
    public TreeMap<Integer, ServiceProvider> getServiceProviders() {return serviceProviders;}
    public ServiceProvider getServiceProviderBySid(int sid) {return serviceProviders.get(sid);}


    public void receiveRecord(BlockchainObject blockchainObject) {
        listBlockchainObjects.add(blockchainObject);
        String type = blockchainObject.getType();
        if (type.equals("ScoreRecord")) {
            listScores.add((ScoreRecord) blockchainObject);
        }
        else if (type.equals("AuthenticationRecord")) {
            listAuthenticationRecords.add((AuthenticationRecord) blockchainObject);
        }
    }

    public ArrayList<BlockchainObject> getRecord() {
        return listBlockchainObjects;
    }
    public Vector<ScoreRecord> getListScores() {return listScores;}
    public void setListScores(Vector<ScoreRecord> sampleListScores) {listScores = sampleListScores;} //TODO: remove this method
    public int getNewScoreId() { return listScores.size(); }

    public Vector<AuthenticationRecord> getListAuthenticationRecords() {return listAuthenticationRecords;}
    public int getNewAuthenticationId() {return listAuthenticationRecords.size();}

    public Vector<PublicKey> getListPublicKey()  {
        Vector<PublicKey> listPublicKeys = new Vector<>();
        for (int i = 0; i < userList.size(); ++i) {
            listPublicKeys.add(userList.get(i).getPublicKey());
        }
        return listPublicKeys;
    }

    public static void saveToDisk() {
        saveToDisk(cacheDataFilename);
    }

    private static void saveToDisk(String filename) {
        try {
            FileOutputStream fileOut =
                    new FileOutputStream(filename);
            ObjectOutputStream out = new ObjectOutputStream(fileOut);
            out.writeObject(system);
            out.close();
            fileOut.close();
            System.out.println("Serialized data is saved in " + filename);
        } catch (IOException i) {
            i.printStackTrace();
        }
    }

    private static DBLACRSystem loadFromDisk(String filename) {
        DBLACRSystem system1 = null;
        try {
            FileInputStream file = new FileInputStream(filename);
            ObjectInputStream in = new ObjectInputStream(file);
            system1 = (DBLACRSystem) in.readObject();
            in.close();
            file.close();
            System.out.println("Restore DBLACR System from disk.");
        } catch (IOException i) {
            i.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return system1;
    }
}