package com.lamductan.Test;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.dblacr.actor.Actor;
import com.lamductan.dblacr.actor.sp.ServiceProvider;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignature;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSignatureVerifier;
import com.lamductan.dblacr.lib.crypto.CLSignature.CLSigner;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.system.DBLACRSystem;
import com.lamductan.dblacr.actor.user.User;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.SortedMap;
import java.util.Vector;

import com.ibm.zurich.idmx.utils.Utils;
import javafx.util.Pair;
import sun.security.pkcs11.Secmod;
import sun.util.xml.PlatformXmlPropertiesProvider;

public class Main {
    /********************** Main Test function ********************************/
    public static void main(String args[]) {
        DBLACRSystem dblacrSystem = DBLACRSystem.getInstance();
        SystemParameters sp = dblacrSystem.getSystemParameters();
        boolean restartTest = true;
        boolean initAuthentication = true;
        boolean testBlackListAuthentication = false;

        boolean serialze = false;

        if (restartTest) {

            //Test register
            System.out.println("1. Test User Register");
            int nUsers = 2;
            Test.testUserRegister(nUsers);
            System.out.println("注册完成");



            // Print list users
            System.out.println("2. Test List users");
            Test.printListUsers(dblacrSystem);
            System.out.println();


            //DBLACRSystem.saveToDisk();

            // Service providers join
            System.out.println("3. Test Service Provider join");
            int nServiceProviders = 2;
            Test.testServiceProviderJoin(nServiceProviders);
            System.out.println();
        }

        if (initAuthentication) {
            // Test Authentication
//            System.out.println("4. Test Random Authenticate");
//            Test.testAuthenticateRandomUser(dblacrSystem, sp);
//            System.out.println();

            for (int i = 0; i < 1; ++i) {
                Test.testAuthenticateUser(0, dblacrSystem);
            }
            System.out.println("-------------------------------");
            for (int i = 0; i < 1; ++i) {
                Test.testAuthenticateUser(1, dblacrSystem);
            }
//            dblacrSystem.setListScores(Test.createSampleScoreList());
        }

        if (testBlackListAuthentication) {
            for(int j = 0; j < 1; ++j) {
                //Print Sample list scores
                System.out.println("5. Test Sample List Score");
                Test.printSampleScoreList(dblacrSystem);
                System.out.println();



                //Test Authenticate user0
                System.out.println("6. Test User0 Register after add list score");
                Test.testAuthenticateUser(0, dblacrSystem);
                System.out.println();


                System.out.println("7. Test User2 Register after add list score");
                Test.testAuthenticateUser(1, dblacrSystem);
                System.out.println();
            }
        }

        // Serialize data
        if (serialze) serializeData();

    }
    /******************** End main test function ******************************/


    private static void serializeData() {
        Runtime.getRuntime().addShutdownHook(new Thread()
        {
            public void run()
            {
                DBLACRSystem.saveToDisk();
            }
        });
    }
}