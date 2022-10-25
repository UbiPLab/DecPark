package com.lamductan.Test;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.actor.sp.ServiceProvider;
import com.lamductan.dblacr.actor.user.User;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.ScoreRecord;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.system.DBLACRSystem;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Vector;

public class Test {
    public static void testAuthenticateUser(int userId, DBLACRSystem dblacrSystem) {
        int sid = 0;
        User user;
        boolean result;

        user = dblacrSystem.getUsers().get(userId);
        result = user.authenticate(sid);
        System.out.println("User " + userId + " authenticates ServiceProvider " + sid + ", result: " + result);
        System.out.println();
    }

    public static void printSampleScoreList(DBLACRSystem dblacrSystem) {
        System.out.println("Sample score list");
        System.out.println(dblacrSystem.getListScores());
        System.out.println();
    }

    public static void testServiceProviderJoin(int nServiceProviders) {
        for(int i = 0; i < nServiceProviders; ++i) {
            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.joinToSystem();
        }
    }

    public static void printListUsers(DBLACRSystem dblacrSystem) {
        System.out.println();
        System.out.println("List users:");
        ArrayList<BlockchainObject> blockchainObjects = dblacrSystem.getRecord();
        for(BlockchainObject blockchainObject: blockchainObjects) {
            System.out.println(blockchainObject.toString());
        }
        System.out.println();
    }

    public static void testUserRegister(int nUsers) {
        for(int i = 0; i < nUsers; ++i) {
            User user = new User();
            user.register();
        }
    }

    public static void testAuthenticateRandomUser(DBLACRSystem dblacrSystem, SystemParameters sp) {
        int nUsers = dblacrSystem.getUsers().size();
        int nServiceProviders = dblacrSystem.getServiceProviders().size();

        for(int i = 0; i < 5; ++i) {
            int randomUser = Utils.computeRandomNumber(BigInteger.valueOf(nUsers), sp).intValue();
            int randomSP = Utils.computeRandomNumber(BigInteger.valueOf(nServiceProviders), sp).intValue();
            User user = dblacrSystem.getUsers().get(randomUser);
            boolean result = user.authenticate(randomSP);
            System.out.println("User " + randomUser + " authenticates ServiceProvider " + randomSP + ", result: " + result);
            System.out.println();
        }

        for(int i = 0; i < 5; ++i) {
            int randomUser = Utils.computeRandomNumber(BigInteger.valueOf(nUsers), sp).intValue();
            int randomSP = Utils.computeRandomNumber(BigInteger.valueOf(nServiceProviders), sp).intValue();
            User user = dblacrSystem.getUsers().get(randomUser);
            boolean result = user.authenticate(randomSP);
            System.out.println("User " + randomUser + " authenticates ServiceProvider " + randomSP + ", result: " + result);
            System.out.println();
        }
    }

    public static Vector<Vector<Pair<Integer, Integer>>> addListScores(Vector<Vector<Pair<Integer, Integer>>> listScores,
                                                                        int[] scoreValues) {
        Vector<Pair<Integer, Integer>> scores;
        scores = new Vector<>();
        for(int i = 0; i < scoreValues.length; ++i)
            scores.add(new Pair<>(i, scoreValues[i]));
        listScores.add(scores);
        return listScores;
    }


    public static Vector<ScoreRecord> createSampleScoreList() {
        DBLACRSystem dblacrSystem = DBLACRSystem.getInstance();
        Vector<ScoreRecord> scoreRecords = new Vector<>();
        Vector<AuthenticationRecord> authenticationRecords = dblacrSystem.getListAuthenticationRecords();
        int nAuthenticationEvent = 7;//7个验证事件
        Vector<Vector<Pair<Integer, Integer>>> sampleScores = new Vector<>();

        sampleScores = addListScores(sampleScores, new int[]{-1, 0});
        sampleScores = addListScores(sampleScores, new int[]{-2, 0});
        sampleScores = addListScores(sampleScores, new int[]{-3, 0});
        sampleScores = addListScores(sampleScores, new int[]{1, 0});
        sampleScores = addListScores(sampleScores, new int[]{2, 0});
        sampleScores = addListScores(sampleScores, new int[]{0, 3});
        sampleScores = addListScores(sampleScores, new int[]{0, -1});

        for(int i = 0; i < nAuthenticationEvent; ++i) {
            AuthenticationRecord authenticationRecord = authenticationRecords.get(i);
            int sid = authenticationRecord.getSid();
            int tid = authenticationRecord.getTid();
            Ticket ticket = authenticationRecord.getTau();
            Vector<Pair<Integer, Integer>> scores = sampleScores.get(i);
            ScoreRecord scoreRecord = new ScoreRecord(sid, tid, ticket, scores);
            scoreRecords.add(scoreRecord);
        }
        return scoreRecords;
    }

    public static void retrieveUserFromScoreList() {
        DBLACRSystem dblacrSystem = DBLACRSystem.getInstance();
        Vector<ScoreRecord> scoreRecords = dblacrSystem.getListScores();
        ArrayList<User> listUsers = dblacrSystem.getUsers();
        for(int i = 0; i < scoreRecords.size(); ++i) {
            ScoreRecord scoreRecord = scoreRecords.get(i);
            Ticket tau = scoreRecord.getTicket();
            for(int j = 0; j < listUsers.size(); ++j) {
                User user = listUsers.get(j);
                if (tau.verify(user.getPrivateKey())) {
                    System.out.println("Score " + i + ": User " + j);
                }
            }
        }
    }
}
