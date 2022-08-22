package com.lamductan.dblacr.lib.blockchain;

import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import javafx.util.Pair;

import java.io.Serializable;
import java.util.Vector;

public class ScoreRecord extends BlockchainObject implements Serializable {
    private static final long serialVersionUID = 6529685098267757680L;

    private int sid;//sp'id
    private int tid;//authentication'id
    private Ticket ticket;//ticket of user
    private Vector<Pair<Integer, Integer>> s;

    public ScoreRecord(int _sid, int _tid, Ticket _ticket, Vector<Pair<Integer, Integer>> _s) {
        sid = _sid;
        tid = _tid;
        ticket = _ticket;
        s = _s;
    }

    @Override
    public String getType() {return "ScoreRecord";}

    public int getSid() {return sid;}
    public int getTid() {return tid;}
    public Ticket getTicket() {return ticket;}
    public Vector<Pair<Integer, Integer>> getS() {return s;}

    @Override
    public String toString() {
        String str = "[";
        str += sid + ",";
        str += tid + ",";
        str += ticket + ",";
        str += s + "]\n";
        return str;
    }
}
