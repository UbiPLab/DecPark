package com.lamductan.dblacr.lib.crypto.key;

import java.math.BigInteger;

public interface IPrivateKey {
    BigInteger getP();
    BigInteger getQ();
}
