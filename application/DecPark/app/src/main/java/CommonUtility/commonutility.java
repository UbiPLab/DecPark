package CommonUtility;

import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import java.io.IOException;
import java.math.BigInteger;

public class commonutility {

    public static String exportPrivateKey(String keystorePath, String password) {
        try {
            Credentials credentials = WalletUtils.loadCredentials(password, keystorePath);
            BigInteger privateKey = credentials.getEcKeyPair().getPrivateKey();
            return privateKey.toString(16);
        } catch (IOException | CipherException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static void main(String[] args) {
        String s = exportPrivateKey("E:\\zmw\\AndroidTool\\AndroidProject\\DecPark\\app\\src\\main\\res\\keystore\\UTC--2022-09-01T01-15-03.768751600Z--f2f40e2ff231fc3e8e0ab412be497b05d62b8310", "123");
        System.out.println(s);
    }
}
