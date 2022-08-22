package Leaf;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;


public class AESUtils {


    private static final int KEY_SIZE = 128;

    private static final String ALGORITHM = "AES";

    private static final String RNG_ALGORITHM = "SHA1PRNG";


    private static SecretKey generateKey(byte[] key) throws Exception {

        SecureRandom random = SecureRandom.getInstance(RNG_ALGORITHM);

        random.setSeed(key);


        KeyGenerator gen = KeyGenerator.getInstance(ALGORITHM);

        gen.init(KEY_SIZE, random);

        return gen.generateKey();
    }


    public static byte[] encrypt(byte[] plainBytes, byte[] key) throws Exception {

        SecretKey secKey = generateKey(key);


        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, secKey);


        byte[] cipherBytes = cipher.doFinal(plainBytes);

        return cipherBytes;
    }

    public static byte[] decrypt(byte[] cipherBytes, byte[] key) throws Exception {

        SecretKey secKey = generateKey(key);


        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE, secKey);


        byte[] plainBytes = cipher.doFinal(cipherBytes);

        return plainBytes;
    }

    public static void encryptFile(File plainIn, File cipherOut, byte[] key) throws Exception {
        aesFile(plainIn, cipherOut, key, true);
    }


    public static void decryptFile(File cipherIn, File plainOut, byte[] key) throws Exception {
        aesFile(plainOut, cipherIn, key, false);
    }


    private static void aesFile(File plainFile, File cipherFile, byte[] key, boolean isEncrypt) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);

        SecretKey secKey = generateKey(key);

        cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secKey);


        InputStream in = null;
        OutputStream out = null;

        try {
            if (isEncrypt) {

                in = new FileInputStream(plainFile);
                out = new FileOutputStream(cipherFile);
            } else {

                in = new FileInputStream(cipherFile);
                out = new FileOutputStream(plainFile);
            }

            byte[] buf = new byte[1024];
            int len = -1;

            while ((len = in.read(buf)) != -1) {
                out.write(cipher.update(buf, 0, len));
            }
            out.write(cipher.doFinal());

            out.flush();

        } finally {
            close(in);
            close(out);
        }
    }

    private static void close(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException e) {

            }
        }
    }

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        String content = "12,12345678910";
        String key = Param.AESkey;

        byte[] cipherBytes = AESUtils.encrypt(content.getBytes(), key.getBytes());
        long end = System.currentTimeMillis();
        System.out.println((end-start)+"ms");
        System.out.println(Arrays.toString(cipherBytes));
        System.out.println(cipherBytes.length);

        byte[] plainBytes = AESUtils.decrypt(cipherBytes, key.getBytes());
        System.out.println(Arrays.toString(plainBytes));


        System.out.println(new String(plainBytes));

    }

}
