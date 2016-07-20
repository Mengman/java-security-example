package me.ycli.encrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by yucai on 2016/7/20.
 * email: yucai.li@hpe.com
 */
public class PrivateExample {
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (args.length != 1) {
            System.err.println("Usage: java PrivateExample text");
            System.exit(1);
        }
        byte[] plainText = args[0].getBytes("UTF8");

        //Step 1: create private key
        System.out.println( "\nStart generating DES key" );
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        Key key = keyGen.generateKey();
        System.out.println( "Finish generating DES key" );

        //Step 2: create cipher
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        System.out.println( "\n" + cipher.getProvider().getInfo() );
        cipher.init(Cipher.ENCRYPT_MODE, key);

        //Step 3: use cipher to encrypt message
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println( "Finish encryption: " );
        System.out.println( new String(cipherText, "UTF8") );

        //Step 4: use cipher to decrypt message
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptText = cipher.doFinal(cipherText);
        System.out.println( "Finish decryption: " );
        System.out.println( new String(decryptText, "UTF8") );
    }
}
