package me.ycli.encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by yucai on 2016/7/20.
 * email: yucai.li@hpe.com
 */
public class PublicExample {
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        if (args.length != 1) {
            System.err.println("Usage: java PublicExample text");
            System.exit(1);
        }

        byte[] plainText = args[0].getBytes("UTF8");

        //Step 1: generate a RSA key
        System.out.println( "\nStart generating RSA key" );
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        System.out.println( "Finish generating RSA key" );

        //Step 2: get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        System.out.println( "\n" + cipher.getProvider().getInfo() );

        //Step 3: encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedText = cipher.doFinal(plainText);
        System.out.println( "Finish encryption: " );
        System.out.println( new String(encryptedText, "UTF8") );

        //Step 4: decrypt the encryptedText using the private key
        System.out.println( "\nStart decryption" );
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedText = cipher.doFinal(encryptedText);
        System.out.println( "Finish decryption: " );
        System.out.println( new String(decryptedText, "UTF8") );
    }
}
