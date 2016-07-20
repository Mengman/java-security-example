package me.ycli.digest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * Created by ycli on 16-7-19.
 * × email: yucai.li@hpe.com
 */
public class MessageDigestExample {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            System.out.println("Did not find BouncyCastleProvider");
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
        if(args.length != 1) {
            System.err.println("Usage: java MessageDigestExample text");
            System.exit(1);
        }

        byte[] plainText = args[0].getBytes("UTF8");

        MessageDigest messageDigest = MessageDigest.getInstance("MD5", BouncyCastleProvider.PROVIDER_NAME);
        System.out.println("\n" + messageDigest.getProvider().getInfo());
        messageDigest.update(plainText);
        System.out.println( "\nDigest: " );
        System.out.println( new String( messageDigest.digest(), "UTF8") );
    }
}
