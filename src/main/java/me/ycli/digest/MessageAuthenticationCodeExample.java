package me.ycli.digest;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by ycli on 16-7-19.
 * × email: yucai.li@hpe.com
 */
public class MessageAuthenticationCodeExample {
    public static void  main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        if(args.length != 1) {
            System.err.println("Usage: java MessageAuthenticationCodeExample text");
            System.exit(1);
        }

        byte[] plainText = args[0].getBytes("UTF8");
        System.out.println( "\nStart generating key" );
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
        SecretKey md5key = keyGen.generateKey();
        System.out.println( "Finish generating key: \n" + md5key.toString() + "\n" );

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(md5key);
        mac.update(plainText);

        System.out.println( "\n" + mac.getProvider().getInfo() );
        System.out.println( "\nMAC: " );
        System.out.println( new String( mac.doFinal(), "UTF8") );

    }
}
