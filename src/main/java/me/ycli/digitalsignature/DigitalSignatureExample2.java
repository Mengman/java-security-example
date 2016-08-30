package me.ycli.digitalsignature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by yucai on 2016/8/4.
 * email: yucai.li@hpe.com
 *
 * 利用Signature类，能够更加方便的实现数字签名，签名原理与example1相同
 */
public class DigitalSignatureExample2 {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.printf("Usage: DigitalSignatureExample2 nameOfFileToSign");
        } else try {
            //Step 1: generate DSA keypair
            System.out.printf("\nStart generating DSA key");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);
            KeyPair keyPair = keyGen.genKeyPair();
            System.out.printf("\nFinish generating DSA key");

            //Step 2: create signature object and init it with private key
            System.out.printf("\nStart creating signature object");
            Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
            signature.initSign(keyPair.getPrivate());
            System.out.printf("\nFinish creating signature object");

            //Step 3: Supply the Signature Object the Data to be signed
            System.out.printf("\nStart signing the file");
            FileInputStream fis = new FileInputStream(args[0]);
            BufferedInputStream bufin = new BufferedInputStream(fis);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bufin.read(buffer)) >= 0) {
                signature.update(buffer, 0, len);
            }
            bufin.close();
            fis.close();
            byte[] realSig = signature.sign();
            System.out.printf("\n" + new String(realSig, "UTF8"));
            System.out.printf("\nFinish signing the file");

            //Step 4: Save signature and public key in files
            System.out.printf("\nSaving signature and key pair to file");
            FileOutputStream sigfos = new FileOutputStream("sig");
            sigfos.write(realSig);
            sigfos.close();
            System.out.printf("\nSaved signature to sig");

            byte[] pubKey = keyPair.getPublic().getEncoded();
            FileOutputStream pubKeyfos = new FileOutputStream("pubk");
            pubKeyfos.write(pubKey);
            pubKeyfos.close();
            System.out.printf("\nSaved public key to pubk");

            byte[] privateKey = keyPair.getPrivate().getEncoded();
            FileOutputStream privateKeyfos = new FileOutputStream("prik");
            privateKeyfos.write(privateKey);
            privateKeyfos.close();
            System.out.printf("\nSaved private key to prik");

            //Step 6: Verify Signature
            verifySignature("pubk", "sig", "data");

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

    public static void verifySignature(String publicKeyFile, String signatureFile, String dataFile) {
        try {
            //Step 1: Load public key and signature from file
            FileInputStream keyfis = new FileInputStream(publicKeyFile);
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

            FileInputStream sigfis = new FileInputStream(signatureFile);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            //Step 2: Initialize the Signature Object for Verification
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
            sig.initVerify(publicKey);

            //Step 3: Supply the Signature Object with the data to be verified
            FileInputStream datafis = new FileInputStream(dataFile);
            BufferedInputStream bufin = new BufferedInputStream(datafis);
            byte[] buffer = new byte[1024];
            int len;
            while (bufin.available() != 0) {
                len = bufin.read(buffer);
                sig.update(buffer, 0, len);
            }
            bufin.close();
            datafis.close();

            //Step 4: Verify the Signature
            boolean verifies = sig.verify(sigToVerify);
            System.out.printf("Signature verifies: " + verifies);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
