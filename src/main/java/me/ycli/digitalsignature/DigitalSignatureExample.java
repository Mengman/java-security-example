package me.ycli.digitalsignature;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by yucai on 2016/7/23.
 * email: yucai.li@hpe.com
 *
 * 使用数字签名的目的在于防止中间人攻击（Man-in-the-Middle attack）,例如Bob和Alice利用非对称密钥发送信息，由于公钥是公开的，
 * Bob无法知道自己收到的消息是否真的来自于Alice，因为Eve可能在截取到Alice的公钥，然后用Alice的公钥向Bob发送信息。
 *
 * 利用数字签名方法，可以有效的防止中间人攻击，其原理如下：
 * 1. 消息发送者生成消息的digest。
 * 2. 发送者使用私钥对digest进行加密。
 * 3. 发送者将加密后的digest和消息发送给接收者。
 * 4. 接收者使用发送者的公钥解密digest，然后重新计算消息的digest。
 * 5. 对比两个digest是否一致，如果一致表示消息未被修改。
 *
 * 由于私钥只保存于发送者手中，所以接收者能确保消息未被修改。
 */
public class DigitalSignatureExample {
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (args.length != 1) {
            System.err.println("Usage: java DigitalSignature1Example text");
            System.exit(1);
        }

        byte[] plainText = args[0].getBytes("UTF8");

        //Step 1: generate message digest
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        System.out.println( "\n" + messageDigest.getProvider().getInfo() );
        messageDigest.update(plainText);
        byte[] md = messageDigest.digest();
        System.out.println( "\nDigest: " );
        System.out.println( new String( md, "UTF8") );

        //Step 2: generate RSA keypair
        System.out.println("\nStart generating RSA key");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        System.out.println("Finish generating RSA key");

        //Step 3: Get RSA cipher and list the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        System.out.printf("\n" + cipher.getProvider().getInfo());

        //Step 4: Encrypt the message digest with the RSA private key to create the signature
        System.out.printf("\nStart encryption");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] cipherText = cipher.doFinal(md);
        System.out.printf("\nFinish encryption: ");
        System.out.printf(new String(cipherText, "UTF8"));

        //Step 5: Verify Signature, start by decrypting the signature with the RSA public key
        System.out.printf("\nStart decryption");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());

        byte[] newMD = cipher.doFinal(cipherText);
        System.out.printf("\nFinish decryption");
        // here may throw "java.util.UnknownFormatConversionException", it is a bug of jdk...
        // if that happened, change a input string and try again.
        System.out.printf(new String(newMD, "UTF8"));

        //Then, recreate the message digest from the plaintext to simulate what a recipient must do
        System.out.printf("\nStart signature verification");
        messageDigest.reset();
        messageDigest.update(plainText);
        byte[] oldMD = messageDigest.digest();

        //Verify that the two message digests match
        int len = newMD.length;
        if (len > oldMD.length) {
            System.out.printf("Signature failed, length error");
            System.exit(1);
        }
        for (int i=0; i < len; i++) {
            if (oldMD[i] != newMD[i]) {
                System.out.printf("Signature failed, element error");
                System.exit(1);
            }
        }
        System.out.printf("Signature verified");
    }
}
