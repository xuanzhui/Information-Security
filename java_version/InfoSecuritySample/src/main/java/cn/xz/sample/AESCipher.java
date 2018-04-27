package cn.xz.sample;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by xuanzhui on 2017/3/13.
 * 
 * Every implementation of the Java platform is required to support the following standard symmetric Cipher transformations with the keysizes in parentheses:
 * AES/CBC/NoPadding (128)
 * AES/CBC/PKCS5Padding (128)
 * AES/ECB/NoPadding (128)
 * AES/ECB/PKCS5Padding (128)
 * DES/CBC/NoPadding (56)
 * DES/CBC/PKCS5Padding (56)
 * DES/ECB/NoPadding (56)
 * DES/ECB/PKCS5Padding (56)
 * DESede/CBC/NoPadding (168)
 * DESede/CBC/PKCS5Padding (168)
 * DESede/ECB/NoPadding (168)
 * DESede/ECB/PKCS5Padding (168)
 *
 * normally prefer AES/CBC/PKCS5Padding
 * AES padding should be using PKCS#7 although here saying PKCS5Padding
 * key and vector should change each time before encryption in production environment.
 *
 * https://security.stackexchange.com/questions/26179/security-comparsion-of-3des-and-aes
 */
public class AESCipher {
    public byte[] encryptCBCMode(String key, String vector, String plainText) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(vector.getBytes(StandardCharsets.UTF_8));
        SecretKey keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decryptCBCMode(String key, String vector, byte[] cipherBytes) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        IvParameterSpec iv = new IvParameterSpec(vector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

        return cipher.doFinal(cipherBytes);
    }

    public byte[] encryptECBMode(String key, String plainText) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decryptECBMode(String key, byte[] cipherBytes) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        return cipher.doFinal(cipherBytes);
    }
}
