package cn.xz.sample;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Created by xuanzhui on 2017/2/25.
 * "Message Authentication Code" (MAC) algorithm
 */
public class MacAlgorithm {
    public static void main(String[] args) {
        System.out.println(randomCharString(16));
    }

    // 随机生成len长度的string
    private static String randomCharString(int len) {
        String numLetters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < len; i++)
            sb.append(numLetters.charAt(random.nextInt(62)));

        return sb.toString();
    }

    public byte[] hmacMd5(String plainText, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacMD5");
        Key secKey = new SecretKeySpec(key, "HmacMD5");
        mac.init(secKey);
        mac.update(plainText.getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
    }

    public byte[] hmacSHA1(String plainText, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        Key secKey = new SecretKeySpec(key, "HmacSHA1");
        mac.init(secKey);
        mac.update(plainText.getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
    }

    public byte[] hmacSHA256(String plainText, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        Key secKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secKey);
        mac.update(plainText.getBytes(StandardCharsets.UTF_8));
        return mac.doFinal();
    }
}
