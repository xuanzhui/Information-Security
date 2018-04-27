package cn.xz.sample;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by xuanzhui on 2017/2/25.
 * wrapper of message digest api
 * all text will be UTF8 encoded and decoded
 */
public class MessageDigestAlgorithm {
    public byte[] md5(String plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(plainText.getBytes(StandardCharsets.UTF_8));
        return messageDigest.digest();
    }

    public byte[] sha1(String plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(plainText.getBytes(StandardCharsets.UTF_8));
        return messageDigest.digest();
    }

    public byte[] sha256(String plainText) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(plainText.getBytes(StandardCharsets.UTF_8));
        return messageDigest.digest();
    }
}
