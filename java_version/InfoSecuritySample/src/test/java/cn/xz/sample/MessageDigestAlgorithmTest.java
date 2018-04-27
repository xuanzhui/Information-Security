package cn.xz.sample;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

import java.security.NoSuchAlgorithmException;

/**
 * Created by xuanzhui on 2017/2/25.
 * string compared is from python version results
 */
public class MessageDigestAlgorithmTest {
    private static MessageDigestAlgorithm messageDigestAlgorithm;
    private static String plainText;

    @BeforeClass
    public static void beforeClass() {
        messageDigestAlgorithm = new MessageDigestAlgorithm();
        plainText = "来自python的问候";
    }

    @Test
    public void md5Test() throws NoSuchAlgorithmException {
        byte[] bytes = messageDigestAlgorithm.md5(plainText);
        String hexStr = HexUtil.byteArrayToHexString(bytes);
        assertEquals(hexStr, "2B0AC1F0359745FC892D511759116366");
    }

    @Test
    public void sha1Test() throws NoSuchAlgorithmException {
        byte[] bytes = messageDigestAlgorithm.sha1(plainText);
        String hexStr = HexUtil.byteArrayToHexString(bytes);
        assertEquals(hexStr, "F6F5504D3365F956C54DEE052AEEA9039178E397");
    }

    @Test
    public void sha256Test() throws NoSuchAlgorithmException {
        byte[] bytes = messageDigestAlgorithm.sha256(plainText);
        String hexStr = HexUtil.byteArrayToHexString(bytes);
        assertEquals(hexStr, "0970218C22472D3D102A20CC9BC7DEFA1817E5B812A79A7D4CCC8B2CC27BED6C");
    }
}
