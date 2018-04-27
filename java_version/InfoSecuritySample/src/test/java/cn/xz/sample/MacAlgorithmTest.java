package cn.xz.sample;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by xuanzhui on 2017/2/26.
 */
public class MacAlgorithmTest {
    private static MacAlgorithm macAlgorithm;
    private static String plainText;
    private static byte[] keyBytes;

    @BeforeClass
    public static void beforeClass() {
        macAlgorithm = new MacAlgorithm();
        plainText = "来自python的问候";
        keyBytes = "imsS49kraapnUH0Z".getBytes();
    }

    @Test
    public void hmacMd5Test() throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] macBytes = macAlgorithm.hmacMd5(plainText, keyBytes);
        String hexStr = HexUtil.byteArrayToHexString(macBytes);
        assertEquals(hexStr, "13298628585E0FE8101F3FDE28D4CE11");
    }

    @Test
    public void hmacSHA1Test() throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] macBytes = macAlgorithm.hmacSHA1(plainText, keyBytes);
        String hexStr = HexUtil.byteArrayToHexString(macBytes);
        assertEquals(hexStr, "C2B33A0A6C5EE20FBB280097A33C50E9D3F39A0A");
    }

    @Test
    public void hmacSHA256Test() throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] macBytes = macAlgorithm.hmacSHA256(plainText, keyBytes);
        String hexStr = HexUtil.byteArrayToHexString(macBytes);
        assertEquals(hexStr, "DFA93EEAE7D3247C285F06659320767FF4953B78754662A93B6DB0DA285ADA3B");
    }
}
