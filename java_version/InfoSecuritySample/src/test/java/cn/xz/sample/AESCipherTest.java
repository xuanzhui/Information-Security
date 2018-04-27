package cn.xz.sample;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by xuanzhui on 2017/3/20.
 */
public class AESCipherTest {
    private static AESCipher aesCipher;
    private static String key;
    private static String cbcIV;
    private static String plainText;

    @BeforeClass
    public static void beforeClass() {
        aesCipher = new AESCipher();
        key = "xr6OnFq8XanLETxH";
        cbcIV = "Pt1TnnURWIPnIFIA";
        plainText = "测试AES加密PKCS7PADDING";
    }

    @Test
    public void encryptCBCModeTest() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] cipherBytes = aesCipher.encryptCBCMode(key, cbcIV, plainText);
        System.out.println("aes cbc encrypt hex string: " + HexUtil.byteArrayToHexString(cipherBytes));
    }

    @Test
    public void decryptCBCModeTest() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] cipherBytes = HexUtil.hexStringToByteArray("515429FCC844E106D748134D33DD4FCB6B8DD04EBB5AE8EA954D471C7CAF8EFC");
        byte[] plainBytes = aesCipher.decryptCBCMode(key, cbcIV, cipherBytes);
        String text = new String(plainBytes, StandardCharsets.UTF_8);
        assertEquals(plainText, text);
    }

    @Test
    public void encryptECBModeTest() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] cipherBytes = aesCipher.encryptECBMode(key, plainText);
        System.out.println("aes ecb encrypt hex string: " + HexUtil.byteArrayToHexString(cipherBytes));
    }

    @Test
    public void decryptECBModeTest() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] cipherBytes = HexUtil.hexStringToByteArray("582E06C6B868CFC0770381E970A5550FE32DE6E9B6995D81183E58CB9B3F0798");
        byte[] plainBytes = aesCipher.decryptECBMode(key, cipherBytes);
        String text = new String(plainBytes, StandardCharsets.UTF_8);
        assertEquals(plainText, text);
    }
}
