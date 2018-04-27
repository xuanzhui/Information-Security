package cn.xz.sample;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by xuanzhui on 2017/2/27.
 */
public class KDFAlgorithmTest {
    private static KDFAlgorithm kdfAlgorithm;
    private static String password;
    private static byte[] salt;

    @BeforeClass
    public static void beforeClass() {
        kdfAlgorithm = new KDFAlgorithm();
        password = "imsS49kraapnUH0Z";
        salt = "pMlKhTre10obG1ep".getBytes();
    }

    @Test
    public void pbkdf2MD5Test() throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hashBytes = kdfAlgorithm.pbkdf2MD5(password, salt, 1000, 128);
        String hexStr = HexUtil.byteArrayToHexString(hashBytes);
        assertEquals(hexStr, "E582C69A676196A4A5A0D2A43BE927ED");
    }

    @Test
    public void pbkdf2SHA1Test() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hashBytes = kdfAlgorithm.pbkdf2SHA1(password, salt, 1000, 160);
        String hexStr = HexUtil.byteArrayToHexString(hashBytes);
        assertEquals(hexStr, "8DA530D3C7EE6517BADBA6D46BEB421A1CC36751");
    }

    @Test
    public void pbkdf2SHA256Test() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hashBytes = kdfAlgorithm.pbkdf2SHA256(password, salt, 1000, 256);
        String hexStr = HexUtil.byteArrayToHexString(hashBytes);
        assertEquals(hexStr, "85914681E49063EDE3FFF9DD2C0F335750AFEC06A0DC068E990482F674B8D2C3");
    }

    @Test
    public void bcryptFreeBSDSchemaTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String bcryptStr = kdfAlgorithm.bcryptFreeBSDSchema(password, 6);
        System.out.println("bscrypt string: " + bcryptStr);
    }

    @Test
    public void bcryptFreeBSDSchemaVerifyTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        boolean match = kdfAlgorithm.bcryptFreeBSDSchemaVerify(password, "$2a$06$9tKhrwlRr81R3tZ8byUHtuBpjP3UF8Frq7OpIVk8u/hZMDIXuv5ui");
        assertTrue(match);
    }

    @Test
    public void scryptTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] hashBytes = kdfAlgorithm.scrypt(password, salt, (int)Math.pow(2, 14), 8, 1, 64);
        String hexStr = HexUtil.byteArrayToHexString(hashBytes);
        assertEquals(hexStr, "5837EE3D2A7F2DB3FECAC13CB21A25DFA4BD7A37F998FC05C774C683DB71209E574EF425506293B8F208FEC2D3D0BD8552D96BFF96D01BF55B81DBBB629DD3BD");
    }
}
