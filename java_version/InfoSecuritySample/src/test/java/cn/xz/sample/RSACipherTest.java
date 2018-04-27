package cn.xz.sample;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Created by xuanzhui on 2017/3/25.
 */
public class RSACipherTest {
    private static RSACipher rsaCipher;
    private static String rootPath;
    private static String plainText;

    @BeforeClass
    public static void beforeClass() {
        rsaCipher = new RSACipher();
        rootPath = "C:/Users/xuanzhui/WorkSpace/own/Information-Security/cipher_keys/";
        plainText = "JAVA测试RSA算法--RSA/ECB/OAEPWithSHA";
    }

    @Test
    public void getPublicKeyFromDerFormatFileTest() throws InvalidKeySpecException,
            CertificateException, NoSuchAlgorithmException, IOException {
        rsaCipher.getPublicKeyFromDerFormatFile(rootPath + "rsa_public_key_2048.der");
    }

    @Test
    public void getPrivateKeyFromDerFormatFileTest() throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException {
        rsaCipher.getPrivateKeyFromDerFormatFile(rootPath + "pkcs8_rsa_private_key_2048.der");
    }

    @Test
    public void getPublicKeyFromPemFormatFileTest() throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException {
        rsaCipher.getPublicKeyFromPemFormatFile(rootPath + "rsa_public_key_2048.pem");
    }

    @Test
    public void getPrivateKeyFromPemFormatFileTest() throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException {
        rsaCipher.getPrivateKeyFromPemFormatFile(rootPath + "pkcs8_rsa_private_key_2048.pem");
    }

    @Test
    public void getPublicKeyFromCertFileTest() throws CertificateException, FileNotFoundException {
        rsaCipher.getPublicKeyFromCertFile(rootPath + "cert_file_der_format.cer");
        rsaCipher.getPublicKeyFromCertFile(rootPath + "cert_file_pem_format.cer");
    }

    @Test
    public void getPrivateKeyFromP12Test() throws UnrecoverableKeyException, CertificateException,
            NoSuchAlgorithmException, KeyStoreException, IOException {
        rsaCipher.getPrivateKeyFromP12(rootPath + "key_with_cert.p12", "123456", null);
    }

    @Test
    public void getPublicKeyFromP12Test() throws CertificateException, NoSuchAlgorithmException,
            KeyStoreException, IOException {
        rsaCipher.getPublicKeyFromP12(rootPath + "key_with_cert.p12", "123456", null);
    }

    @Test
    public void getPrivateKeyFromJKSTest() throws UnrecoverableKeyException, CertificateException,
            NoSuchAlgorithmException, KeyStoreException, IOException {
        rsaCipher.getPrivateKeyFromJKS(rootPath + "my_keystore.jks", "654321", "aliasname", "123456");

        assertEquals(null, rsaCipher.getPrivateKeyFromJKS(rootPath + "my_keystore.jks", "654321",
                "cert_no_prikey", "123456"));
    }

    @Test
    public void getPublicKeyFromJKSTest() throws CertificateException, NoSuchAlgorithmException,
            KeyStoreException, IOException {
        rsaCipher.getPublicKeyFromJKS(rootPath + "my_keystore.jks", "654321", "aliasname");
    }

    @Test
    public void encryptWithOAEPTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException,
            NoSuchPaddingException {
        PublicKey publicKey = rsaCipher.getPublicKeyFromPemFormatFile(rootPath + "rsa_public_key_2048.pem");
        byte[] cipherBytes = rsaCipher.encryptWithOAEP(publicKey, plainText.getBytes(StandardCharsets.UTF_8));
        System.out.println("cipher with OAEP hex string: " + HexUtil.byteArrayToHexString(cipherBytes));
    }

    @Test
    public void decryptWithOAEPTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
            IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        PrivateKey privateKey = rsaCipher.getPrivateKeyFromPemFormatFile(rootPath + "pkcs8_rsa_private_key_2048.pem");
        byte[] cipherBytes = HexUtil.hexStringToByteArray("5A624632B19B02D61773CDCCD486283F21ADC78C710BA50DA2667B9406103C7AE1BA44843D6E05F2D32DFFC0FA2E1ADFA17066F797910E41E8B5C0E69092CC383746F6F94E9E97E6EC6E01296A3ED71801037BEFC1C3BC61985907720AB460D4973A4DF16E3571A451D3579B89446241346B6F52A07AF212A1CAA6237C13957E96D58EEFC859603C2C2945A4EE76A41DF6600A4B00E707F9B7867C4C4A93AE40F31C81B7D8B2433D4480AE2C9E805F6C57FA9F19E890D39CB405E42789EFD73501BA2D57AE3E93FB9CB8E5256A82D0D070F1E04D4B785458B68AFD1C40D80726DBA2261C3ACF2A59A907B2EBE6C0F82D8828F3F1B6CD5D3BDA128EE9291FE344");
        byte[] plainBytes = rsaCipher.decryptWithOAEP(privateKey, cipherBytes);
        assertEquals(plainText, new String(plainBytes, StandardCharsets.UTF_8));
    }

    @Test
    public void signWithPSSTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
            NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
        PrivateKey privateKey = rsaCipher.getPrivateKeyFromPemFormatFile(rootPath + "pkcs8_rsa_private_key_2048.pem");
        byte[] signBytes = rsaCipher.signWithPSS(privateKey, plainText.getBytes(StandardCharsets.UTF_8), 20);
        System.out.println("sign with PSS hex string : " + HexUtil.byteArrayToHexString(signBytes));
    }

    @Test
    public void verifyWithPSSTest() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException,
            NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
        PublicKey publicKey = rsaCipher.getPublicKeyFromPemFormatFile(rootPath + "rsa_public_key_2048.pem");
        byte[] signBytes = HexUtil.hexStringToByteArray("071A671E00EED75D4C5A0A86C66626A5D8633B44A35160C24CE027F91EF7C215742E525B81022E0D6F293EB137871677926079AB7B90F3429C873ECA86803B8CE33772053EA9042C14D0EE3EE562542F836DCD6DC061F57D667DEAA758267F9E660895EE67934A00365D734E3127330B4F0F1B49693836996BF6310F75F29AE115FBC3366B2BF449EFD31589078067A2FD6A8E6E624D2D9D6BE182435634D67B69D160104DB505817D76114E1CED554A52E805A24B631FD73E9B52DA054E6A95537511D60455CF84FF2B1B477FDB97C926B57B01DA193AE706434D4DD34E3C43F64F9D351F17612443B840063FF304D6145DD78F279CB22E6A5D7AE0564B396B");
        assertTrue(rsaCipher.verifyWithPSS(publicKey, plainText.getBytes(StandardCharsets.UTF_8), signBytes, 20));
    }
}
