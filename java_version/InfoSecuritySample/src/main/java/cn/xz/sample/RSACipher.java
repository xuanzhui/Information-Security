package cn.xz.sample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Created by xuanzhui on 2017/3/24.
 * Every implementation of the Java platform is required to support the following standard asymmetric Cipher transformations with the keysizes in parentheses:
 * RSA/ECB/PKCS1Padding (1024, 2048)
 * RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
 * RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
 *
 * Every implementation of the Java platform is required to support the following standard Signature algorithms:
 * SHA1withDSA
 * SHA1withRSA
 * SHA256withRSA
 *
 * by default PKCS1v15 padding strategy is used
 * we will BouncyCastleProvider for SHA256WithRSA/PSS Signature which is supposed to be a better algorithm
 *
 * for p12 and jks file use below command to check the key info, i.e. alias name
 * keytool -list -keystore keyFile.p12 -storepass password -storetype PKCS12
 * keytool -list -keystore my_keystore.jks -storepass password
 */
public class RSACipher {
    static {
        // 1 is most preferred, followed by 2, and so on
        // in most cases vm will iterate all the available providers by the preference order until one is capable to deal with the required algorithm
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    // would work in most cases
    // http://stackoverflow.com/questions/24756420/how-to-get-the-rsa-public-key-from-private-key-object-in-java
    public PublicKey getPublicKeyFromPrivate(PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec priv = kf.getKeySpec(privateKey, RSAPrivateKeySpec.class);

        // here we use the publicExponent default value 65537
        // http://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));

        return kf.generatePublic(keySpec);
    }

    //===================== der format key file related operation =====================//
    public PublicKey getPublicKeyFromDerFormatFile(String derPath) throws CertificateException,
            IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path fileLocation = Paths.get(derPath);
        byte[] data = Files.readAllBytes(fileLocation);
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(data);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubX509);
    }

    // for standard jdk release, only PKCS#8 format is supported,
    // if BouncyCastleProvider is added, SSLeay[or to say traditional PKCS#1] format is also supported
    public PrivateKey getPrivateKeyFromDerFormatFile(String derPath) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        Path fileLocation = Paths.get(derPath);
        byte[] data = Files.readAllBytes(fileLocation);
        PKCS8EncodedKeySpec priX509 = new PKCS8EncodedKeySpec(data);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(priX509);
    }

    //===================== pem format key file related operation =====================//
    // pem file should start with -----BEGIN and last line should start with -----END
    public PublicKey getPublicKeyFromPemFormatFile(String pemPath) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(pemPath))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;

            while ((line = bufferedReader.readLine()) != null) {
                if (!line.startsWith("--")) {
                    stringBuilder.append(line);
                }
            }

            X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(
                    Base64.getDecoder().decode(stringBuilder.toString()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(pubX509);
        }
    }

    // for standard jdk release, only PKCS#8 format is supported,
    // if BouncyCastleProvider is added, SSLeay[or to say traditional PKCS#1] format is also supported
    public PrivateKey getPrivateKeyFromPemFormatFile(String pemPath) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(pemPath))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;

            while ((line = bufferedReader.readLine()) != null) {
                if (!line.startsWith("--")) {
                    stringBuilder.append(line);
                }
            }

            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(stringBuilder.toString()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(priPKCS8);
        }
    }

    //===================== certificate file related operation =====================//
    // get public key from certificate，both der and pem formats are supported
    public PublicKey getPublicKeyFromCertFile(String certPath) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(certPath);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        return cer.getPublicKey();
    }

    public void printCertificateInfoFromCertFile(String certPath) throws CertificateException, IOException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");

        X509Certificate cer = null;
        try (FileInputStream is = new FileInputStream(certPath)) {
            cer = (X509Certificate) fact.generateCertificate(is);
        }

        if (cer != null) {
            printCertificateInfo(cer);
        }
    }

    //===================== P12 file related operation =====================//
    // if only one key is stored, aliasName can be optional
    public PrivateKey getPrivateKeyFromP12(String p12Path, String password, String aliasName) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] nPassword = password.toCharArray();

        try (FileInputStream fis = new FileInputStream(p12Path)) {
            ks.load(fis, nPassword);
        }

        String keyAlias = null;
        if (aliasName == null) {
            Enumeration<?> enum1 = ks.aliases();
            if (enum1.hasMoreElements()) {
                keyAlias = (String) enum1.nextElement();
            }
        } else {
            keyAlias = aliasName;
        }

        return  (PrivateKey) ks.getKey(keyAlias, nPassword);
    }

    public PublicKey getPublicKeyFromP12(String p12Path, String password, String aliasName) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] nPassword = password.toCharArray();

        try (FileInputStream fis = new FileInputStream(p12Path)) {
            ks.load(fis, nPassword);
        }

        String keyAlias = null;
        if (aliasName == null) {
            Enumeration<?> enum1 = ks.aliases();
            if (enum1.hasMoreElements()) {
                keyAlias = (String) enum1.nextElement();
            }
        } else {
            keyAlias = aliasName;
        }

        X509Certificate cer = (X509Certificate) ks.getCertificate(keyAlias);
        return cer.getPublicKey();
    }

    public void printCertificateInfoFromP12(String p12Path, String password) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] nPassword = password.toCharArray();

        try (FileInputStream fis = new FileInputStream(p12Path)) {
            ks.load(fis, nPassword);
        }

        Enumeration<?> enum1 = ks.aliases();
        String keyAlias;
        while (enum1.hasMoreElements()) {
            keyAlias = (String) enum1.nextElement();
            X509Certificate cer = (X509Certificate) ks.getCertificate(keyAlias);
            printCertificateInfo(cer);
        }
    }

    //===================== JKS file related operation =====================//
    // jks has its own password which can be used to retrieve all the public info, like certificates,
    // but if it also contains private key entry, the entry should have its own password which can be different
    // from jks password, just be careful that not all jks files contain private key entry that null could return
    public PrivateKey getPrivateKeyFromJKS(String jksPath, String jksPassword, String keyAlias, String keyPassword)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance("JKS");

        try (FileInputStream fis = new FileInputStream(jksPath)) {
            keystore.load(fis, jksPassword.toCharArray());
        }

        if (keyAlias == null) {
            Enumeration<?> enum1 = keystore.aliases();
            if (enum1.hasMoreElements()) {
                keyAlias = (String) enum1.nextElement();
            }
        }

        // if the key password is not correct, there would be UnrecoverableKeyException: Cannot recover key
        return (PrivateKey) keystore.getKey(keyAlias, keyPassword.toCharArray());
    }

    public PublicKey getPublicKeyFromJKS(String jksPath, String jksPassword, String keyAlias) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance("JKS");

        try (FileInputStream fis = new FileInputStream(jksPath)) {
            keystore.load(fis, jksPassword.toCharArray());
        }

        if (keyAlias == null) {
            Enumeration<?> enum1 = keystore.aliases();
            if (enum1.hasMoreElements()) {
                keyAlias = (String) enum1.nextElement();
            }
        }

        X509Certificate cer = (X509Certificate) keystore.getCertificate(keyAlias);
        return cer.getPublicKey();
    }

    public void printCertificateInfoFromJKS(String jksPath, String password) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("JKS");
        char[] nPassword = password.toCharArray();

        try (FileInputStream fis = new FileInputStream(jksPath)) {
            ks.load(fis, nPassword);
        }

        Enumeration<?> enum1 = ks.aliases();
        String keyAlias;
        while (enum1.hasMoreElements()) {
            keyAlias = (String) enum1.nextElement();
            X509Certificate cer = (X509Certificate) ks.getCertificate(keyAlias);
            printCertificateInfo(cer);
        }
    }

    // http://stackoverflow.com/questions/16970302/reading-pkcs12-certificate-information
    public void printCertificateInfo(X509Certificate certificate) {
        Principal subject = certificate.getSubjectDN();
        String subjectArray[] = subject.toString().split(",");
        for (String s : subjectArray) {
            // just to show how to get the key and value, split is not really needed for print
            String[] str = s.trim().split("=");
            String key = str[0];
            String value = str[1];
            System.out.println(key + " - " + value);
        }
    }

    //===================== encryption and decryption =====================//
    // explicitly define all the params just to avoid misunderstanding
    // i.e. for RSA/ECB/OAEPWithSHA-256AndMGF1Padding, jdk standard release use SHA-1 as MGF1 hash algorithm
    // while BouncyCastleProvider use SHA-256 instead
    // http://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding

    // as padding would change the cipher result will also change for the same plain text
    public byte[] encryptWithOAEP(PublicKey publicKey, byte[] plainBytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        return oaepFromInit.doFinal(plainBytes);
    }

    public byte[] decryptWithOAEP(PrivateKey privateKey, byte[] encryptedBytes) throws BadPaddingException,
            IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        return oaepFromInit.doFinal(encryptedBytes);
    }

    //===================== signature and verification =====================//

    // as padding would change the cipher result will also change for the same plain text
    public byte[] signWithPSS(PrivateKey privateKey, byte[] plainBytes, int saltLen)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("SHA256WithRSA/PSS", "BC"); //second param "BC" is not really required
        MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec, saltLen, 1);
        signature.setParameter(pssParameterSpec);
        signature.initSign(privateKey);
        signature.update(plainBytes);
        return signature.sign();
    }

    public boolean verifyWithPSS(PublicKey publicKey, byte[] plainBytes, byte[] signBytes,
                                 int saltLen) throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("SHA256WithRSA/PSS", "BC");
        MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec, saltLen, 1);
        signature.setParameter(pssParameterSpec);
        signature.initVerify(publicKey);
        signature.update(plainBytes);
        return signature.verify(signBytes);
    }
}
