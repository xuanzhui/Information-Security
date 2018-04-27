package cn.xz.sample;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by xuanzhui on 2017/2/27.
 * Key derivation function: pbkdf2, bcrypt, scrypt
 * normally used to strengthen the password but slow and input length should be limited
 */
public class KDFAlgorithm {
    // http://crypto.stackexchange.com/questions/12963/password-hashing-in-etc-shadow
    // OrpheanBeholderScryDoubt
    private static final int bcryptIV[] = {
            0x4f727068, 0x65616e42, 0x65686f6c,
            0x64657253, 0x63727944, 0x6f756274
    };

    // has to use BouncyCastle
    public byte[] pbkdf2MD5(String password, byte[] salt, int iterations, int keyLen) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        // change digest for other hash algorithm
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new MD5Digest());
        gen.init(password.getBytes(), salt, iterations);
        return ((KeyParameter) gen.generateDerivedParameters(keyLen)).getKey();
    }

    // keyLen is in bit, normally set key length as hash output length
    public byte[] pbkdf2SHA1(String password, byte[] salt, int iterations, int keyLen) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLen);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }

    public byte[] pbkdf2SHA256(String password, byte[] salt, int iterations, int keyLen) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLen);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    // BCrypt cost must be from 4..31
    // http://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
    // org.bouncycastle.crypto.generators.BCrypt.generate 效果和jbcrypt.crypt_raw一致
    public byte[] bcryptRaw(String password, byte[] salt, int cost) {
        BCrypt bCrypt = new org.mindrot.jbcrypt.BCrypt();
        return bCrypt.crypt_raw(password.getBytes(), salt, cost, bcryptIV);
    }

    // bcrypt cost of 6 means 64 rounds (2**6 = 64)
    public String bcryptFreeBSDSchema(String password, int cost) {
        return BCrypt.hashpw(password, BCrypt.gensalt(cost));
    }

    public boolean bcryptFreeBSDSchemaVerify(String rawPassword, String bcryptPassword) {
        return BCrypt.checkpw(rawPassword, bcryptPassword);
    }

    // with help of org.bouncycastle.crypto.generators.SCrypt
    public byte[] scrypt(String password, byte[] salt, int N, int r, int p, int dkLen) {
        return SCrypt.generate(password.getBytes(), salt, N, r, p, dkLen);
    }
}
