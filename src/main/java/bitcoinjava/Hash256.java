package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash256 {
    public static byte[] hash(byte[] key) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(sha256.digest(key));
    }

    public static String hashToHex(String key) throws NoSuchAlgorithmException {
        return Hex.toHexString(hash(Hex.decodeStrict(key)));
    }
}
