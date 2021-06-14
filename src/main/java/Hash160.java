import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash160 {
    public static byte[] hash(byte[] key) throws NoSuchAlgorithmException {
        MessageDigest ripemd = MessageDigest.getInstance("RIPEMD160");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return ripemd.digest(sha256.digest(key));
    }

    public static String hashToHex(byte[] key) throws NoSuchAlgorithmException {
        return Hex.toHexString(hash(key));
    }
}
