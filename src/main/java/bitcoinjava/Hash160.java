package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

public class Hash160 {
    public static byte[] hash(byte[] key) {
        MessageDigest ripemd = null;
        try {
            ripemd = MessageDigest.getInstance("RIPEMD160");
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchElementException("Algorithm RIPEMD160 not found. You may need to add BouncyCastleProvider as a security provider in your project.");
        }
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchElementException("Algorithm SHA-256 not found. You may need to add BouncyCastleProvider as a security provider in your project.");
        }
        return ripemd.digest(sha256.digest(key));
    }

    public static String hashToHex(byte[] key) {
        return Hex.toHexString(hash(key));
    }

}
